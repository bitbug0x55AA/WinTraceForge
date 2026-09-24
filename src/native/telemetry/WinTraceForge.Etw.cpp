// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <vector>
#include <string>
#include <new>
#include <limits>
#include <climits>
#include <algorithm>

namespace
{
    constexpr ULONG MaxProviders = 16;

    struct CaptureStatus
    {
        ULONG ProviderCount;
        ULONG EnableStatuses[MaxProviders];
        ULONG EventsLost;
        ULONG LogBuffersLost;
        ULONG RealTimeBuffersLost;
        ULONG BuffersWritten;
    };

    bool ValidProviders(const GUID* providers, ULONG count)
    {
        if (!providers || count == 0 || count > MaxProviders) { return false; }
        const GUID empty = {};
        for (ULONG i = 0; i < count; i++)
        {
            if (IsEqualGUID(providers[i], empty)) { return false; }
            for (ULONG j = 0; j < i; j++)
            {
                if (IsEqualGUID(providers[i], providers[j])) { return false; }
            }
        }
        return true;
    }

    struct DecodeStatus
    {
        ULONG SelectedEvents;
        ULONG PartialEvents;
        ULONG DecodeFailures;
        ULONG LimitReached;
        ULONG CallbackFailures;
    };

    struct Capture
    {
        TRACEHANDLE Handle = 0;
        bool Active = false;
        std::wstring Name;
        std::vector<BYTE> Properties;
        CaptureStatus Status = {};

        EVENT_TRACE_PROPERTIES* Data()
        {
            return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(Properties.data());
        }

        ULONG Stop()
        {
            if (!Active) { return ERROR_SUCCESS; }
            ULONG result = ControlTraceW(Handle, Name.c_str(), Data(), EVENT_TRACE_CONTROL_STOP);
            if (result == ERROR_SUCCESS)
            {
                Status.EventsLost = Data()->EventsLost;
                Status.LogBuffersLost = Data()->LogBuffersLost;
                Status.RealTimeBuffersLost = Data()->RealTimeBuffersLost;
                Status.BuffersWritten = Data()->BuffersWritten;
                Active = false;
            }
            else if (result == ERROR_WMI_INSTANCE_NOT_FOUND)
            {
                Active = false;
            }
            return result;
        }
    };

    ULONG StartCapture(Capture& capture, const wchar_t* name, const wchar_t* file, ULONG extraMode = 0)
    {
        capture.Name = name;
        const size_t nameBytes = (wcslen(name) + 1) * sizeof(wchar_t);
        const size_t fileBytes = (wcslen(file) + 1) * sizeof(wchar_t);
        const size_t total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes + fileBytes;
        if (total > ULONG_MAX) { return ERROR_INVALID_PARAMETER; }
        capture.Properties.resize(total, 0);
        auto properties = capture.Data();
        properties->Wnode.BufferSize = static_cast<ULONG>(total);
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.ClientContext = 1;
        HRESULT guidResult = CoCreateGuid(&properties->Wnode.Guid);
        if (FAILED(guidResult)) { return ERROR_GEN_FAILURE; }
        properties->BufferSize = 64;
        properties->MinimumBuffers = 4;
        properties->MaximumBuffers = 16;
        properties->MaximumFileSize = 32;
        properties->FlushTimer = 1;
        properties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL |
            EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING | extraMode;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->LogFileNameOffset = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + nameBytes);
        memcpy(capture.Properties.data() + properties->LoggerNameOffset, name, nameBytes);
        memcpy(capture.Properties.data() + properties->LogFileNameOffset, file, fileBytes);
        ULONG result = StartTraceW(&capture.Handle, name, properties);
        capture.Active = result == ERROR_SUCCESS;
        return result;
    }

    ULONG Enable(Capture& capture, const GUID& provider)
    {
        ENABLE_TRACE_PARAMETERS parameters = {};
        parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        return EnableTraceEx2(capture.Handle, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, MAXULONGLONG, 0, 5000, &parameters);
    }

    std::wstring Escape(const std::wstring& value)
    {
        std::wstring result;
        for (wchar_t character : value)
        {
            switch (character)
            {
            case L'&': result += L"&amp;"; break;
            case L'<': result += L"&lt;"; break;
            case L'>': result += L"&gt;"; break;
            case L'\"': result += L"&quot;"; break;
            case L'\'': result += L"&apos;"; break;
            default:
                result += character >= 0x20 || character == L'\t' || character == L'\n' || character == L'\r' ?
                    character : L'\ufffd';
                break;
            }
        }
        return result;
    }

    std::wstring GuidText(const GUID& guid)
    {
        wchar_t text[40] = {};
        StringFromGUID2(guid, text, ARRAYSIZE(text));
        return text;
    }

    std::wstring TimeText(LARGE_INTEGER value)
    {
        FILETIME time = { value.LowPart, static_cast<DWORD>(value.HighPart) };
        SYSTEMTIME system = {};
        if (!FileTimeToSystemTime(&time, &system)) { return L"invalid"; }
        wchar_t text[40] = {};
        StringCchPrintfW(text, ARRAYSIZE(text), L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
            system.wYear, system.wMonth, system.wDay, system.wHour, system.wMinute, system.wSecond, system.wMilliseconds);
        return text;
    }

    std::wstring InfoString(const std::vector<BYTE>& metadata, ULONG offset)
    {
        if (offset == 0 || offset >= metadata.size() || offset % sizeof(wchar_t) != 0) { return L""; }
        const auto value = reinterpret_cast<const wchar_t*>(metadata.data() + offset);
        size_t available = (metadata.size() - offset) / sizeof(wchar_t);
        size_t length = wcsnlen_s(value, available);
        return length < available ? std::wstring(value, length) : L"";
    }

    ULONG GetRaw(PEVENT_RECORD record, const wchar_t* name, std::vector<BYTE>& raw)
    {
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        ULONG result = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size);
        if (result != ERROR_SUCCESS) { return result; }
        if (size > USHRT_MAX) { return ERROR_BUFFER_OVERFLOW; }
        raw.resize(size == 0 ? 1 : size);
        result = TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, raw.data());
        if (result == ERROR_SUCCESS) { raw.resize(size); }
        return result;
    }

    ULONG FormatField(PEVENT_RECORD record, TRACE_EVENT_INFO* info,
        const std::vector<BYTE>& metadata, ULONG index, std::wstring& name, std::wstring& value)
    {
        const auto& property = info->EventPropertyInfoArray[index];
        name = InfoString(metadata, property.NameOffset);
        if (name.empty()) { return ERROR_INVALID_DATA; }
        if ((property.Flags & PropertyStruct) || (property.Flags & PropertyParamCount) || property.count != 1)
        {
            return ERROR_NOT_SUPPORTED;
        }
        std::vector<BYTE> raw;
        ULONG result = GetRaw(record, name.c_str(), raw);
        if (result != ERROR_SUCCESS) { return result; }
        USHORT length = property.length;
        if (property.Flags & PropertyParamLength)
        {
            if (property.lengthPropertyIndex >= info->PropertyCount) { return ERROR_INVALID_DATA; }
            std::wstring lengthName = InfoString(metadata, info->EventPropertyInfoArray[property.lengthPropertyIndex].NameOffset);
            std::vector<BYTE> lengthData;
            result = GetRaw(record, lengthName.c_str(), lengthData);
            if (result != ERROR_SUCCESS) { return result; }
            ULONG count = 0;
            if (lengthData.empty() || lengthData.size() > sizeof(count)) { return ERROR_NOT_SUPPORTED; }
            memcpy(&count, lengthData.data(), lengthData.size());
            if (count > USHRT_MAX) { return ERROR_BUFFER_OVERFLOW; }
            length = static_cast<USHORT>(count);
        }
        if (property.nonStructType.InType == TDH_INTYPE_BINARY) { length = static_cast<USHORT>(raw.size()); }
        ULONG pointerSize = record->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
        ULONG formattedSize = 0;
        USHORT consumed = 0;
        result = TdhFormatProperty(info, nullptr, pointerSize,
            property.nonStructType.InType, property.nonStructType.OutType, length,
            static_cast<USHORT>(raw.size()), raw.data(), &formattedSize, nullptr, &consumed);
        if (result != ERROR_INSUFFICIENT_BUFFER) { return result == ERROR_SUCCESS ? ERROR_INVALID_DATA : result; }
        if (formattedSize > 131072) { return ERROR_BUFFER_OVERFLOW; }
        std::vector<wchar_t> formatted(formattedSize / sizeof(wchar_t) + 1, 0);
        result = TdhFormatProperty(info, nullptr, pointerSize,
            property.nonStructType.InType, property.nonStructType.OutType, length,
            static_cast<USHORT>(raw.size()), raw.data(), &formattedSize, formatted.data(), &consumed);
        if (result == ERROR_SUCCESS) { value = formatted.data(); }
        return result;
    }

    using DecodedCallback = int(__cdecl*)(ULONG sequence, const wchar_t* xml, void* context);

    struct Reader
    {
        DecodedCallback Callback;
        void* Context;
        DecodeStatus Status = {};
        std::vector<GUID> Providers;
        bool Cancel = false;
    };

    void WINAPI OnEvent(PEVENT_RECORD record)
    {
        auto& reader = *static_cast<Reader*>(record->UserContext);
        if (reader.Cancel || std::none_of(reader.Providers.begin(), reader.Providers.end(),
            [record](const GUID& provider) { return IsEqualGUID(record->EventHeader.ProviderId, provider); })) { return; }
        if (reader.Status.SelectedEvents >= 10000)
        {
            reader.Status.LimitReached = 1;
            reader.Cancel = true;
            return;
        }
        reader.Status.SelectedEvents++;
        try
        {
            ULONG size = 0;
            ULONG decode = TdhGetEventInformation(record, 0, nullptr, nullptr, &size);
            std::vector<BYTE> metadata;
            TRACE_EVENT_INFO* info = nullptr;
            if (decode == ERROR_INSUFFICIENT_BUFFER && size <= 1048576)
            {
                metadata.resize(size);
                info = reinterpret_cast<TRACE_EVENT_INFO*>(metadata.data());
                decode = TdhGetEventInformation(record, 0, nullptr, info, &size);
            }
            std::wstring provider;
            if (decode == ERROR_SUCCESS && info && info->ProviderNameOffset)
            {
                provider = InfoString(metadata, info->ProviderNameOffset);
            }
            std::wstring related;
            for (USHORT i = 0; i < record->ExtendedDataCount; i++)
            {
                const auto& data = record->ExtendedData[i];
                if (data.ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID && data.DataSize == sizeof(GUID))
                {
                    related = GuidText(*reinterpret_cast<const GUID*>(data.DataPtr));
                }
            }
            std::wstring xml = L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='" +
                Escape(provider) + L"' Guid='" + GuidText(record->EventHeader.ProviderId) +
                L"'/><EventID>" + std::to_wstring(record->EventHeader.EventDescriptor.Id) +
                L"</EventID><Version>" + std::to_wstring(record->EventHeader.EventDescriptor.Version) +
                L"</Version><TimeCreated SystemTime='" + TimeText(record->EventHeader.TimeStamp) +
                L"'/><Execution ProcessID='" + std::to_wstring(record->EventHeader.ProcessId) +
                L"' ThreadID='" + std::to_wstring(record->EventHeader.ThreadId) +
                L"'/><Correlation ActivityID='" + GuidText(record->EventHeader.ActivityId) +
                L"' RelatedActivityID='" + related + L"'/></System><EventData>";
            ULONG fieldErrors = 0;
            if (decode == ERROR_SUCCESS && info)
            {
                ULONG count = info->TopLevelPropertyCount;
                if (count > 64) { fieldErrors++; count = 64; }
                for (ULONG i = 0; i < count; i++)
                {
                    std::wstring name;
                    std::wstring value;
                    ULONG result = FormatField(record, info, metadata, i, name, value);
                    if (result != ERROR_SUCCESS)
                    {
                        fieldErrors++;
                        value = L"[TDH field not decoded; Win32=" + std::to_wstring(result) + L"]";
                    }
                    xml += L"<Data Name='" + Escape(name) + L"'>" + Escape(value) + L"</Data>";
                }
                if (fieldErrors) { reader.Status.PartialEvents++; }
            }
            else
            {
                reader.Status.DecodeFailures++;
            }
            xml += L"</EventData><Decoding Win32Status='" + std::to_wstring(decode) +
                L"' FieldErrors='" + std::to_wstring(fieldErrors) + L"'/></Event>";
            if (reader.Callback(reader.Status.SelectedEvents, xml.c_str(), reader.Context) != 0)
            {
                reader.Status.CallbackFailures++;
                reader.Cancel = true;
            }
        }
        catch (const std::bad_alloc&)
        {
            reader.Status.DecodeFailures++;
            reader.Cancel = true;
        }
    }

    ULONG WINAPI OnBuffer(PEVENT_TRACE_LOGFILEW logfile)
    {
        return !static_cast<Reader*>(logfile->Context)->Cancel;
    }

    ULONG ReadTrace(const wchar_t* path, Reader& reader)
    {
        EVENT_TRACE_LOGFILEW logfile = {};
        logfile.LogFileName = const_cast<wchar_t*>(path);
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = OnEvent;
        logfile.BufferCallback = OnBuffer;
        logfile.Context = &reader;
        TRACEHANDLE handle = OpenTraceW(&logfile);
        if (handle == INVALID_PROCESSTRACE_HANDLE) { return GetLastError(); }
        ULONG result = ProcessTrace(&handle, 1, nullptr, nullptr);
        ULONG close = CloseTrace(handle);
        return result == ERROR_SUCCESS ? close : result;
    }
}

extern "C" __declspec(dllexport) ULONG __cdecl NativeEtwStartV2(
    const GUID* providers, ULONG count, const wchar_t* name, const wchar_t* file, void** handle, CaptureStatus* status) noexcept
{
    if (!handle || !status) { return ERROR_INVALID_PARAMETER; }
    *handle = nullptr;
    *status = {};
    if (!ValidProviders(providers, count) || !name || !*name || !file || !*file) { return ERROR_INVALID_PARAMETER; }
    Capture* capture = new (std::nothrow) Capture;
    if (!capture) { return ERROR_OUTOFMEMORY; }
    try
    {
        ULONG result = StartCapture(*capture, name, file);
        if (result != ERROR_SUCCESS) { delete capture; return result; }
        *handle = capture;
        capture->Status.ProviderCount = count;
        for (ULONG i = 0; i < count; i++) { capture->Status.EnableStatuses[i] = Enable(*capture, providers[i]); }
        *status = capture->Status;
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        capture->Stop();
        delete capture;
        *handle = nullptr;
        return ERROR_OUTOFMEMORY;
    }
}

extern "C" __declspec(dllexport) ULONG __cdecl NativeEtwStopV2(void* handle, CaptureStatus* status) noexcept
{
    if (!handle || !status) { return ERROR_INVALID_PARAMETER; }
    auto capture = static_cast<Capture*>(handle);
    ULONG result = capture->Stop();
    *status = capture->Status;
    return result;
}

extern "C" __declspec(dllexport) ULONG __cdecl NativeEtwClose(void* handle) noexcept
{
    if (!handle) { return ERROR_SUCCESS; }
    auto capture = static_cast<Capture*>(handle);
    ULONG result = capture->Stop();
    delete capture;
    return result;
}

extern "C" __declspec(dllexport) ULONG __cdecl NativeEtwReadV2(
    const GUID* providers, ULONG count, const wchar_t* file, DecodedCallback callback, void* context, DecodeStatus* status) noexcept
{
    if (!status) { return ERROR_INVALID_PARAMETER; }
    *status = {};
    if (!ValidProviders(providers, count) || !file || !*file || !callback) { return ERROR_INVALID_PARAMETER; }
    try
    {
        Reader reader = { callback, context, {}, std::vector<GUID>(providers, providers + count), false };
        ULONG result = ReadTrace(file, reader);
        *status = reader.Status;
        return result;
    }
    catch (const std::bad_alloc&) { return ERROR_OUTOFMEMORY; }
}
