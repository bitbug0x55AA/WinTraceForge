// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "WinTraceForge.Etw.cpp"
#include <TraceLoggingProvider.h>
#include <stdio.h>

TRACELOGGING_DEFINE_PROVIDER(TestProvider, "WinTraceForge.SelfTest",
    (0x47fc7aa0, 0xa6c8, 0x490b, 0x99, 0xaa, 0x3d, 0xb8, 0x68, 0x16, 0x21, 0x55));

namespace
{
    const GUID TestGuid = { 0x47fc7aa0, 0xa6c8, 0x490b, { 0x99, 0xaa, 0x3d, 0xb8, 0x68, 0x16, 0x21, 0x55 } };
    struct Assertions
    {
        unsigned Received = 0;
        bool ScalarDecoded = false;
        bool PartialReported = false;
    };

    int __cdecl Receive(ULONG, const wchar_t* xml, void* context)
    {
        auto& assertions = *static_cast<Assertions*>(context);
        assertions.Received++;
        std::wstring text(xml);
        assertions.ScalarDecoded |= text.find(L"ETW selftest &amp; xml") != std::wstring::npos &&
            text.find(L"Name='ClientProcessId'") != std::wstring::npos &&
            text.find(L"FieldErrors='0'") != std::wstring::npos;
        assertions.PartialReported |= text.find(L"TDH field not decoded") != std::wstring::npos;
        wprintf(L"%ls\n", xml);
        return 0;
    }

    int __cdecl RejectCallback(ULONG, const wchar_t*, void*) { return 1; }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2 || GetFileAttributesW(argv[1]) != INVALID_FILE_ATTRIBUTES)
    {
        fwprintf(stderr, L"Supply one unused ETL output filename.\n");
        return 2;
    }
    Capture capture;
    GUID run;
    if (FAILED(CoCreateGuid(&run))) { return 1; }
    std::wstring name = L"WinTraceForge-SelfTest-" + GuidText(run);
    ULONG result = TraceLoggingRegister(TestProvider);
    if (result != ERROR_SUCCESS) { return 1; }
    result = StartCapture(capture, name.c_str(), argv[1],
        EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC);
    if (result != ERROR_SUCCESS)
    {
        fwprintf(stderr, L"Private ETW StartTrace failed: %lu\n", result);
        TraceLoggingUnregister(TestProvider);
        return 1;
    }
    result = Enable(capture, TestGuid);
    if (result == ERROR_SUCCESS)
    {
        TraceLoggingWrite(TestProvider, "ScalarEvidence",
            TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
            TraceLoggingUInt32(GetCurrentProcessId(), "ClientProcessId"),
            TraceLoggingWideString(L"ETW selftest & xml", "Operation"),
            TraceLoggingUInt32(0, "ResultCode"));
        const UINT32 values[] = { 1, 2, 3 };
        TraceLoggingWrite(TestProvider, "ArrayEvidence",
            TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
            TraceLoggingUInt32Array(values, ARRAYSIZE(values), "Values"));
    }
    ULONG stop = capture.Stop();
    TraceLoggingUnregister(TestProvider);
    if (result != ERROR_SUCCESS || stop != ERROR_SUCCESS)
    {
        fwprintf(stderr, L"Enable=%lu Stop=%lu\n", result, stop);
        return 1;
    }
    ULONG queryStopped = ControlTraceW(capture.Handle, name.c_str(), capture.Data(), EVENT_TRACE_CONTROL_QUERY);
    if (queryStopped != ERROR_WMI_INSTANCE_NOT_FOUND || capture.Stop() != ERROR_SUCCESS)
    {
        fwprintf(stderr, L"Session cleanup/idempotent-stop test failed: %lu\n", queryStopped);
        return 1;
    }
    Assertions assertions;
    Reader reader = { Receive, &assertions, {}, { TestGuid }, false };
    ULONG read = ReadTrace(argv[1], reader);
    wprintf(L"Read=%lu Selected=%lu Partial=%lu Failures=%lu Lost=%lu\n", read,
        reader.Status.SelectedEvents, reader.Status.PartialEvents, reader.Status.DecodeFailures, capture.Status.EventsLost);
    if (read != ERROR_SUCCESS || assertions.Received != 2 || !assertions.ScalarDecoded ||
        !assertions.PartialReported || reader.Status.PartialEvents != 1 || reader.Status.DecodeFailures != 0 ||
        capture.Status.EventsLost != 0)
    {
        fwprintf(stderr, L"ETW round-trip assertions failed.\n");
        return 1;
    }
    Reader rejected = { RejectCallback, nullptr, {}, { TestGuid }, false };
    ULONG cancelled = ReadTrace(argv[1], rejected);
    if (rejected.Status.CallbackFailures != 1 || (cancelled != ERROR_CANCELLED && cancelled != ERROR_SUCCESS))
    {
        fwprintf(stderr, L"Callback failure propagation test failed: %lu\n", cancelled);
        return 1;
    }
    Reader capped = { Receive, &assertions, {}, { TestGuid }, false };
    capped.Status.SelectedEvents = 10000;
    EVENT_RECORD record = {};
    record.EventHeader.ProviderId = TestGuid;
    record.UserContext = &capped;
    OnEvent(&record);
    if (!capped.Cancel || capped.Status.LimitReached != 1 || capped.Status.SelectedEvents != 10000)
    {
        fwprintf(stderr, L"Decode cap test failed.\n");
        return 1;
    }
    GUID other;
    if (FAILED(CoCreateGuid(&other))) { return 1; }
    GUID third;
    if (FAILED(CoCreateGuid(&third))) { return 1; }
    GUID providers[] = { other, third, TestGuid };
    DecodeStatus status = {};
    Assertions exported;
    if (NativeEtwReadV2(providers, 3, argv[1], Receive, &exported, &status) != ERROR_SUCCESS ||
        exported.Received != 2 || status.SelectedEvents != 2)
    { fwprintf(stderr, L"Generic provider-list export failed.\n"); return 1; }
    if (NativeEtwReadV2(&other, 1, argv[1], Receive, &exported, &status) != ERROR_SUCCESS ||
        status.SelectedEvents != 0)
    { fwprintf(stderr, L"Provider-list isolation failed.\n"); return 1; }
    GUID duplicate[] = { TestGuid, TestGuid };
    GUID empty = {};
    if (ValidProviders(nullptr, 1) || ValidProviders(&TestGuid, 0) ||
        ValidProviders(&TestGuid, 17) || ValidProviders(duplicate, 2) || ValidProviders(&empty, 1))
    { fwprintf(stderr, L"Invalid provider list accepted.\n"); return 1; }
    void* invalidHandle = nullptr;
    CaptureStatus invalidStatus = {};
    if (NativeEtwStartV2(duplicate, 2, L"invalid", argv[1], &invalidHandle, &invalidStatus) != ERROR_INVALID_PARAMETER ||
        invalidHandle != nullptr || NativeEtwReadV2(nullptr, 1, argv[1], Receive, nullptr, &status) != ERROR_INVALID_PARAMETER)
    { fwprintf(stderr, L"Invalid provider-list ABI request accepted.\n"); return 1; }
    wprintf(L"PASS: actual private ETW -> ETL -> ProcessTrace -> TDH round-trip and generic provider lists; no production provider enabled.\n");
    return 0;
}
