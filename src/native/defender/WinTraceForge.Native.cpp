// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wbemidl.h>
#include <wrl/client.h>
#include <new>
#include <string>

using Microsoft::WRL::ComPtr;

namespace
{
    struct BStr
    {
        BSTR value;
        explicit BStr(const wchar_t* text) : value(SysAllocString(text)) {}
        ~BStr() { SysFreeString(value); }
        BStr(const BStr&) = delete;
        BStr& operator=(const BStr&) = delete;
    };

    struct Variant
    {
        VARIANT value;
        Variant() { VariantInit(&value); }
        ~Variant() { VariantClear(&value); }
        Variant(const Variant&) = delete;
        Variant& operator=(const Variant&) = delete;
    };

    struct Session
    {
        bool uninitialize = false;
        ComPtr<IWbemServices> services;
        ComPtr<IWbemClassObject> definition;
        ComPtr<IWbemClassObject> input;

        ~Session()
        {
            input.Reset();
            definition.Reset();
            services.Reset();
            if (uninitialize) { CoUninitialize(); }
        }
    };

    bool Allowed(const wchar_t* name)
    {
        return name && (wcscmp(name, L"ExclusionPath") == 0 ||
            wcscmp(name, L"ExclusionExtension") == 0 ||
            wcscmp(name, L"ExclusionProcess") == 0 ||
            wcscmp(name, L"ExclusionIpAddress") == 0);
    }

    HRESULT SetSecurity(IUnknown* proxy)
    {
        return CoSetProxyBlanket(proxy, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    }
}

extern "C" __declspec(dllexport) HRESULT __cdecl NativeOpen(void** handle) noexcept
{
    if (!handle) { return E_POINTER; }
    *handle = nullptr;
    Session* session = new (std::nothrow) Session;
    if (!session) { return E_OUTOFMEMORY; }
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    session->uninitialize = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    {
        delete session;
        return hr;
    }

    // Preserve existing process-wide COM security if the CLR initialized it first.
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
    {
        delete session;
        return hr;
    }
    {
        ComPtr<IWbemLocator> locator;
        hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(locator.GetAddressOf()));
        if (SUCCEEDED(hr))
        {
            BStr path(L"ROOT\\Microsoft\\Windows\\Defender");
            hr = path.value ? locator->ConnectServer(path.value, nullptr, nullptr, nullptr,
                WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, session->services.GetAddressOf()) :
                E_OUTOFMEMORY;
        }
    }
    if (SUCCEEDED(hr)) { hr = SetSecurity(session->services.Get()); }
    if (FAILED(hr))
    {
        delete session;
        return hr;
    }
    *handle = session;
    return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __cdecl NativePrepare(void* handle) noexcept
{
    Session* session = static_cast<Session*>(handle);
    if (!session || !session->services) { return E_INVALIDARG; }
    BStr className(L"MSFT_MpPreference");
    if (!className.value) { return E_OUTOFMEMORY; }
    HRESULT hr = session->services->GetObject(className.value, 0, nullptr,
        session->definition.ReleaseAndGetAddressOf(), nullptr);
    if (FAILED(hr)) { return hr; }
    ComPtr<IWbemClassObject> parameters;
    hr = session->definition->GetMethod(L"Add", 0, parameters.GetAddressOf(), nullptr);
    if (FAILED(hr)) { return hr; }
    if (!parameters) { return WBEM_E_INVALID_METHOD_PARAMETERS; }
    return parameters->SpawnInstance(0, session->input.ReleaseAndGetAddressOf());
}

extern "C" __declspec(dllexport) HRESULT __cdecl NativeSupports(
    void* handle, const wchar_t* name, BOOL* supported) noexcept
{
    Session* session = static_cast<Session*>(handle);
    if (!supported) { return E_POINTER; }
    *supported = FALSE;
    if (!session || !session->input || !session->definition || !Allowed(name)) { return E_INVALIDARG; }
    CIMTYPE inputType = 0;
    CIMTYPE outputType = 0;
    HRESULT hr = session->input->Get(name, 0, nullptr, &inputType, nullptr);
    if (hr == WBEM_E_NOT_FOUND) { return S_OK; }
    if (FAILED(hr)) { return hr; }
    hr = session->definition->Get(name, 0, nullptr, &outputType, nullptr);
    if (hr == WBEM_E_NOT_FOUND) { return S_OK; }
    if (FAILED(hr)) { return hr; }
    *supported = inputType == (CIM_STRING | CIM_FLAG_ARRAY) &&
        outputType == (CIM_STRING | CIM_FLAG_ARRAY);
    return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __cdecl NativeSetValues(
    void* handle, const wchar_t* name, const wchar_t* const* values, int count) noexcept
{
    Session* session = static_cast<Session*>(handle);
    if (!session || !session->input || !Allowed(name) || !values || count <= 0) { return E_INVALIDARG; }
    Variant input;
    input.value.vt = VT_ARRAY | VT_BSTR;
    input.value.parray = SafeArrayCreateVector(VT_BSTR, 0, static_cast<ULONG>(count));
    if (!input.value.parray) { return E_OUTOFMEMORY; }
    for (LONG i = 0; i < count; i++)
    {
        if (!values[i]) { return E_INVALIDARG; }
        BStr value(values[i]);
        if (!value.value) { return E_OUTOFMEMORY; }
        HRESULT hr = SafeArrayPutElement(input.value.parray, &i, value.value);
        if (FAILED(hr)) { return hr; }
    }
    return session->input->Put(name, 0, &input.value, 0);
}

extern "C" __declspec(dllexport) HRESULT __cdecl NativeAdd(
    void* handle, VARIANT* returnValue) noexcept
{
    if (!returnValue) { return E_POINTER; }
    VariantInit(returnValue);
    Session* session = static_cast<Session*>(handle);
    if (!session || !session->services || !session->input) { return E_INVALIDARG; }
    BStr className(L"MSFT_MpPreference");
    BStr method(L"Add");
    if (!className.value || !method.value) { return E_OUTOFMEMORY; }
    ComPtr<IWbemClassObject> result;
    HRESULT hr = session->services->ExecMethod(className.value, method.value, 0, nullptr,
        session->input.Get(), result.GetAddressOf(), nullptr);
    if (FAILED(hr)) { return hr; }
    if (!result) { return S_OK; }
    hr = result->Get(L"ReturnValue", 0, returnValue, nullptr, nullptr);
    return hr == WBEM_E_NOT_FOUND ? S_OK : hr;
}

extern "C" __declspec(dllexport) HRESULT __cdecl NativeRead(
    void* handle, const wchar_t* name, VARIANT* values) noexcept
{
    if (!values) { return E_POINTER; }
    VariantInit(values);
    Session* session = static_cast<Session*>(handle);
    if (!session || !session->services || !Allowed(name)) { return E_INVALIDARG; }
    try
    {
        std::wstring query = L"SELECT ";
        query += name;
        query += L" FROM MSFT_MpPreference";
        BStr wql(L"WQL");
        BStr text(query.c_str());
        if (!wql.value || !text.value) { return E_OUTOFMEMORY; }
        ComPtr<IEnumWbemClassObject> results;
        HRESULT hr = session->services->ExecQuery(wql.value, text.value,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, results.GetAddressOf());
        if (FAILED(hr)) { return hr; }
        hr = SetSecurity(results.Get());
        if (FAILED(hr)) { return hr; }
        ComPtr<IWbemClassObject> record;
        ULONG returned = 0;
        hr = results->Next(30000, 1, record.GetAddressOf(), &returned);
        if (hr == WBEM_S_TIMEDOUT) { return HRESULT_FROM_WIN32(ERROR_TIMEOUT); }
        if (FAILED(hr)) { return hr; }
        if (returned != 1 || !record) { return WBEM_E_NOT_FOUND; }
        hr = record->Get(name, 0, values, nullptr, nullptr);
        if (FAILED(hr)) { return hr; }
        // Drain the singleton query to avoid cancellation telemetry from an abandoned enumerator.
        record.Reset();
        returned = 0;
        hr = results->Next(30000, 1, record.GetAddressOf(), &returned);
        if (hr == WBEM_S_TIMEDOUT) { return HRESULT_FROM_WIN32(ERROR_TIMEOUT); }
        if (FAILED(hr)) { return hr; }
        return returned == 0 ? S_OK : WBEM_E_PROVIDER_FAILURE;
    }
    catch (const std::bad_alloc&)
    {
        return E_OUTOFMEMORY;
    }
}

extern "C" __declspec(dllexport) void __cdecl NativeClose(void* handle) noexcept
{
    delete static_cast<Session*>(handle);
}
