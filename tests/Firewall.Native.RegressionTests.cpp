// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Standalone white-box ABI/codec regression runner; no persistent COM writes.
#include "WinTraceForge.Firewall.Native.cpp"
#include <iostream>

namespace
{
    int assertions = 0;
    void Assert(bool condition, const char* message)
    {
        ++assertions;
        if (!condition) { throw std::runtime_error(message); }
    }
    template<typename F> void Invalid(F action, const char* message)
    {
        Assert(FirewallNative::Guard(action) == E_INVALIDARG, message);
    }
    HRESULT Invoke(void* session, uint32_t operation, const std::vector<unsigned char>& packet)
    {
        void* output = nullptr;
        uint32_t length = 0;
        const HRESULT status = FirewallNativeInvoke(session, operation, packet.data(),
            static_cast<uint32_t>(packet.size()), &output, &length);
        if (FAILED(status)) { Assert(output == nullptr && length == 0, "failure outputs initialized"); }
        else { Assert(output != nullptr && length >= 4, "success outputs initialized"); }
        FirewallNativeFree(output);
        return status;
    }

    // Intercept the exact Rules.Add boundary; never forward to the real policy collection.
    struct AddProbe : INetFwRules
    {
        ULONG references = 1;
        unsigned calls = 0;
        bool applicationNull = false, serviceNull = false;
        std::wstring localPorts, remotePorts, application, service;
        long protocol = 0;
        HRESULT result = E_ACCESSDENIED;
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** value) override
        {
            if (!value) { return E_POINTER; }
            *value = nullptr;
            if (id != __uuidof(IUnknown) && id != __uuidof(IDispatch) && id != __uuidof(INetFwRules)) { return E_NOINTERFACE; }
            *value = static_cast<INetFwRules*>(this); AddRef(); return S_OK;
        }
        ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG left = --references;
            if (!left) { delete this; }
            return left;
        }
        HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT*) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID*) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE get_Count(long*) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE Remove(BSTR) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE Item(BSTR, INetFwRule**) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE get__NewEnum(IUnknown**) override { return E_NOTIMPL; }
        HRESULT STDMETHODCALLTYPE Add(INetFwRule* rule) override
        {
            using namespace FirewallNative;
            ++calls;
            return Guard([&] {
                Bstr app, svc, local, remote;
                Check(rule->get_ApplicationName(&app.value)); Check(rule->get_ServiceName(&svc.value));
                Check(rule->get_LocalPorts(&local.value)); Check(rule->get_RemotePorts(&remote.value));
                Check(rule->get_Protocol(&protocol));
                applicationNull = app.value == nullptr; serviceNull = svc.value == nullptr;
                application = app.value ? app.value : L""; service = svc.value ? svc.value : L"";
                localPorts = local.value ? local.value : L""; remotePorts = remote.value ? remote.value : L"";
                Check(result);
            });
        }
    };

    void AddBoundary()
    {
        using namespace FirewallNative;
        Check(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
        try
        {
            for (const bool inbound : {false, true})
            {
                Policy policy;
                auto* probe = new AddProbe();
                policy.rules.Attach(probe);
                Writer packet;
                const wchar_t* fields[] = {
                    L"WinTraceForge.Detached.AddBoundary", L"WinTraceForge.Firewall.v1",
                    L"Detached test only", L"", L"", L"*", L"192.10.10.1",
                    inbound ? L"443" : L"*", inbound ? L"*" : L"1234", L"All",
                    L"", L"", L"", L"", L""
                };
                for (const auto* field : fields)
                {
                    Bstr text; text.value = SysAllocString(field); Check(text.value ? S_OK : E_OUTOFMEMORY);
                    packet.String(text.value);
                }
                packet.Int(0);
                for (const uint32_t value : {6u, inbound ? 1u : 2u, 0u, 1u, 0u, 0u, 1u, 0u}) { packet.Int(value); }
                Writer prepared;
                policy.Execute(5, packet.bytes, prepared);
                Writer empty, response;
                Assert(Guard([&] { policy.Execute(7, empty.bytes, response); }) == E_ACCESSDENIED,
                    "actual Add boundary preserves injected persistence HRESULT");
                Assert(probe->calls == 1, "operation 7 invokes collection exactly once");
                Assert(probe->applicationNull, "unspecified application remains NULL at Add boundary");
                Assert(probe->serviceNull, "unspecified service remains NULL at Add boundary");
                Assert(probe->protocol == 6, "protocol preserved at Add boundary");
                Assert(probe->localPorts == (inbound ? L"443" : L"*"), "local port scope at Add boundary");
                Assert(probe->remotePorts == (inbound ? L"*" : L"1234"), "remote port scope at Add boundary");
            }
        }
        catch (...) { CoUninitialize(); throw; }
        CoUninitialize();
    }
    void Codec()
    {
        using namespace FirewallNative;
        Writer output;
        output.String(nullptr);
        Bstr empty;
        empty.value = SysAllocString(L"");
        output.String(empty.value);
        Bstr unicode;
        unicode.value = SysAllocString(L"Ethernet-\x7f51\x7edc");
        output.String(unicode.value);
        Reader reader(output.bytes);
        Assert(reader.String().isNull, "null BSTR preserved");
        Text text = reader.String();
        Assert(!text.isNull && text.value.empty(), "empty BSTR preserved");
        Assert(reader.String().value == unicode.value, "UTF16 preserved");
        reader.End();
        Invalid([&] { reader.Int(); }, "truncated integer");
        Writer malformed;
        malformed.Int(MaxString + 1);
        Invalid([&] { Reader value(malformed.bytes); value.String(); }, "huge string rejected");
        malformed.bytes.resize(4);
        malformed.Int(2);
        Invalid([&] { Reader value(malformed.bytes); value.String(); }, "truncated string rejected");
        malformed.bytes.resize(4);
        malformed.Int(2);
        const wchar_t nul[] = {L'a', 0};
        malformed.Raw(nul, sizeof(nul));
        Invalid([&] { Reader value(malformed.bytes); value.String(); }, "embedded NUL rejected");
        malformed.bytes.resize(4);
        malformed.Int(2);
        Invalid([&] { Reader value(malformed.bytes); value.Boolean(); }, "noncanonical Boolean rejected");
        Invalid([&] { Reader value(malformed.bytes); value.End(); }, "trailing data rejected");
        Variant list;
        list.value.vt = VT_ARRAY | VT_VARIANT;
        SAFEARRAYBOUND bound = {2, 7};
        list.value.parray = SafeArrayCreate(VT_VARIANT, 1, &bound);
        Assert(list.value.parray != nullptr, "variant array allocation");
        Variant item;
        item.value.vt = VT_BSTR;
        item.value.bstrVal = SysAllocString(L"interface-7");
        LONG index = 7;
        Check(SafeArrayPutElement(list.value.parray, &index, &item.value));
        index = 8;
        Check(SafeArrayPutElement(list.value.parray, &index, &item.value));
        Writer strings;
        strings.Strings(list.value);
        Reader arrayReader(strings.bytes);
        Assert(arrayReader.Int() == 2, "nonzero lower bound count");
        Assert(arrayReader.String().value == L"interface-7", "variant array first");
        Assert(arrayReader.String().value == L"interface-7", "variant array second");
        arrayReader.End();
        Variant invalid;
        invalid.value.vt = VT_I4;
        Invalid([&] { Writer value; value.Strings(invalid.value); }, "non-array not defaulted");
        Variant wrongItem;
        wrongItem.value.vt = VT_I4;
        Check(SafeArrayPutElement(list.value.parray, &index, &wrongItem.value));
        Invalid([&] { Writer value; value.Strings(list.value); }, "non-string array item refused");
        Variant bstrList;
        bstrList.value.vt = VT_ARRAY | VT_BSTR;
        bstrList.value.parray = SafeArrayCreateVector(VT_BSTR, 0, 1);
        index = 0;
        Check(SafeArrayPutElement(bstrList.value.parray, &index, unicode.value));
        Writer bstrWriter;
        bstrWriter.Strings(bstrList.value);
        Reader bstrReader(bstrWriter.bytes);
        Assert(bstrReader.Int() == 1 && bstrReader.String().value == unicode.value, "BSTR array supported");
    }
    void Parameters()
    {
        using namespace FirewallNative;
        Assert(FirewallNativeOpen(nullptr) == E_POINTER, "null open output");
        Assert(FirewallNativeClose(nullptr) == E_HANDLE, "null session");
        Assert(FirewallNativeClose(reinterpret_cast<void*>(123456789)) == E_HANDLE, "unknown session");
        void* session = nullptr;
        Check(FirewallNativeOpen(&session));
        try
        {
            Writer packet;
            Assert(Invoke(session, 1, packet.bytes) == S_OK, "read current profile");
            Assert(Invoke(session, 2, packet.bytes) == S_OK, "read local modify state");
            Assert(Invoke(session, 3, packet.bytes) == S_OK, "read profiles");
            Assert(Invoke(session, 0, packet.bytes) == E_INVALIDARG, "invalid operation zero");
            Assert(Invoke(session, 9, packet.bytes) == E_INVALIDARG, "invalid operation upper");
            Assert(Invoke(reinterpret_cast<void*>(123456789), 1, packet.bytes) == E_HANDLE, "unknown invoke handle");
            Assert(Invoke(session, 7, packet.bytes) == HRESULT_FROM_WIN32(ERROR_INVALID_STATE),
                "Add without detached rule stops before Rules.Add");
            packet.Int(UINT32_MAX);
            Assert(Invoke(session, 4, packet.bytes) == E_INVALIDARG, "null lookup name");
            Assert(Invoke(session, 8, packet.bytes) == E_INVALIDARG, "null remove name rejected before Rules.Remove");
            packet.bytes.resize(4);
            packet.Int(0);
            Assert(Invoke(session, 4, packet.bytes) == E_INVALIDARG, "empty lookup name");
            packet.bytes.resize(4);
            packet.Int(15);
            Assert(Invoke(session, 4, packet.bytes) == E_INVALIDARG, "truncated name");
            Assert(Invoke(session, 5, packet.bytes) == E_INVALIDARG, "truncated rule");
            packet.bytes.resize(3);
            Assert(Invoke(session, 1, packet.bytes) == E_INVALIDARG, "short packet");
            packet.bytes.assign(4, 0);
            Assert(Invoke(session, 1, packet.bytes) == E_INVALIDARG, "bad magic");
            void* output = nullptr;
            uint32_t length = 0;
            Assert(FirewallNativeInvoke(session, 1, nullptr, 4, &output, &length) == E_INVALIDARG, "null input");
            Assert(FirewallNativeInvoke(session, 1, packet.bytes.data(), 4, nullptr, &length) == E_POINTER, "null output");
            Assert(FirewallNativeInvoke(session, 1, packet.bytes.data(), 4, &output, nullptr) == E_POINTER, "null length");
            Assert(FirewallNativeInvoke(session, 1, packet.bytes.data(), 0xffffffffu, &output, &length) == E_INVALIDARG, "oversized packet");
        }
        catch (...) { FirewallNativeClose(session); throw; }
        Check(FirewallNativeClose(session));
        Assert(FirewallNativeClose(session) == E_HANDLE, "double close");
        Writer packet;
        Assert(Invoke(session, 1, packet.bytes) == E_HANDLE, "closed handle invocation");
        FirewallNativeFree(nullptr);
    }
}
int main()
{
    try
    {
        Codec();
        Parameters();
        AddBoundary();
        std::cout << "PASS: " << assertions << " native assertions; no persistent COM writes.\n";
        return 0;
    }
    catch (const FirewallNative::Failure& error)
    { std::cerr << "HRESULT: " << std::hex << error.code << "\n"; return 1; }
    catch (const std::exception& error) { std::cerr << error.what() << "\n"; return 1; }
}
