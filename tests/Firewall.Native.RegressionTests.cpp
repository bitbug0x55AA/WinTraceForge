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

    // Snapshot of the rule as INetFwRules::Add received it. Text keeps NULL and
    // allocated-empty BSTRs distinct; never compare these through rendered text.
    struct Submitted
    {
        FirewallNative::Text name, grouping, description, application, service,
            localAddresses, remoteAddresses, localPorts, remotePorts, interfaceTypes;
        long protocol = -1, profiles = -1, edgeOptions = -1;
        NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_MAX;
        NET_FW_ACTION action = NET_FW_ACTION_MAX;
        VARIANT_BOOL enabled = VARIANT_FALSE, edge = VARIANT_TRUE;
        bool preparedObject = false;
    };

    FirewallNative::Text Capture(INetFwRule* rule, HRESULT (STDMETHODCALLTYPE INetFwRule::*get)(BSTR*))
    {
        FirewallNative::Bstr value;
        FirewallNative::Check((rule->*get)(&value.value));
        FirewallNative::Text text;
        text.isNull = value.value == nullptr;
        if (value.value) { text.value.assign(value.value, SysStringLen(value.value)); }
        return text;
    }

    bool IsNull(const FirewallNative::Text& text) { return text.isNull; }
    bool IsEmpty(const FirewallNative::Text& text) { return !text.isNull && text.value.empty(); }
    bool Is(const FirewallNative::Text& text, const wchar_t* expected) { return !text.isNull && text.value == expected; }

    // Intercept the exact Rules.Add boundary; never forward to the real policy collection.
    struct AddProbe : INetFwRules
    {
        ULONG references = 1;
        unsigned calls = 0;
        IUnknown* prepared = nullptr;
        Submitted seen;
        // A probe that cannot inspect the rule must fail the test, not pass vacuously.
        HRESULT snapshot = E_UNEXPECTED;
        HRESULT result = S_OK;
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
            snapshot = Guard([&] {
                Require(rule != nullptr);
                ComPtr<IUnknown> identity;
                Check(rule->QueryInterface(IID_PPV_ARGS(identity.GetAddressOf())));
                seen.preparedObject = identity.Get() == prepared;
                seen.name = Capture(rule, &INetFwRule::get_Name);
                seen.grouping = Capture(rule, &INetFwRule::get_Grouping);
                seen.description = Capture(rule, &INetFwRule::get_Description);
                seen.application = Capture(rule, &INetFwRule::get_ApplicationName);
                seen.service = Capture(rule, &INetFwRule::get_ServiceName);
                seen.localAddresses = Capture(rule, &INetFwRule::get_LocalAddresses);
                seen.remoteAddresses = Capture(rule, &INetFwRule::get_RemoteAddresses);
                seen.localPorts = Capture(rule, &INetFwRule::get_LocalPorts);
                seen.remotePorts = Capture(rule, &INetFwRule::get_RemotePorts);
                seen.interfaceTypes = Capture(rule, &INetFwRule::get_InterfaceTypes);
                Check(rule->get_Protocol(&seen.protocol));
                Check(rule->get_Direction(&seen.direction));
                Check(rule->get_Action(&seen.action));
                // NetFwRule get_Profiles ORs the mask into *out rather than assigning it.
                seen.profiles = 0;
                Check(rule->get_Profiles(&seen.profiles));
                Check(rule->get_Enabled(&seen.enabled));
                Check(rule->get_EdgeTraversal(&seen.edge));
                ComPtr<INetFwRule2> rule2;
                Check(rule->QueryInterface(IID_PPV_ARGS(rule2.GetAddressOf())));
                Check(rule2->get_EdgeTraversalOptions(&seen.edgeOptions));
            });
            return result;
        }
    };

    // Mirrors FirewallModule.ExpectedRule: the managed model encodes "no program/service"
    // as "" and the builder must not turn that into an allocated empty BSTR.
    struct Request
    {
        const wchar_t* name = L"WinTraceForge.Firewall.AddBoundary";
        const wchar_t* grouping = L"WinTraceForge.Firewall.v1";
        const wchar_t* description = L"WinTraceForge detached Add-boundary test";
        const wchar_t* application = L"";
        const wchar_t* service = L"";
        const wchar_t* localAddresses = L"*";
        const wchar_t* remoteAddresses = L"192.0.2.15";
        // NetFwRule canonicalizes one host as a full mask (IPv4) or singleton range (IPv6).
        const wchar_t* remoteCanonical = L"192.0.2.15/255.255.255.255";
        const wchar_t* localPorts = L"*";
        const wchar_t* remotePorts = L"1234";
        uint32_t protocol = 6, direction = 2, action = 0, profiles = 2, enabled = 1;

        // nullptr fields are encoded as the ABI NULL state (-1), not as "".
        std::vector<unsigned char> Packet() const
        {
            using namespace FirewallNative;
            Writer packet;
            const wchar_t* fields[] = {
                name, grouping, description, application, service, localAddresses, remoteAddresses,
                localPorts, remotePorts, L"All", L"", L"", L"", L"", L""
            };
            for (const auto* field : fields)
            {
                Bstr text;
                if (field) { text.value = SysAllocString(field); Check(text.value ? S_OK : E_OUTOFMEMORY); }
                packet.String(text.value);
            }
            packet.Int(0);
            for (const uint32_t value : {protocol, direction, action, profiles, 0u, 0u, enabled, 0u}) { packet.Int(value); }
            return packet.bytes;
        }
    };

    // Prepares a detached NetFwRule through operation 5 exactly as the DLL does,
    // then submits it through operation 7 to a probe collection. No policy is opened.
    struct Boundary
    {
        FirewallNative::Policy policy;
        AddProbe* probe = new AddProbe();
        HRESULT prepare = E_UNEXPECTED, add = E_UNEXPECTED;
        FirewallNative::Writer response;

        explicit Boundary(const Request& request, HRESULT addResult = S_OK,
            const std::function<void(INetFwRule3*)>& tamper = nullptr)
        {
            using namespace FirewallNative;
            policy.rules.Attach(probe);
            probe->result = addResult;
            Writer readback;
            prepare = Guard([&] { policy.Execute(5, request.Packet(), readback); });
            if (FAILED(prepare)) { return; }
            ComPtr<IUnknown> identity;
            Check(policy.prepared.As(&identity));
            probe->prepared = identity.Get();
            if (tamper) { tamper(policy.prepared.Get()); }
            const Writer empty;
            add = Guard([&] { policy.Execute(7, empty.bytes, response); });
        }
        const Submitted& Seen() const
        {
            Assert(probe->calls == 1 && probe->snapshot == S_OK, "Add probe captured the submitted rule");
            return probe->seen;
        }
    };

    void ExpectSubmitted(const Boundary& boundary, const Request& request, const char* label)
    {
        const std::string prefix = std::string(label) + ": ";
        auto check = [&](bool condition, const char* what) { Assert(condition, (prefix + what).c_str()); };
        const Submitted& seen = boundary.Seen();
        check(boundary.prepare == S_OK, "detached preparation succeeded");
        check(boundary.probe->calls == 1, "INetFwRules::Add invoked exactly once");
        check(seen.preparedObject, "Add received the prepared detached object itself");
        check(Is(seen.name, request.name), "Name");
        check(Is(seen.grouping, request.grouping), "Grouping");
        check(Is(seen.description, request.description), "Description");
        check(Is(seen.localAddresses, request.localAddresses), "LocalAddresses");
        check(Is(seen.remoteAddresses, request.remoteAddresses) || Is(seen.remoteAddresses, request.remoteCanonical),
            "RemoteAddresses is the one requested host");
        check(Is(seen.localPorts, request.localPorts), "LocalPorts");
        check(Is(seen.remotePorts, request.remotePorts), "RemotePorts");
        check(Is(seen.interfaceTypes, L"All"), "InterfaceTypes");
        check(seen.protocol == static_cast<long>(request.protocol), "Protocol");
        check(seen.direction == static_cast<NET_FW_RULE_DIRECTION>(request.direction), "Direction");
        check(seen.action == static_cast<NET_FW_ACTION>(request.action), "Action");
        check(seen.profiles == static_cast<long>(request.profiles), "Profiles");
        check(seen.enabled == (request.enabled ? VARIANT_TRUE : VARIANT_FALSE), "Enabled");
        check(seen.edge == VARIANT_FALSE && seen.edgeOptions == 0, "edge traversal disabled");
    }

    // Regression: an outbound TCP rule failed at INetFwRules::Add with E_INVALIDARG because
    // unspecified ApplicationName/ServiceName were submitted as SysAllocString(L"").
    void UnspecifiedScopesStayNull()
    {
        Request outboundTcp;  // The live-tested failing shape: outbound TCP to one address and remote port.
        Request inboundTcp;
        inboundTcp.direction = 1; inboundTcp.action = 1; inboundTcp.localPorts = L"443"; inboundTcp.remotePorts = L"*";
        inboundTcp.profiles = 7;
        Request outboundUdp;
        outboundUdp.protocol = 17; outboundUdp.remoteAddresses = L"2001:db8::1";
        outboundUdp.remoteCanonical = L"2001:db8::1-2001:db8::1";
        outboundUdp.localPorts = L"12345"; outboundUdp.remotePorts = L"53"; outboundUdp.profiles = 1;
        outboundUdp.enabled = 0;
        const std::pair<const char*, Request> cases[] = {
            {"outbound TCP", outboundTcp}, {"inbound TCP", inboundTcp}, {"outbound UDP", outboundUdp}
        };
        for (const auto& entry : cases)
        {
            // Both ABI encodings of "unspecified" (managed "" and NULL) must reach Add as NULL.
            for (const bool nullEncoding : {false, true})
            {
                Request request = entry.second;
                if (nullEncoding) { request.application = nullptr; request.service = nullptr; }
                const std::string label = std::string(entry.first) + (nullEncoding ? " (NULL request)" : " (empty request)");
                Boundary boundary(request);
                ExpectSubmitted(boundary, request, label.c_str());
                Assert(boundary.add == S_OK, (label + ": Add success returned").c_str());
                Assert(IsNull(boundary.Seen().application), (label + ": unspecified ApplicationName is NULL at Add, not empty BSTR").c_str());
                Assert(IsNull(boundary.Seen().service), (label + ": unspecified ServiceName is NULL at Add, not empty BSTR").c_str());
            }
        }
    }

    void ExplicitScopesReachAdd()
    {
        Request program;
        program.application = L"C:\\Windows\\System32\\notepad.exe";
        Boundary withProgram(program);
        ExpectSubmitted(withProgram, program, "explicit program");
        Assert(Is(withProgram.Seen().application, program.application), "explicit program reaches Add exactly");
        Assert(IsNull(withProgram.Seen().service), "program rule keeps unspecified service NULL");
        Request service;
        service.service = L"Dnscache";
        Boundary withService(service);
        ExpectSubmitted(withService, service, "explicit service");
        Assert(Is(withService.Seen().service, service.service), "explicit service reaches Add exactly");
        Assert(IsNull(withService.Seen().application), "service rule keeps unspecified program NULL");
    }

    // Representation must be preserved, not inferred from rendered text. Description is a
    // property where the detached object keeps NULL and L"" distinct, so the builder must too.
    void ExplicitEmptyVersusUnspecified()
    {
        Request unspecified;
        unspecified.description = nullptr;
        Boundary absent(unspecified);
        Assert(absent.prepare == S_OK && absent.add == S_OK, "NULL Description prepared and submitted");
        Assert(IsNull(absent.Seen().description), "NULL Description stays NULL at Add");
        Request supplied;
        supplied.description = L"";
        Boundary empty(supplied);
        Assert(empty.prepare == S_OK && empty.add == S_OK, "empty Description prepared and submitted");
        Assert(IsEmpty(empty.Seen().description), "explicitly empty Description stays an empty BSTR at Add");
    }

    // Negative control: prove this Windows build's detached rule still exposes an allocated
    // empty BSTR at the Add boundary. If it ever normalizes to NULL, the NULL assertions above
    // would pass vacuously, so fail here instead of silently losing regression coverage.
    void ProbeDetectsEmptyBstr()
    {
        using namespace FirewallNative;
        Request request;
        Boundary boundary(request, S_OK, [](INetFwRule3* rule) {
            Bstr empty; empty.value = SysAllocString(L""); Check(empty.value ? S_OK : E_OUTOFMEMORY);
            Check(rule->put_ApplicationName(empty.value));
            Check(rule->put_ServiceName(empty.value));
        });
        Assert(boundary.probe->calls == 1, "negative control reached Add");
        Assert(IsEmpty(boundary.Seen().application), "probe distinguishes empty ApplicationName from NULL");
        Assert(IsEmpty(boundary.Seen().service), "probe distinguishes empty ServiceName from NULL");
    }

    void AddHresultPropagation()
    {
        const HRESULT failures[] = {
            E_INVALIDARG,  // The live failure: must stay attributable to Add, not preparation.
            E_ACCESSDENIED, HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), HRESULT_FROM_WIN32(ERROR_INVALID_STATE),
            static_cast<HRESULT>(0x800706BAL), static_cast<HRESULT>(0x8007F00DL)
        };
        for (const HRESULT failure : failures)
        {
            Request request;
            Boundary boundary(request, failure);
            Assert(boundary.prepare == S_OK, "preparation succeeds before injected Add failure");
            Assert(boundary.probe->calls == 1, "failing Add invoked exactly once");
            Assert(boundary.add == failure, "exact INetFwRules::Add HRESULT returned");
            Assert(boundary.response.bytes.size() == 4, "failed Add writes no response payload");
            Assert(IsNull(boundary.Seen().application) && IsNull(boundary.Seen().service),
                "failed Add still received NULL optional scopes");
        }
        Request request;
        Boundary success(request, S_FALSE);
        Assert(success.add == S_OK, "success-code Add normalizes to S_OK");
        Assert(success.response.bytes.size() == 4, "successful Add returns an empty v1 packet");
    }

    void AddBoundary()
    {
        using namespace FirewallNative;
        Check(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
        try
        {
            UnspecifiedScopesStayNull();
            ExplicitScopesReachAdd();
            ExplicitEmptyVersusUnspecified();
            ProbeDetectsEmptyBstr();
            AddHresultPropagation();
        }
        catch (...) { CoUninitialize(); throw; }
        CoUninitialize();
    }
    // Shared ABI contract with Firewall.RegressionTests.cs NullVersusEmptyCodec: identical bytes.
    // A normalization helper that collapses NULL and L"" on either side must break one of them.
    const unsigned char NullThenEmpty[] = { 0x4e, 0x57, 0x46, 0x31, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };

    void NullVersusEmpty()
    {
        using namespace FirewallNative;
        const std::vector<unsigned char> golden(std::begin(NullThenEmpty), std::end(NullThenEmpty));
        Writer output;
        output.String(nullptr);
        Bstr empty;
        empty.value = SysAllocString(L"");
        Assert(empty.value != nullptr, "allocate empty BSTR");
        output.String(empty.value);
        Assert(output.bytes == golden, "NULL encodes as -1 and allocated empty BSTR as zero length");
        Reader reader(golden);
        const Text decodedNull = reader.String(), decodedEmpty = reader.String();
        reader.End();
        Assert(decodedNull.isNull, "-1 decodes as NULL");
        Assert(!decodedEmpty.isNull && decodedEmpty.value.empty(), "zero length decodes as empty, not NULL");
        Bstr allocatedNull, allocatedEmpty;
        decodedNull.Allocate(allocatedNull);
        decodedEmpty.Allocate(allocatedEmpty);
        Assert(allocatedNull.value == nullptr, "NULL Text allocates no BSTR");
        Assert(allocatedEmpty.value != nullptr && SysStringLen(allocatedEmpty.value) == 0, "empty Text allocates empty BSTR");
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
        NullVersusEmpty();
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
int main(int argc, char** argv)
{
    try
    {
        // --deterministic (CI) needs no firewall policy: only codec checks and detached rules
        // submitted to a probe collection. The default mode also opens the live policy read-only.
        const bool deterministic = argc == 2 && std::string(argv[1]) == "--deterministic";
        if (argc > 2 || (argc == 2 && !deterministic)) { std::cerr << "usage: [--deterministic]\n"; return 2; }
        Codec();
        if (!deterministic) { Parameters(); }
        AddBoundary();
        std::cout << "PASS: " << assertions << " native assertions" << (deterministic ? " (deterministic)" : "") <<
            "; no persistent COM writes.\n";
        return 0;
    }
    catch (const FirewallNative::Failure& error)
    { std::cerr << "HRESULT: " << std::hex << error.code << "\n"; return 1; }
    catch (const std::exception& error) { std::cerr << error.what() << "\n"; return 1; }
}
