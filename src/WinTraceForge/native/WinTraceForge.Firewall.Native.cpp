// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netfw.h>
#include <wrl/client.h>
#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

// ABI v1: little-endian integers and counted UTF-16 (not terminated strings).
// Every packet starts with 0x3146574e. Strings use a signed character count;
// -1 means a null BSTR, distinct from an allocated empty BSTR.
// Operations: 1 current profiles, 2 modify state, 3 profiles, 4 find by name,
// 5 detached prepare/readback, 6 discard prepared, 7 Rules.Add, 8 Rules.Remove.
// Only operations 7 and 8 persist anything. There is no policy setter.
namespace FirewallNative
{
    using Microsoft::WRL::ComPtr;
    constexpr uint32_t Magic = 0x3146574e;
    constexpr size_t MaxPacket = 16 * 1024 * 1024;
    constexpr uint32_t MaxCount = 65536;
    constexpr uint32_t MaxString = 1024 * 1024;

    struct Failure { HRESULT code; };
    void Check(HRESULT hr) { if (FAILED(hr)) { throw Failure{hr}; } }
    void Require(bool condition) { if (!condition) { throw Failure{E_INVALIDARG}; } }

    struct Bstr
    {
        BSTR value = nullptr;
        Bstr() = default;
        ~Bstr() { SysFreeString(value); }
        Bstr(const Bstr&) = delete;
        Bstr& operator=(const Bstr&) = delete;
    };

    struct Variant
    {
        VARIANT value;
        Variant() { VariantInit(&value); }
        ~Variant() { VariantClear(&value); }
        Variant(const Variant&) = delete;
        Variant& operator=(const Variant&) = delete;
    };

    struct Text
    {
        bool isNull = false;
        std::wstring value;
        void Allocate(Bstr& target) const
        {
            if (isNull) { return; }
            target.value = SysAllocStringLen(value.data(), static_cast<UINT>(value.size()));
            if (!target.value) { throw Failure{E_OUTOFMEMORY}; }
        }
    };

    struct Writer
    {
        std::vector<unsigned char> bytes;
        Writer() { Int(Magic); }
        void Raw(const void* data, size_t size)
        {
            Require(size <= MaxPacket - bytes.size());
            if (size == 0) { return; }
            const auto* begin = static_cast<const unsigned char*>(data);
            bytes.insert(bytes.end(), begin, begin + size);
        }
        void Int(uint32_t value) { Raw(&value, sizeof(value)); }
        void String(BSTR value)
        {
            if (!value) { Int(UINT32_MAX); return; }
            const UINT size = SysStringLen(value);
            Require(size <= MaxString);
            Int(size);
            Raw(value, static_cast<size_t>(size) * sizeof(wchar_t));
        }
        void Boolean(VARIANT_BOOL value)
        {
            Require(value == VARIANT_FALSE || value == VARIANT_TRUE);
            Int(value == VARIANT_TRUE ? 1u : 0u);
        }
        void Strings(const VARIANT& value)
        {
            if (value.vt == VT_EMPTY || value.vt == VT_NULL) { Int(0); return; }
            Require(value.vt == (VT_ARRAY | VT_BSTR) || value.vt == (VT_ARRAY | VT_VARIANT));
            SAFEARRAY* array = value.parray;
            Require(array && SafeArrayGetDim(array) == 1);
            LONG lower = 0, upper = 0;
            Check(SafeArrayGetLBound(array, 1, &lower));
            Check(SafeArrayGetUBound(array, 1, &upper));
            const int64_t count = static_cast<int64_t>(upper) - lower + 1;
            Require(count >= 0 && count <= MaxCount);
            Int(static_cast<uint32_t>(count));
            for (int64_t offset = 0; offset < count; ++offset)
            {
                LONG index = static_cast<LONG>(static_cast<int64_t>(lower) + offset);
                if (value.vt == (VT_ARRAY | VT_BSTR))
                {
                    Bstr item;
                    Check(SafeArrayGetElement(array, &index, &item.value));
                    String(item.value);
                }
                else
                {
                    Variant item;
                    Check(SafeArrayGetElement(array, &index, &item.value));
                    Require(item.value.vt == VT_BSTR);
                    String(item.value.bstrVal);
                }
            }
        }
    };

    struct Reader
    {
        const std::vector<unsigned char>& bytes;
        size_t position = 0;
        explicit Reader(const std::vector<unsigned char>& input) : bytes(input) { Require(Int() == Magic); }
        uint32_t Int()
        {
            Require(position <= bytes.size() && bytes.size() - position >= sizeof(uint32_t));
            uint32_t value;
            memcpy(&value, bytes.data() + position, sizeof(value));
            position += sizeof(value);
            return value;
        }
        Text String()
        {
            const uint32_t count = Int();
            Text text;
            if (count == UINT32_MAX) { text.isNull = true; return text; }
            Require(count <= MaxString && count <= (bytes.size() - position) / sizeof(wchar_t));
            text.value.resize(count);
            if (count) { memcpy(&text.value[0], bytes.data() + position, static_cast<size_t>(count) * sizeof(wchar_t)); }
            position += static_cast<size_t>(count) * sizeof(wchar_t);
            // Reject NULs rather than allowing COM to treat a counted name as a prefix.
            Require(text.value.find(L'\0') == std::wstring::npos);
            return text;
        }
        uint32_t Boolean() { const auto value = Int(); Require(value <= 1); return value; }
        void End() const { Require(position == bytes.size()); }
    };

    struct Rule
    {
        Text text[15];
        std::vector<Text> interfaces;
        uint32_t protocol, direction, action, profiles, edgeOptions, secureFlags, enabled, edge;
        explicit Rule(Reader& reader)
        {
            for (auto& value : text) { value = reader.String(); }
            const uint32_t count = reader.Int();
            Require(count <= MaxCount);
            for (uint32_t i = 0; i < count; ++i) { interfaces.push_back(reader.String()); }
            protocol = reader.Int(); direction = reader.Int(); action = reader.Int();
            profiles = reader.Int(); edgeOptions = reader.Int(); secureFlags = reader.Int();
            enabled = reader.Boolean(); edge = reader.Boolean();
            reader.End();
            Require(!text[0].isNull && !text[0].value.empty());
        }
    };

    void ReadRule(INetFwRule3* rule, Writer& output)
    {
#define FW_STRING(property) { Bstr value; Check(rule->get_##property(&value.value)); output.String(value.value); }
        FW_STRING(Name)
        FW_STRING(Grouping)
        FW_STRING(Description)
        FW_STRING(ApplicationName)
        FW_STRING(ServiceName)
        FW_STRING(LocalAddresses)
        FW_STRING(RemoteAddresses)
        FW_STRING(LocalPorts)
        FW_STRING(RemotePorts)
        FW_STRING(InterfaceTypes)
        FW_STRING(LocalAppPackageId)
        FW_STRING(LocalUserOwner)
        FW_STRING(LocalUserAuthorizedList)
        FW_STRING(RemoteUserAuthorizedList)
        FW_STRING(RemoteMachineAuthorizedList)
#undef FW_STRING
        Variant interfaces;
        Check(rule->get_Interfaces(&interfaces.value));
        output.Strings(interfaces.value);
        long protocol = 0, profiles = 0, edgeOptions = 0, secureFlags = 0;
        NET_FW_RULE_DIRECTION direction;
        NET_FW_ACTION action;
        VARIANT_BOOL enabled = VARIANT_FALSE, edge = VARIANT_FALSE;
        Check(rule->get_Protocol(&protocol));
        Check(rule->get_Direction(&direction));
        Check(rule->get_Action(&action));
        Check(rule->get_Profiles(&profiles));
        Check(rule->get_EdgeTraversalOptions(&edgeOptions));
        Check(rule->get_SecureFlags(&secureFlags));
        Check(rule->get_Enabled(&enabled));
        Check(rule->get_EdgeTraversal(&edge));
        output.Int(static_cast<uint32_t>(protocol));
        output.Int(static_cast<uint32_t>(direction));
        output.Int(static_cast<uint32_t>(action));
        output.Int(static_cast<uint32_t>(profiles));
        output.Int(static_cast<uint32_t>(edgeOptions));
        output.Int(static_cast<uint32_t>(secureFlags));
        output.Boolean(enabled);
        output.Boolean(edge);
    }

    struct Policy
    {
        ComPtr<INetFwPolicy2> policy;
        ComPtr<INetFwRules> rules;
        ComPtr<INetFwRule3> prepared;

        void Open()
        {
            Check(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(policy.GetAddressOf())));
            Check(policy->get_Rules(rules.GetAddressOf()));
            Require(rules != nullptr);
        }
        void Profiles(Writer& output)
        {
            output.Int(3);
            for (const int profile : {1, 2, 4})
            {
                const auto type = static_cast<NET_FW_PROFILE_TYPE2>(profile);
                VARIANT_BOOL enabled = VARIANT_FALSE, block = VARIANT_FALSE;
                NET_FW_ACTION inbound, outbound;
                Variant excluded;
                Check(policy->get_FirewallEnabled(type, &enabled));
                Check(policy->get_BlockAllInboundTraffic(type, &block));
                Check(policy->get_DefaultInboundAction(type, &inbound));
                Check(policy->get_DefaultOutboundAction(type, &outbound));
                Check(policy->get_ExcludedInterfaces(type, &excluded.value));
                output.Int(static_cast<uint32_t>(profile));
                output.Int(static_cast<uint32_t>(inbound));
                output.Int(static_cast<uint32_t>(outbound));
                output.Boolean(enabled);
                output.Boolean(block);
                output.Strings(excluded.value);
            }
        }
        void Find(const Text& name, Writer& output)
        {
            Require(!name.isNull && !name.value.empty());
            ComPtr<IUnknown> unknown;
            Check(rules->get__NewEnum(unknown.GetAddressOf()));
            Require(unknown != nullptr);
            ComPtr<IEnumVARIANT> enumeration;
            Check(unknown.As(&enumeration));
            const size_t countOffset = output.bytes.size();
            output.Int(0);
            uint32_t count = 0;
            while (true)
            {
                Variant item;
                ULONG fetched = 0;
                const HRESULT hr = enumeration->Next(1, &item.value, &fetched);
                Check(hr);
                if (hr == S_FALSE) { Require(fetched == 0); break; }
                Require(hr == S_OK && fetched == 1);
                IUnknown* object = nullptr;
                if (item.value.vt == VT_DISPATCH) { object = item.value.pdispVal; }
                else if (item.value.vt == VT_UNKNOWN) { object = item.value.punkVal; }
                Require(object != nullptr);
                ComPtr<INetFwRule> base;
                Check(object->QueryInterface(IID_PPV_ARGS(base.GetAddressOf())));
                Bstr actual;
                Check(base->get_Name(&actual.value));
                const UINT length = SysStringLen(actual.value);
                if (actual.value && length == name.value.size() &&
                    CompareStringOrdinal(actual.value, static_cast<int>(length), name.value.data(),
                        static_cast<int>(name.value.size()), TRUE) == CSTR_EQUAL)
                {
                    ComPtr<INetFwRule3> rule;
                    Check(base.As(&rule));
                    Require(count < MaxCount);
                    ReadRule(rule.Get(), output);
                    ++count;
                }
            }
            memcpy(output.bytes.data() + countOffset, &count, sizeof(count));
        }
        void Prepare(const Rule& expected, Writer& output)
        {
            if (prepared) { throw Failure{HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)}; }
            ComPtr<INetFwRule3> rule;
            Check(CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(rule.GetAddressOf())));
#define FW_SET(property, index) { Bstr value; expected.text[index].Allocate(value); Check(rule->put_##property(value.value)); }
            FW_SET(Name, 0)
            FW_SET(Description, 2)
            FW_SET(Grouping, 1)
            Check(rule->put_Protocol(static_cast<long>(expected.protocol)));
            FW_SET(LocalAddresses, 5)
            FW_SET(RemoteAddresses, 6)
            // TCP/UDP initializes unspecified ports. Leave optional scopes unset:
            // an allocated empty BSTR is not the default NULL application/service.
            if (!expected.text[7].isNull && !expected.text[7].value.empty() && expected.text[7].value != L"*")
            { FW_SET(LocalPorts, 7) }
            if (!expected.text[8].isNull && !expected.text[8].value.empty() && expected.text[8].value != L"*")
            { FW_SET(RemotePorts, 8) }
            if (!expected.text[3].isNull && !expected.text[3].value.empty()) { FW_SET(ApplicationName, 3) }
            if (!expected.text[4].isNull && !expected.text[4].value.empty()) { FW_SET(ServiceName, 4) }
            FW_SET(InterfaceTypes, 9)
#undef FW_SET
            Check(rule->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(expected.direction)));
            Check(rule->put_Action(static_cast<NET_FW_ACTION>(expected.action)));
            Check(rule->put_Profiles(static_cast<long>(expected.profiles)));
            Check(rule->put_EdgeTraversal(VARIANT_FALSE));
            Check(rule->put_EdgeTraversalOptions(0));
            Check(rule->put_Enabled(expected.enabled ? VARIANT_TRUE : VARIANT_FALSE));
            // Match COM preflight: do not set interface/IPsec/package/user restrictions.
            // Read every default and let the managed ownership comparator reject differences.
            ReadRule(rule.Get(), output);
            prepared = rule;
        }
        void Execute(uint32_t operation, const std::vector<unsigned char>& input, Writer& output)
        {
            Reader reader(input);
            if (operation == 4 || operation == 8)
            {
                const Text name = reader.String();
                reader.End();
                Require(!name.isNull && !name.value.empty());
                if (operation == 4) { Find(name, output); }
                else { Bstr value; name.Allocate(value); Check(rules->Remove(value.value)); }
                return;
            }
            if (operation == 5) { const Rule rule(reader); Prepare(rule, output); return; }
            reader.End();
            switch (operation)
            {
                case 1:
                {
                    long value = 0; Check(policy->get_CurrentProfileTypes(&value));
                    output.Int(static_cast<uint32_t>(value)); break;
                }
                case 2:
                {
                    NET_FW_MODIFY_STATE value;
                    Check(policy->get_LocalPolicyModifyState(&value));
                    output.Int(static_cast<uint32_t>(value)); break;
                }
                case 3: Profiles(output); break;
                case 6: prepared.Reset(); break;
                case 7:
                    if (!prepared) { throw Failure{HRESULT_FROM_WIN32(ERROR_INVALID_STATE)}; }
                    Check(rules->Add(prepared.Get())); break;
                default: throw Failure{E_INVALIDARG};
            }
        }
    };

    template<typename F> HRESULT Guard(F action) noexcept
    {
        try { action(); return S_OK; }
        catch (const Failure& failure) { return failure.code; }
        catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
        catch (...) { return E_FAIL; }
    }

    // The worker creates, uses and releases all COM interfaces in its own MTA.
    // SafeHandle finalization is consequently safe on an arbitrary managed thread.
    struct Session
    {
        std::mutex gate, calls;
        std::condition_variable changed;
        bool ready = false, stopping = false, pending = false, complete = false;
        HRESULT startup = E_UNEXPECTED, result = E_UNEXPECTED;
        std::function<void(Policy&)> work;
        std::thread worker;

        Session() : worker([this] { Run(); })
        {
            std::unique_lock<std::mutex> lock(gate);
            changed.wait(lock, [this] { return ready; });
        }
        ~Session()
        {
            { std::lock_guard<std::mutex> lock(gate); stopping = true; }
            changed.notify_all();
            if (worker.joinable()) { worker.join(); }
        }
        void Run() noexcept
        {
            const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            {
                Policy policy;
                const HRESULT opened = FAILED(initialized) ? initialized : Guard([&] { policy.Open(); });
                std::unique_lock<std::mutex> lock(gate);
                startup = opened;
                ready = true;
                changed.notify_all();
                while (true)
                {
                    changed.wait(lock, [this] { return stopping || pending; });
                    if (stopping) { break; }
                    lock.unlock();
                    const HRESULT status = Guard([&] { work(policy); });
                    lock.lock();
                    result = status;
                    pending = false;
                    complete = true;
                    changed.notify_all();
                }
            }
            if (SUCCEEDED(initialized)) { CoUninitialize(); }
        }
        HRESULT Call(std::function<void(Policy&)> action)
        {
            std::lock_guard<std::mutex> serialized(calls);
            std::unique_lock<std::mutex> lock(gate);
            if (FAILED(startup)) { return startup; }
            work = std::move(action);
            complete = false;
            pending = true;
            changed.notify_all();
            changed.wait(lock, [this] { return complete; });
            work = nullptr;
            return result;
        }
    };

    std::mutex registryGate;
    std::map<uintptr_t, std::shared_ptr<Session>> registry;
    uintptr_t nextHandle = 1;
    std::shared_ptr<Session> Get(void* handle)
    {
        std::lock_guard<std::mutex> lock(registryGate);
        const auto found = registry.find(reinterpret_cast<uintptr_t>(handle));
        if (found == registry.end()) { throw Failure{E_HANDLE}; }
        return found->second;
    }
}

extern "C" __declspec(dllexport) HRESULT __cdecl FirewallNativeOpen(void** handle) noexcept
{
    if (!handle) { return E_POINTER; }
    *handle = nullptr;
    return FirewallNative::Guard([&]
    {
        auto session = std::make_shared<FirewallNative::Session>();
        FirewallNative::Check(session->startup);
        std::lock_guard<std::mutex> lock(FirewallNative::registryGate);
        FirewallNative::Require(FirewallNative::nextHandle < (std::numeric_limits<uintptr_t>::max)());
        const uintptr_t key = FirewallNative::nextHandle++;
        FirewallNative::registry.emplace(key, session);
        *handle = reinterpret_cast<void*>(key);
    });
}

extern "C" __declspec(dllexport) HRESULT __cdecl FirewallNativeInvoke(
    void* handle, uint32_t operation, const unsigned char* input, uint32_t inputLength,
    void** output, uint32_t* outputLength) noexcept
{
    if (!output || !outputLength) { return E_POINTER; }
    *output = nullptr;
    *outputLength = 0;
    if (!input || inputLength < 4 || inputLength > FirewallNative::MaxPacket || operation < 1 || operation > 8)
    { return E_INVALIDARG; }
    return FirewallNative::Guard([&]
    {
        auto session = FirewallNative::Get(handle);
        const std::vector<unsigned char> copied(input, input + inputLength);
        FirewallNative::Writer writer;
        // Reserve the bounded maximum before executing a potential persistent write.
        // A successful Add/Remove cannot be obscured by output allocation failure.
        void* allocation = CoTaskMemAlloc(FirewallNative::MaxPacket);
        if (!allocation) { throw FirewallNative::Failure{E_OUTOFMEMORY}; }
        std::unique_ptr<void, decltype(&CoTaskMemFree)> owned(allocation, CoTaskMemFree);
        writer.bytes.reserve(FirewallNative::MaxPacket);
        FirewallNative::Check(session->Call([&](FirewallNative::Policy& policy)
        { policy.Execute(operation, copied, writer); }));
        memcpy(allocation, writer.bytes.data(), writer.bytes.size());
        *outputLength = static_cast<uint32_t>(writer.bytes.size());
        *output = owned.release();
    });
}

extern "C" __declspec(dllexport) HRESULT __cdecl FirewallNativeClose(void* handle) noexcept
{
    return FirewallNative::Guard([&]
    {
        std::shared_ptr<FirewallNative::Session> session;
        {
            std::lock_guard<std::mutex> lock(FirewallNative::registryGate);
            const auto found = FirewallNative::registry.find(reinterpret_cast<uintptr_t>(handle));
            if (found == FirewallNative::registry.end()) { throw FirewallNative::Failure{E_HANDLE}; }
            session = std::move(found->second);
            FirewallNative::registry.erase(found);
        }
    });
}

extern "C" __declspec(dllexport) void __cdecl FirewallNativeFree(void* buffer) noexcept
{
    CoTaskMemFree(buffer);
}
