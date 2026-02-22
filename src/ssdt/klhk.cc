#include "klhk.hpp"

#include "Veil.h"
#include "core/core.hpp"
#include "core/utils.hpp"

// Global pointers for klhk.sys variables
namespace {

PETHREAD* g_hvm_thread_object = nullptr;
PLONG g_hvm_run_requests = nullptr;
PRKEVENT g_hvm_notification_event = nullptr;
PRKEVENT g_hvm_sync_event = nullptr;
PNTSTATUS g_hvm_status = nullptr;
void*** g_system_dispatch_array = nullptr;
unsigned int* g_ssdt_service_count = nullptr;
unsigned int* g_shadow_ssdt_service_count = nullptr;
unsigned int* g_provider = nullptr;
bool g_initialized = false;

}  // namespace

bool ssdt::klhk::is_loaded() {
    return core::get_kernel_module_base(L"klhk.sys") != 0;
}

static void* get_system_routine_address(const wchar_t* routine_name) {
    UNICODE_STRING routine_unicode;
    RtlInitUnicodeString(&routine_unicode, routine_name);
    return MmGetSystemRoutineAddress(&routine_unicode);
}

core::VoidResult ssdt::klhk::initialize() {
    if (g_initialized) {
        return core::ok();
    }

    ASSERT_TRUE(is_loaded(), KlhkNotLoaded);

    // Check Necessary routines with MmGetSystemRoutineAddress
    // KeSetTargetProcessorDpcEx
    // KeRegisterProcessorChangeCallback
    // KeDeregisterProcessorChangeCallback
    ASSERT_TRUE(get_system_routine_address(L"KeSetTargetProcessorDpcEx"),
                KlhkInitFailed);
    ASSERT_TRUE(
        get_system_routine_address(L"KeRegisterProcessorChangeCallback"),
        KlhkInitFailed);
    ASSERT_TRUE(
        get_system_routine_address(L"KeDeregisterProcessorChangeCallback"),
        KlhkInitFailed);

    // Find klhk's hvm thread object
    auto presult =
        core::find_pattern_km(L"klhk.sys", ".text", "48392D????????89");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_hvm_thread_object = reinterpret_cast<PETHREAD*>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    presult = core::find_pattern_km(L"klhk.sys", ".text", "83c904890d????????");
    ASSERT_TRUE(presult, KlhkInitFailed);

    int hvm_init_flag = *reinterpret_cast<PLONG>(
        presult + 3 + 6 + *reinterpret_cast<uint32_t*>(presult + 3 + 2));

    log("hvm_init_flag = %x", hvm_init_flag);

    // Find klhk's hvm run counter
    presult =
        core::find_pattern_km(L"klhk.sys", ".text", "F0FF05????????488D0D");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_hvm_run_requests = reinterpret_cast<PLONG>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    // Find klhk's hvm notification event
    presult += 0x7;
    g_hvm_notification_event = reinterpret_cast<PRKEVENT>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    // Find klhk's hvm synchronization event
    presult =
        core::find_pattern_km(L"klhk.sys", ".text", "488D05????????498973");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_hvm_sync_event = reinterpret_cast<PRKEVENT>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    // Find klhk's hvm status
    presult = core::find_pattern_km(L"klhk.sys", ".text", "8B1D????????89");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_hvm_status = reinterpret_cast<PNTSTATUS>(
        presult + *reinterpret_cast<int*>(presult + 0x2) + 0x6);

    // Find klhk's service table (g_system_dispatch_array)
    presult =
        core::find_pattern_km(L"klhk.sys", "_hvmcode", "4C8D0D????????4D");

    ASSERT_TRUE(presult, KlhkInitFailed);
    g_system_dispatch_array = reinterpret_cast<void***>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);
    log("klhk::initialize: g_system_dispatch_array found at %p",
        g_system_dispatch_array);
    /*
    180014000                              void* system_dispatch_array_1 =
g_system_dispatch_array; 180014007                              int32_t rax_14 =
*(uint32_t*)((char*)system_dispatch_array_1 + 0x30);

    */
    log("shadow ssdt count: %u",
        *reinterpret_cast<unsigned int*>(
            reinterpret_cast<char*>(g_system_dispatch_array) + 0x30));

    // Find number of services (SSDT)
    presult = core::find_pattern_km(L"klhk.sys", ".text", "890D????????8BD3");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_ssdt_service_count = reinterpret_cast<unsigned int*>(
        presult + *reinterpret_cast<int*>(presult + 0x2) + 0x6);
    log("klhk::initialize: g_ssdt_service_count found at %p, value = %u",
        g_ssdt_service_count, *g_ssdt_service_count);

    // Find number of services (Shadow SSDT)
    presult = core::find_pattern_km(L"klhk.sys", ".text", "8905????????85C0");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_shadow_ssdt_service_count = reinterpret_cast<unsigned int*>(
        presult + *reinterpret_cast<int*>(presult + 0x2) + 0x6);
    log("klhk::initialize: g_shadow_ssdt_service_count found at %p, value = %u "
        "(This is the value checked for > 0)",
        g_shadow_ssdt_service_count, *g_shadow_ssdt_service_count);

    // Find provider data
    presult = core::find_pattern_km(L"klhk.sys", ".text", "391D????????75");

    ASSERT_TRUE(presult, KlhkInitFailed);

    g_provider = reinterpret_cast<unsigned int*>(
        presult + *reinterpret_cast<int*>(presult + 2) + 0x6);

    g_initialized = true;
    return core::ok();
}

core::Result<NTSTATUS> ssdt::klhk::hvm_init() {
    ASSERT_TRUE(g_initialized, NotInitialized);

    ASSERT_TRUE(g_hvm_thread_object && *g_hvm_thread_object, HvmInitFailed);
    ASSERT_TRUE(g_hvm_run_requests, HvmInitFailed);
    ASSERT_TRUE(g_hvm_notification_event, HvmInitFailed);
    ASSERT_TRUE(g_hvm_sync_event, HvmInitFailed);
    ASSERT_TRUE(g_hvm_status, HvmInitFailed);
    ASSERT_TRUE(g_provider, HvmInitFailed);

    // Set provider to random value
    *g_provider = 4;

    // Hypervisor initialization
    _InterlockedIncrement(g_hvm_run_requests);
    KeResetEvent(g_hvm_notification_event);
    KeSetEvent(g_hvm_sync_event, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(g_hvm_notification_event, Executive, KernelMode,
                          FALSE, nullptr);

    // Return status
    return *g_hvm_status;
}

unsigned int ssdt::klhk::get_ssdt_count() {
    return g_ssdt_service_count ? *g_ssdt_service_count : 0;
}

unsigned int ssdt::klhk::get_shadow_ssdt_count() {
    return g_shadow_ssdt_service_count ? *g_shadow_ssdt_service_count : 0;
}

void*** ssdt::klhk::get_dispatch_array() {
    return g_system_dispatch_array;
}

bool ssdt::klhk::hook_ssdt_routine(unsigned short index, void* dest,
                                   void** original) {
    if (!g_system_dispatch_array || !dest || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    if (!svc_count || index >= svc_count) {
        return false;
    }

    *original = *g_system_dispatch_array[index];
    *g_system_dispatch_array[index] = dest;
    return true;
}

bool ssdt::klhk::unhook_ssdt_routine(unsigned short index, void* original) {
    if (!g_system_dispatch_array || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    if (!svc_count || index >= svc_count ||
        *g_system_dispatch_array[index] == original) {
        return false;
    }

    *g_system_dispatch_array[index] = original;
    return true;
}

bool ssdt::klhk::hook_shadow_ssdt_routine(unsigned short index, void* dest,
                                          void** original) {
    if (!g_system_dispatch_array || !dest || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    const auto svc_count_shadow = get_shadow_ssdt_count();

    if (!svc_count || !svc_count_shadow) {
        return false;
    }

    const auto index_dispatch = (index - 0x1000) + svc_count;
    const auto limit = svc_count + svc_count_shadow;

    if (index_dispatch >= limit) {
        return false;
    }

    *original = *g_system_dispatch_array[index_dispatch];
    *g_system_dispatch_array[index_dispatch] = dest;
    return true;
}

bool ssdt::klhk::unhook_shadow_ssdt_routine(unsigned short index,
                                            void* original) {
    if (!g_system_dispatch_array || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    const auto svc_count_shadow = get_shadow_ssdt_count();

    if (!svc_count || !svc_count_shadow) {
        return false;
    }

    const auto index_dispatch = (index - 0x1000) + svc_count;
    const auto limit = svc_count + svc_count_shadow;

    if (index_dispatch >= limit ||
        *g_system_dispatch_array[index_dispatch] == original) {
        return false;
    }

    *g_system_dispatch_array[index_dispatch] = original;
    return true;
}

void* ssdt::klhk::get_ssdt_routine(unsigned short index) {
    if (!g_system_dispatch_array) {
        return nullptr;
    }

    const auto svc_count = get_ssdt_count();
    return (svc_count && index < svc_count) ? *g_system_dispatch_array[index]
                                            : nullptr;
}

void* ssdt::klhk::get_shadow_ssdt_routine(unsigned short index) {
    if (!g_system_dispatch_array) {
        return nullptr;
    }

    const auto svc_count = get_ssdt_count();
    const auto svc_count_shadow = get_shadow_ssdt_count();

    if (!svc_count || !svc_count_shadow) {
        return nullptr;
    }

    const auto index_dispatch = (index - 0x1000) + svc_count;
    const auto limit = svc_count + svc_count_shadow;

    return (index_dispatch < limit) ? *g_system_dispatch_array[index_dispatch]
                                    : nullptr;
}
