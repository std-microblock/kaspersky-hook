#include "debugger_peb_hide.hpp"

#include <ntifs.h>

#include "core/core.hpp"
#include "process_manager.hpp"
#include "ssdt/ssdt_hook.hpp"

namespace {

// Set or clear the BeingDebugged flag in the target process PEB
BOOLEAN SetPebDeuggerFlag(PEPROCESS TargetProcess, BOOLEAN Value) {
    PPEB Peb = PsGetProcessPeb(TargetProcess);
    PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

    if (Peb32 != NULL) {
        KAPC_STATE State;
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
        __try {
            Peb32->BeingDebugged = Value;
            Peb->BeingDebugged = Value;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            log("SetPebDeuggerFlag: Access Violation");
            KeUnstackDetachProcess(&State);
            return FALSE;
        }
        KeUnstackDetachProcess(&State);
    } else if (Peb != NULL) {
        KAPC_STATE State;
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
        __try {
            Peb->BeingDebugged = Value;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            log("SetPebDeuggerFlag: Access Violation");
            KeUnstackDetachProcess(&State);
            return FALSE;
        }
        KeUnstackDetachProcess(&State);
    } else {
        log("SetPebDeuggerFlag: Both pebs doesn't exist");
        return FALSE;
    }

    return TRUE;
}

// Clear debug-related flags in NtGlobalFlag (0x70 = heap debug flags)
BOOLEAN ClearPebNtGlobalFlag(PEPROCESS TargetProcess) {
    PPEB Peb = PsGetProcessPeb(TargetProcess);
    PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

    if (Peb32 != NULL) {
        KAPC_STATE State;
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
        __try {
            Peb32->NtGlobalFlag &= ~0x70;
            Peb->NtGlobalFlag &= ~0x70;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            log("ClearPebNtGlobalFlag: Access Violation");
            KeUnstackDetachProcess(&State);
            return FALSE;
        }
        KeUnstackDetachProcess(&State);
    } else if (Peb != NULL) {
        KAPC_STATE State;
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
        __try {
            Peb->NtGlobalFlag &= ~0x70;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            log("ClearPebNtGlobalFlag: Access Violation");
            KeUnstackDetachProcess(&State);
            return FALSE;
        }
        KeUnstackDetachProcess(&State);
    } else {
        log("ClearPebNtGlobalFlag: Both pebs doesn't exist");
        return FALSE;
    }

    return TRUE;
}

}  // anonymous namespace

namespace debugger_peb_hide {

core::VoidResult register_hooks() {
    auto& mgr = ssdt::SsdtHookManager::instance();

    // NtDebugActiveProcess
    {
        auto res = mgr.hook_by_syscall_name("NtDebugActiveProcess");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ProcessHandle, HANDLE DebugObjectHandle) -> NTSTATUS {
            auto original = hook.get_original<NtDebugActiveProcess>();

            // Execute original syscall first (attach debugger)
            NTSTATUS status = original(ProcessHandle, DebugObjectHandle);

            // If attach succeeded, clear PEB debugging flags
            if (NT_SUCCESS(status)) {
                PEPROCESS TargetProcess = nullptr;
                NTSTATUS ob_status = ObReferenceObjectByHandle(
                    ProcessHandle, 0, *PsProcessType, KernelMode,
                    reinterpret_cast<PVOID*>(&TargetProcess), nullptr);

                if (NT_SUCCESS(ob_status) && TargetProcess) {
                    // Clear BeingDebugged flag
                    SetPebDeuggerFlag(TargetProcess, FALSE);

                    // Clear NtGlobalFlag debug bits
                    ClearPebNtGlobalFlag(TargetProcess);

                    log("NtDebugActiveProcess: Cleared PEB flags for process %p",
                        PsGetProcessId(TargetProcess));

                    ObDereferenceObject(TargetProcess);
                }
            }

            return status;
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    log("debugger_peb_hide: hooks registered successfully");
    return core::ok();
}

}  // namespace debugger_peb_hide

