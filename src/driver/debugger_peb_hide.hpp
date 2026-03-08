#pragma once

#include "core/expected.hpp"

namespace debugger_peb_hide {

// Register PEB-related anti-debug hooks.
// Hooks NtDebugActiveProcess to automatically clear PEB debugging flags
// after a debugger attaches to a target process.
//
// When NtDebugActiveProcess is called:
//   1. Execute the original syscall (attach debugger)
//   2. Clear PEB.BeingDebugged flag
//   3. Clear PEB.NtGlobalFlag debug bits (0x70)
//
core::VoidResult register_hooks();

}  // namespace debugger_peb_hide
