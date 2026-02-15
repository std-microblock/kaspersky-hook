#pragma once

#include "Veil.h"
#include "core/expected.hpp"

namespace hide {

namespace globals {
extern const wchar_t* wsProtectedProcesses[];
extern const wchar_t* wsMonitoredProcesses[];
extern const wchar_t* wsBlacklistedProcessess[];
extern const char* szProtectedDrivers[];
}  // namespace globals

namespace tools {
bool GetProcessName(HANDLE PID, PUNICODE_STRING out_name);
bool GetProcessNameByPEPROCESS(PEPROCESS process, PUNICODE_STRING out_name);
void FreeUnicodeString(PUNICODE_STRING str);
void DumpMZ(PUCHAR base);
void SwapEndianness(char* str, size_t size);

bool IsProtectedProcess(HANDLE PID);
bool IsProtectedProcess(PWCH Buffer);
bool IsProtectedProcessEx(PEPROCESS Process);

bool IsMonitoredProcess(HANDLE PID);
bool IsMonitoredProcessEx(PEPROCESS Process);

bool IsBlacklistedProcess(HANDLE PID);
bool IsBlacklistedProcessEx(PEPROCESS Process);
}  // namespace tools

// Hook registration function
core::VoidResult register_hooks();

}  // namespace hide
