#pragma once
#include "Utils.h"

BOOLEAN EPTHookFunctionTwoTrampoline(UINT64 targetAddress, UINT64 proxFucntion, UINT64 trampolineAddress, UINT64* originalFunction, UINT64 hookedModuleAddress);
BOOLEAN EPTHookFunctionOneTrampoline(UINT64 targetAddress, UINT64 proxFucntion, UINT64* originalFunction);
BOOLEAN HookSsdtTwoTrampoline(PVOID AddressOfTargetFunction, PVOID ProxFunctionAddress, PVOID* OriginFunction);
BOOLEAN HookSssdtTwoTrampoline(PVOID AddressOfTargetFunction,PVOID ProxFunctionAddress, PVOID* OriginFunction);
BOOLEAN HookSyscalls();

BOOLEAN EptSetPageNoReadWriteAttribute(PVOID VirtualAddress);
BOOLEAN EptPageRecoverAttribute(PVOID VirtualAddress);



VOID    UnHookSsdt(UINT64 AddressOfTargetFunction);
VOID    UnHookSssdt(UINT64 AddressOfTargetFunction);
VOID    UnHookSyscalls();

