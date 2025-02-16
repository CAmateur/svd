#pragma once
#include "GlobalConfig.h"
LONG GetDirectoryTableOffset();

ULONG64 GetEprocessVadOffsets();

ULONG64 GetEprocessPebOffsets();

ULONG64 GetPhyicalAddress(ULONG64 Cr3, ULONG64 VirtualAddress);

NTSTATUS ReadPhysicalAddress(PVOID PhysicalAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesTransferred);

NTSTATUS WritePhysicalAddress(PVOID PhysicalAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesTransferred);

NTSTATUS ReadProcessMemoryByInvlpg(ULONG ProcessPid, PVOID BaseAddress, PVOID Buffer, SIZE_T Size);//无附加物理读

NTSTATUS WriteProcessMemoryByInvlpg(ULONG ProcessPid, PVOID BaseAddress, PVOID Buffer, SIZE_T Size);//无附加物理写

NTSTATUS GetProcessModuleByPhyical(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer);

NTSTATUS GetProcessModuleByAttach(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer);

NTSTATUS GetProcessModule(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer, ULONG Flags);//1无附加物理取模块 2附加取模块

NTSTATUS CopyProcessHandle(ULONG ProcessPid, PVOID OutBuffer);//傀儡句柄

NTSTATUS QueryVirtualMemory(ULONG ProcessPid, ULONG64 BaseAddress, PVOID Buffer);//查询内存

NTSTATUS SetProtectVirtualMemory(ULONG ProcessPid, ULONG64 BaseAddress, SIZE_T Size, ULONG Protect);//内存属性