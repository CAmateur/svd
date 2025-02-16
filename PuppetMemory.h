#pragma once
#include "GlobalConfig.h"
LONG GetDirectoryTableOffset();

ULONG64 GetEprocessVadOffsets();

ULONG64 GetEprocessPebOffsets();

ULONG64 GetPhyicalAddress(ULONG64 Cr3, ULONG64 VirtualAddress);

NTSTATUS ReadPhysicalAddress(PVOID PhysicalAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesTransferred);

NTSTATUS WritePhysicalAddress(PVOID PhysicalAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesTransferred);

NTSTATUS ReadProcessMemoryByInvlpg(ULONG ProcessPid, PVOID BaseAddress, PVOID Buffer, SIZE_T Size);//�޸��������

NTSTATUS WriteProcessMemoryByInvlpg(ULONG ProcessPid, PVOID BaseAddress, PVOID Buffer, SIZE_T Size);//�޸�������д

NTSTATUS GetProcessModuleByPhyical(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer);

NTSTATUS GetProcessModuleByAttach(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer);

NTSTATUS GetProcessModule(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer, ULONG Flags);//1�޸�������ȡģ�� 2����ȡģ��

NTSTATUS CopyProcessHandle(ULONG ProcessPid, PVOID OutBuffer);//���ܾ��

NTSTATUS QueryVirtualMemory(ULONG ProcessPid, ULONG64 BaseAddress, PVOID Buffer);//��ѯ�ڴ�

NTSTATUS SetProtectVirtualMemory(ULONG ProcessPid, ULONG64 BaseAddress, SIZE_T Size, ULONG Protect);//�ڴ�����