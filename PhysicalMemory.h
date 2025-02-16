#pragma once
#include "GlobalConfig.h"



class PhysicalMemory
{
public:

	static ULONG_PTR GetProcessCr3(PEPROCESS pProcess);
	static ULONG_PTR TranslateLinearAddress(ULONG_PTR directoryTableBase, ULONG_PTR virtualAddress);
	static NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead, BOOLEAN isCr3);
	static NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten, BOOLEAN isCr3);

	static NTSTATUS ReadProcessMemoryPhysicalByMmMapIoSpace(HANDLE pid, ULONG64 Address, PVOID AllocatedBuffer, SIZE_T size);
	static NTSTATUS WriteProcessMemoryPhysicalByMmMapIoSpace(HANDLE pid, ULONG64 Address, PVOID AllocatedBuffer, SIZE_T size);

	static NTSTATUS GetProcessModule_Physical(HANDLE pid, CHAR* QueryName, PVOID outBuffer);
	static NTSTATUS GetProcessModuleFunc_Physical(HANDLE pid, ULONG64 Module, CHAR* QueryName, PVOID outBuffer);

private:
	static KSPIN_LOCK PhysicalLock;

};

typedef struct _VMX_PTE
{
	union
	{
		struct {
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Type : 3;
			UINT64 IgnorePat : 1;
			UINT64 Reserved1 : 1;
			UINT64 Accessed : 1;
			UINT64 Dirty : 1;
			UINT64 UserModeExecute : 1;
			UINT64 Reserved2 : 1;
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved3 : 15;
			UINT64 SuppressVe : 1;
		};
		UINT64 AsUlonglong;
	};
} VMX_PTE, * PVMX_PTE;



class PhysicalMemory2
{
public:
	static VOID Initilize();
	static VOID Destory();
	static UINT64 GetProcessCr3(PEPROCESS pProcess);
	static UINT64 TranslateLinearAddress(UINT64 Cr3, UINT64 TargetVirtualAddress);
	static NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID PBuffer, SIZE_T Size, SIZE_T* BytesRead, BOOLEAN IsCr3);
	static NTSTATUS ReadProcessMemoryPhysicalByMmMapIoSpace(HANDLE Pid, UINT64 TargetVirtualAddress, PVOID PBuffer, SIZE_T Size);
	static PEPROCESS GetProcessById(HANDLE ProcessId);
	static UINT64 ByPassCr3(PHYSICAL_ADDRESS PhysicalAddress, PVOID NewAddress);
	static VOID ByUnPassCr3(PHYSICAL_ADDRESS PhysicalAddress, UINT64 OldPteAddress);
	static UINT64 GetPteBase();
	static UINT64 GetPfnBase();

private:
	static KSPIN_LOCK PhysicalLock;
	static UINT64 UserDirectoryTableBase;
	static UINT64 DirectoryTableBase;
	static UINT64 ActiveProcessLinks;
	static UINT64 PteBase;
	static UINT64 PfnBase;
};



