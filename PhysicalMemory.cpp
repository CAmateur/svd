#pragma once
#include "PhysicalMemory.h"
#include "Utils.h"
#include "ntimage.h"
typedef unsigned char           uint8_t;
typedef unsigned long long int  uint64_t;

typedef struct HardwarePteX64 {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]
	ULONG64 cache_disable : 1;       //!< [4]
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 36;  //!< [12:47]
	ULONG64 reserved1 : 4;           //!< [48:51]
	ULONG64 software_ws_index : 11;  //!< [52:62]
	ULONG64 no_execute : 1;          //!< [63]
}HardwarePte;


typedef struct _PEB64 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	UCHAR Padding0[4];
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64/*PPEB_LDR_DATA64*/ Ldr;
} PEB64, * PPEB64;
typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;





#define PAGE_OFFSET_SIZE 12
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process
(
	IN PEPROCESS Process
);

EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb
(
	IN PEPROCESS Process
);

KSPIN_LOCK PhysicalMemory::PhysicalLock = { 0 };

ULONG_PTR PhysicalMemory::TranslateLinearAddress(ULONG_PTR directoryTableBase, ULONG_PTR virtualAddress) {
	directoryTableBase &= ~0xf;

	uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
	uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
	uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
	uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	ReadPhysicalAddress((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize, TRUE);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	ReadPhysicalAddress((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize, TRUE);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	ReadPhysicalAddress((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize, TRUE);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize, TRUE);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

PVOID GetPteBase()
{
	static ULONG64 BaseAddr = 0;
	if (BaseAddr) return (PVOID)BaseAddr;

	ULONG64 func = (ULONG64)GetProcAddress((PWCHAR)L"MmGetVirtualForPhysical");
	BaseAddr = *(PUINT64)(func + 0x22);
	return (PVOID)BaseAddr;
}


PVOID GetPfnBase()
{
	static ULONG64 BaseAddr = 0;
	if (BaseAddr) return (PVOID)BaseAddr;

	ULONG64 func = (ULONG64)GetProcAddress((PWCHAR)L"MmGetVirtualForPhysical");
	BaseAddr = *(PUINT64)(func + 0x10);
	return (PVOID)BaseAddr;
}
ULONG64 GetPTE10(ULONG64 addr)
{
	ULONG64 BaseAddr = 0;

	BaseAddr = (ULONG64)GetPteBase();

	ULONG64 offset = (addr >> 9) & 0x7FFFFFFFF8L;
	return offset + BaseAddr;
}

ULONG64 GetPDE10(ULONG64 addr)
{
	ULONG64 BaseAddr = 0;

	BaseAddr = (ULONG64)GetPteBase();

	ULONG64 PTE = GetPTE10(addr);
	return ((PTE >> 9) & 0x7FFFFFFFF8L) + BaseAddr;
}

ULONG64 GetPPE10(ULONG64 addr)
{
	ULONG64 BaseAddr = 0;

	BaseAddr = (ULONG64)GetPteBase();

	ULONG64 PDE = GetPDE10(addr);
	return ((PDE >> 9) & 0x7FFFFFFFF8L) + BaseAddr;
}

ULONG64 GetPML410(ULONG64 addr)
{
	ULONG64 BaseAddr = 0;

	BaseAddr = (ULONG64)GetPteBase();

	ULONG64 PPE = GetPPE10(addr);
	return ((PPE >> 9) & 0x7FFFFFFFF8L) + BaseAddr;
}


ULONG64 GetPTE(ULONG64 addr)
{
	return GetPTE10(addr);
}

ULONG64 GetPDE(ULONG64 addr)
{
	return GetPDE10(addr);

}

ULONG64 GetPPE(ULONG64 addr)
{
	return GetPPE10(addr);
}

ULONG64 GetPML4(ULONG64 addr)
{
	return GetPML410(addr);
}



BOOLEAN SetExecutePage(ULONG64 baseAddr, SIZE_T size)
{
	int pageCount = ((size + 0xFFF) & ~0xFFF) >> 12;
	ULONG64 tempAddr = baseAddr;
	for (int i = 0; i < pageCount; i++)
	{
		HardwarePte* p = (HardwarePte*)GetPDE(tempAddr);
		if (MmIsAddressValid(p) && p->valid)
		{
			p->no_execute = 0;
			p->write = 1;
		}

		p = (HardwarePte*)GetPTE(tempAddr);
		if (MmIsAddressValid(p) && p->valid)
		{
			p->no_execute = 0;
			p->write = 1;

		}

		p = (HardwarePte*)GetPPE(tempAddr);
		if (MmIsAddressValid(p) && p->valid)
		{
			p->no_execute = 0;
			p->write = 1;

		}

		tempAddr += PAGE_SIZE;
	}
	return TRUE;
}

UINT64 ByPassCr3(IN PHYSICAL_ADDRESS PhysicalAddress, PVOID NewAddress)
{
	//第二步找到MMPTE基址
	PVOID PteBase = GetPteBase();
	PVOID PfnBase = GetPfnBase();
	PfnBase = (PVOID)((UINT64)PfnBase & 0xFFFFFFFFFFFFFFF0);
	if (!PteBase && !PfnBase)
	{
		//Log("FindBase is error\n");
		return 0;
	}
	//第三步找到CR3的MMPFN.PteAddress来替换
	UINT64 Index = PhysicalAddress.QuadPart >> 0xc;
	//保存旧的OldPteAddress，可以在映射后恢复，也可以不恢复，目前未发现不恢复会出现问题
	UINT64 OldPteAddress = *(PUINT64)(Index * 0x30 + (UINT64)PfnBase + 8);
	//第4步得到开始申请的非分页内存的PTE，进行替换
	UINT64 MemPte = (((UINT64)NewAddress & 0xFFFFFFFFFFFF) >> 0xc) * 8 + (UINT64)PteBase;
	*(PUINT64)(Index * 0x30 + (UINT64)PfnBase + 8) = MemPte;
	return OldPteAddress;
}
VOID ByUnPassCr3(IN PHYSICAL_ADDRESS PhysicalAddress, UINT64 OldPteAddress)
{
	PVOID PfnBase = GetPfnBase();
	PfnBase = (PVOID)((UINT64)PfnBase & 0xFFFFFFFFFFFFFFF0);
	if (!PfnBase) return;
	//第三步找到CR3的MMPFN.PteAddress来替换
	UINT64 Index = PhysicalAddress.QuadPart >> 0xc;
	*(PUINT64)(Index * 0x30 + (UINT64)PfnBase + 8) = OldPteAddress;
}


NTSTATUS PhysicalMemory::ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead, BOOLEAN isCr3)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS Physical = { 0 };
	Physical.QuadPart = (LONGLONG)TargetAddress;

	KIRQL oldIrql = { 0 };
	PVOID Mem = NULL;
	UINT64 OldPteAddress = 0;
	if (isCr3) {
		Mem = ExAllocatePoolWithTag(NonPagedPool, 0x1000, POOLTAG);
		if (!Mem) return status;

		KeAcquireSpinLock(&PhysicalLock, &oldIrql);
		OldPteAddress = ByPassCr3(Physical, Mem);
	}
	PVOID pmapped_mem = MmMapIoSpace(Physical, Size, MmCached);
	if (pmapped_mem) {
		//KIRQL kirql = KeRaiseIrqlToDpcLevel();
		memcpy(lpBuffer, pmapped_mem, Size);
		//KeLowerIrql(kirql);
		*BytesRead = Size;
		MmUnmapIoSpace(pmapped_mem, Size);
		status = STATUS_SUCCESS;
	}

	if (isCr3) {
		ByUnPassCr3(Physical, OldPteAddress);
		KeReleaseSpinLock(&PhysicalLock, oldIrql);
		ExFreePool(Mem);
	}
	return status;
}


NTSTATUS PhysicalMemory::WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWrite, BOOLEAN isCr3)//写
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS Physical = { 0 };
	Physical.QuadPart = (LONGLONG)TargetAddress;

	KIRQL oldIrql = { 0 };
	PVOID Mem = NULL;
	UINT64 OldPteAddress = 0;
	if (isCr3) {
		Mem = ExAllocatePoolWithTag(NonPagedPool, 0x1000, POOLTAG);
		if (!Mem)
			return status;
		KeAcquireSpinLock(&PhysicalLock, &oldIrql);
		OldPteAddress = ByPassCr3(Physical, Mem);
	}
	PVOID pmapped_mem = MmMapIoSpace(Physical, Size, MmCached);
	if (pmapped_mem) {
		memcpy(pmapped_mem, lpBuffer, Size);
		*BytesWrite = Size;
		MmUnmapIoSpace(pmapped_mem, Size);
		status = STATUS_SUCCESS;
	}
	if (isCr3) {
		ByUnPassCr3(Physical, OldPteAddress);
		KeReleaseSpinLock(&PhysicalLock, oldIrql);
		ExFreePool(Mem);
	}
	return status;
}




//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR PhysicalMemory::GetProcessCr3(PEPROCESS pProcess)
{
	ULONG_PTR process_dirbase = GetCr3(pProcess);
	if (process_dirbase == 0)
	{
		DWORD64 UserDirOffset = GlobalConfig::Instance().UserDirectoryTableBaseOffset;
		ULONG_PTR process_userdirbase = *(PULONG_PTR)((UINT64)pProcess + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}

ULONG_PTR GetKernelDirBase()
{
	PUCHAR process = (PUCHAR)PsGetCurrentProcess();
	ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	return cr3;
}



/**
读进程内存 物理内存
*/
NTSTATUS PhysicalMemory::ReadProcessMemoryPhysicalByMmMapIoSpace(HANDLE pid, ULONG64 Address, PVOID AllocatedBuffer, SIZE_T size)
{
	NTSTATUS NtRet = STATUS_UNSUCCESSFUL;
	if ((INT64)pid <= 0 || Address <= 0 || Address > 0x7fffffffffff || (UINT64)AllocatedBuffer <= 0 || size <= 0) return NtRet;

	PEPROCESS eProcess = GetProcessById(pid);
	if (eProcess == NULL) return NtRet;

	__try
	{
		ULONG_PTR process_dirbase = GetProcessCr3(eProcess);
		if (process_dirbase == 0) return NtRet;

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{
			uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, Address + CurOffset);
			if (!CurPhysAddr) break;

			//读并防止超出页
			ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			NtRet = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead, TRUE);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			//if (!NT_SUCCESS(NtRet)) break;
			if (BytesRead == 0) break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		NtRet = STATUS_UNSUCCESSFUL;
	}
	return NtRet;
}


NTSTATUS PhysicalMemory::WriteProcessMemoryPhysicalByMmMapIoSpace(HANDLE pid, ULONG64 Address, PVOID AllocatedBuffer, SIZE_T size)
{
	NTSTATUS NtRet = STATUS_UNSUCCESSFUL;
	if ((INT64)pid <= 0 || Address <= 0 || Address > 0x7fffffffffff || (UINT64)AllocatedBuffer <= 0 || size <= 0) return NtRet;

	PEPROCESS eProcess = GetProcessById(pid);
	if (eProcess == NULL) return NtRet;

	__try
	{
		ULONG_PTR process_dirbase = GetProcessCr3(eProcess);
		if (process_dirbase == 0) return NtRet;

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{
			uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, Address + CurOffset);
			if (!CurPhysAddr) break;

			ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesWritten = 0;
			NtRet = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten, FALSE);
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			//if (!NT_SUCCESS(NtRet)) break;
			if (BytesWritten == 0) break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		NtRet = STATUS_UNSUCCESSFUL;
	}
	return NtRet;
}



NTSTATUS PhysicalMemory::GetProcessModule_Physical(HANDLE pid, CHAR* QueryName, PVOID outBuffer) {
	NTSTATUS NtRet = STATUS_UNSUCCESSFUL;
	if ((INT64)pid <= 0 || (INT64)QueryName <= 0 || (INT64)outBuffer <= 0) return NtRet;

	PEPROCESS eProcess = GetProcessById(pid);
	if (eProcess == NULL) return NtRet;

	//模块名转换
	ANSI_STRING AnsiBuffer = { 0 };
	UNICODE_STRING QueryModuleName = { 0 };
	AnsiBuffer.Buffer = QueryName;
	AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(QueryName);
	RtlAnsiStringToUnicodeString(&QueryModuleName, &AnsiBuffer, TRUE);//转换
	__try {
		ULONG64 BaseAddress = 0;
		//判断目标进程x86 or x64
		BOOLEAN IsWow64 = (PsGetProcessWow64Process(eProcess) != NULL) ? TRUE : FALSE;
		if (IsWow64) {//x86
			PEB32 Peb32 = { 0 };
			if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)PsGetProcessWow64Process(eProcess), &Peb32, sizeof(PEB32)))) {
				PEB_LDR_DATA32 LdrData32 = { 0 };
				if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Peb32.Ldr, &LdrData32, sizeof(PEB_LDR_DATA32)))) {
					ULONG PListEnrty32 = LdrData32.InMemoryOrderModuleList.Flink;
					ULONG PListEnrtyEnd32 = PListEnrty32;
					LIST_ENTRY32 ListEnrty32 = { 0 };
					if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, PListEnrty32, &ListEnrty32, sizeof(LIST_ENTRY32)))) {
						do {
							LDR_DATA_TABLE_ENTRY32 DataTable32 = { 0 };
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, PListEnrty32 - sizeof(LIST_ENTRY32), &DataTable32, sizeof(LDR_DATA_TABLE_ENTRY32)))) break;
							WCHAR name[200] = L"X";
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, DataTable32.BaseDllName.Buffer, &name, DataTable32.BaseDllName.Length))) break;

							UNICODE_STRING ModuleName = { 0 };
							RtlInitUnicodeString(&ModuleName, name);
							if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
							{
								BaseAddress = DataTable32.DllBase;
								NtRet = STATUS_SUCCESS;
								break;
							}
							PListEnrty32 = ListEnrty32.Flink;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, PListEnrty32, &ListEnrty32, sizeof(LIST_ENTRY32)))) break;
						} while (PListEnrty32 != PListEnrtyEnd32);
					}
				}
			}
		}
		else {//x64
			PEB64 Peb64 = { 0 };
			if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)PsGetProcessPeb(eProcess), &Peb64, sizeof(PEB64)))) {
				PEB_LDR_DATA64 LdrData64 = { 0 };
				if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Peb64.Ldr, &LdrData64, sizeof(PEB_LDR_DATA64)))) {
					ULONG_PTR PListEnrty64 = LdrData64.InMemoryOrderModuleList.Flink;
					ULONG_PTR PListEnrtyEnd64 = PListEnrty64;
					LIST_ENTRY64 ListEnrty64 = { 0 };
					if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, PListEnrty64, &ListEnrty64, sizeof(LIST_ENTRY64)))) {
						do {
							LDR_DATA_TABLE_ENTRY64 DataTable64 = { 0 };
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, PListEnrty64 - sizeof(LIST_ENTRY64), &DataTable64, sizeof(LDR_DATA_TABLE_ENTRY64)))) break;
							WCHAR name[200] = L"X";
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)DataTable64.BaseDllName.Buffer, &name, DataTable64.BaseDllName.Length))) break;

							UNICODE_STRING ModuleName = { 0 };
							RtlInitUnicodeString(&ModuleName, name);
							if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
							{
								BaseAddress = DataTable64.DllBase;
								NtRet = STATUS_SUCCESS;
								break;
							}
							PListEnrty64 = ListEnrty64.Flink;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, PListEnrty64, &ListEnrty64, sizeof(LIST_ENTRY64)))) break;
						} while (PListEnrty64 != PListEnrtyEnd64);
					}
				}
			}
		}
		if (NT_SUCCESS(NtRet)) {
			RtlCopyMemory(outBuffer, &BaseAddress, 8);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		NtRet = STATUS_UNSUCCESSFUL;
	}

	RtlFreeUnicodeString(&QueryModuleName);// 释放内存
	return NtRet;
}


NTSTATUS PhysicalMemory::GetProcessModuleFunc_Physical(HANDLE pid, ULONG64 Module, CHAR* QueryName, PVOID outBuffer) {
	NTSTATUS NtRet = STATUS_UNSUCCESSFUL;
	if ((INT64)pid <= 0 || (INT64)QueryName <= 0 || Module <= 0 || (INT64)outBuffer <= 0) return NtRet;

	PEPROCESS eProcess = GetProcessById(pid);
	if (eProcess == NULL) return NtRet;

	//模块名转换
	ANSI_STRING AnsiBuffer = { 0 };
	UNICODE_STRING QueryFuncName = { 0 };
	AnsiBuffer.Buffer = QueryName;
	AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(QueryName);
	RtlAnsiStringToUnicodeString(&QueryFuncName, &AnsiBuffer, TRUE);//转换

	__try
	{
		ULONG64 FuncAddr = 0;
		//判断目标进程x86 or x64
		BOOLEAN IsWow64 = (PsGetProcessWow64Process(eProcess) != NULL) ? TRUE : FALSE;
		if (IsWow64) {//x86
			IMAGE_DOS_HEADER dosheader = { 0 };
			if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module, &dosheader, sizeof(IMAGE_DOS_HEADER)))) {
				IMAGE_OPTIONAL_HEADER32 opthdr = { 0 };
				if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module + dosheader.e_lfanew + 24, &opthdr, sizeof(IMAGE_OPTIONAL_HEADER32)))) {
					IMAGE_EXPORT_DIRECTORY exports = { 0 };
					if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module + opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &exports, sizeof(IMAGE_EXPORT_DIRECTORY)))) {
						PULONG pAddressOfFunctions = (ULONG*)(Module + exports.AddressOfFunctions);
						PULONG pAddressOfNames = (ULONG*)(Module + exports.AddressOfNames);
						PUSHORT pAddressOfNameOrdinals = (USHORT*)(Module + exports.AddressOfNameOrdinals);

						//对比函数名 
						for (ULONG i = 0; i < exports.NumberOfNames; i++)
						{
							USHORT index = 0;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)(&pAddressOfNameOrdinals[i]), &index, sizeof(USHORT)))) break;
							ULONG offset = 0;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)(&pAddressOfFunctions[index]), &offset, sizeof(ULONG)))) break;
							ULONG NameOffser = 0;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)(&pAddressOfNames[i]), &NameOffser, sizeof(ULONG)))) break;
							CHAR Name[50] = "X";
							for (UINT64 j = 0; j < 50; j++) {
								if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module + NameOffser + j, &Name[j], 1))) break;
							}

							ANSI_STRING AnsiStringSec = { 0 };
							RtlInitString(&AnsiStringSec, Name);
							UNICODE_STRING FuncName = { 0 };
							RtlAnsiStringToUnicodeString(&FuncName, &AnsiStringSec, TRUE);
							if (RtlEqualUnicodeString(&QueryFuncName, &FuncName, TRUE))
							{
								RtlFreeUnicodeString(&FuncName);// 释放内存
								FuncAddr = Module + offset;
								NtRet = STATUS_SUCCESS;
								break;
							}
							RtlFreeUnicodeString(&FuncName);// 释放内存
						}
					}
				}
			}
		}
		else {//x64
			IMAGE_DOS_HEADER dosheader = { 0 };
			if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module, &dosheader, sizeof(IMAGE_DOS_HEADER)))) {
				IMAGE_OPTIONAL_HEADER64 opthdr = { 0 };
				if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module + dosheader.e_lfanew + 24, &opthdr, sizeof(IMAGE_OPTIONAL_HEADER64)))) {
					IMAGE_EXPORT_DIRECTORY exports = { 0 };
					if (NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module + opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &exports, sizeof(IMAGE_EXPORT_DIRECTORY)))) {
						PULONG pAddressOfFunctions = (ULONG*)(Module + exports.AddressOfFunctions);
						PULONG pAddressOfNames = (ULONG*)(Module + exports.AddressOfNames);
						PUSHORT pAddressOfNameOrdinals = (USHORT*)(Module + exports.AddressOfNameOrdinals);

						//对比函数名 
						for (ULONG i = 0; i < exports.NumberOfNames; i++)
						{
							USHORT index = 0;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)(&pAddressOfNameOrdinals[i]), &index, sizeof(USHORT)))) break;
							ULONG offset = 0;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)(&pAddressOfFunctions[index]), &offset, sizeof(ULONG)))) break;
							ULONG NameOffser = 0;
							if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, (ULONG_PTR)(&pAddressOfNames[i]), &NameOffser, sizeof(ULONG)))) break;
							CHAR Name[50] = "X";
							for (UINT64 j = 0; j < 50; j++) {
								if (!NT_SUCCESS(ReadProcessMemoryPhysicalByMmMapIoSpace(pid, Module + NameOffser + j, &Name[j], 1))) break;
							}

							ANSI_STRING AnsiStringSec = { 0 };
							RtlInitString(&AnsiStringSec, Name);
							UNICODE_STRING FuncName = { 0 };
							RtlAnsiStringToUnicodeString(&FuncName, &AnsiStringSec, TRUE);
							if (RtlEqualUnicodeString(&QueryFuncName, &FuncName, TRUE))
							{
								RtlFreeUnicodeString(&FuncName);// 释放内存
								FuncAddr = Module + offset;
								NtRet = STATUS_SUCCESS;
								break;
							}
							RtlFreeUnicodeString(&FuncName);// 释放内存
						}
					}
				}
			}
		}

		if (NT_SUCCESS(NtRet)) {
			RtlCopyMemory(outBuffer, &FuncAddr, 8);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		NtRet = STATUS_UNSUCCESSFUL;
	}
	RtlFreeUnicodeString(&QueryFuncName);// 释放内存
	return NtRet;
}







#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) ((SIZE_T)_VAR_ & 0xFFFULL)

#define ADDRMASK_EPT_PML1_INDEX(_VAR_) (((SIZE_T)_VAR_ & 0x1FF000ULL) >> 12)

#define ADDRMASK_EPT_PML2_INDEX(_VAR_) (((SIZE_T)_VAR_ & 0x3FE00000ULL) >> 21)

#define ADDRMASK_EPT_PML3_INDEX(_VAR_) (((SIZE_T)_VAR_ & 0x7FC0000000ULL) >> 30)

#define ADDRMASK_EPT_PML4_INDEX(_VAR_) (((SIZE_T)_VAR_ & 0xFF8000000000ULL) >> 39)



UINT64 PhysicalMemory2::UserDirectoryTableBase = NULL;
UINT64 PhysicalMemory2::DirectoryTableBase = NULL;
UINT64 PhysicalMemory2::PhysicalLock = NULL;
UINT64 PhysicalMemory2::ActiveProcessLinks = NULL;
UINT64 PhysicalMemory2::PteBase = NULL;
UINT64 PhysicalMemory2::PfnBase = NULL;

VOID PhysicalMemory2::Initilize()
{
	KeInitializeSpinLock(&PhysicalLock);
	UserDirectoryTableBase = GlobalConfig::Instance().UserDirectoryTableBaseOffset;
	DirectoryTableBase = GlobalConfig::Instance().DirectoryTableBaseOffset;
	ActiveProcessLinks = GlobalConfig::Instance().ActiveProcessLinksOffset;
	PteBase = GetPteBase();
	PfnBase = GetPfnBase();
}

VOID PhysicalMemory2::Destory()
{

}

UINT64 PhysicalMemory2::GetProcessCr3(PEPROCESS PProcess)
{
	UINT64 Cr3 = NULL;
	Cr3 = *(UINT64*)((UINT64)PProcess + DirectoryTableBase);

	if (!Cr3)
		Cr3 = *(UINT64*)((UINT64)PProcess + UserDirectoryTableBase);

	return Cr3;
}

UINT64 PhysicalMemory2::TranslateLinearAddress(UINT64 Cr3, UINT64 TargetVirtualAddress)
{
	Cr3 &= ~0xF;
	UINT64 PageOffset = ADDRMASK_EPT_PML1_OFFSET(TargetVirtualAddress);
	UINT64 PteIndex = ADDRMASK_EPT_PML1_INDEX(TargetVirtualAddress);
	UINT64 PtIndex = ADDRMASK_EPT_PML2_INDEX(TargetVirtualAddress);
	UINT64 PdIndex = ADDRMASK_EPT_PML3_INDEX(TargetVirtualAddress);
	UINT64 PdpIndex = ADDRMASK_EPT_PML4_INDEX(TargetVirtualAddress);

	SIZE_T Readsize = 0;
	UINT64 Pdpe = 0;
	ReadPhysicalAddress((PVOID)(Cr3 + 8 * PdpIndex), &Pdpe, sizeof(Pdpe), &Readsize, TRUE);
	if (~Pdpe & 1)
		return 0;

	UINT64 Pde = 0;
	ReadPhysicalAddress((PVOID)((Pdpe & PMASK) + 8 * PdIndex), &Pde, sizeof(Pde), &Readsize, TRUE);
	if (~Pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (Pde & 0x80)
		return (Pde & (~0ull << 42 >> 12)) + (TargetVirtualAddress & ~(~0ull << 30));

	UINT64 Pte = 0;
	ReadPhysicalAddress((PVOID)((Pde & PMASK) + 8 * PtIndex), &Pte, sizeof(Pte), &Readsize, TRUE);
	if (~Pte & 1)
		return 0;

	/* 2MB large page */
	if (Pte & 0x80)
		return (Pte & PMASK) + (TargetVirtualAddress & ~(~0ull << 21));

	TargetVirtualAddress = 0;
	ReadPhysicalAddress((PVOID)((Pte & PMASK) + 8 * PteIndex), &TargetVirtualAddress, sizeof(TargetVirtualAddress), &Readsize, TRUE);
	TargetVirtualAddress &= PMASK;

	if (!TargetVirtualAddress)
		return 0;

	return TargetVirtualAddress + PageOffset;
}


NTSTATUS PhysicalMemory2::ReadPhysicalAddress(PVOID TargetAddress, PVOID PBuffer, SIZE_T Size, SIZE_T* BytesRead, BOOLEAN IsCr3)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS PhysicalAddress = { 0 };
	PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;

	KIRQL OldIrql = { 0 };
	PVOID PMem = NULL;
	UINT64 OldPteAddress = 0;

	if (IsCr3)
	{
		PMem = ExAllocatePoolWithTag(NonPagedPool, 0x1000, POOLTAG);
		if (!PMem) return Status;

		KeAcquireSpinLock(&PhysicalLock, &OldIrql);
		OldPteAddress = ByPassCr3(PhysicalAddress, PMem);
	}


	PVOID PMap = MmMapIoSpace(PhysicalAddress, Size, MmCached);
	if (PMap)
	{
		memcpy(PBuffer, PMap, Size);
		*BytesRead = Size;
		MmUnmapIoSpace(PMap, Size);
		Status = STATUS_SUCCESS;
	}


	if (IsCr3)
	{
		ByUnPassCr3(PhysicalAddress, OldPteAddress);
		KeReleaseSpinLock(&PhysicalLock, OldIrql);
		ExFreePool(PMem);
	}
	return Status;
}

NTSTATUS PhysicalMemory2::ReadProcessMemoryPhysicalByMmMapIoSpace(HANDLE Pid, UINT64 TargetVirtualAddress, PVOID PBuffer, SIZE_T Size)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (!Pid || !TargetVirtualAddress || TargetVirtualAddress > 0x7fffffffffff || !PBuffer || Size <= 0)
		return Status;

	PEPROCESS PEProcess = GetProcessById(Pid);
	if (!PEProcess)
		return Status;

	__try
	{
		UINT64 Cr3 = GetProcessCr3(PEProcess);
		if (!Cr3)
			return Status;

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = Size;
		while (TotalSize)
		{
			UINT64 CurPhysAddr = TranslateLinearAddress(Cr3, TargetVirtualAddress + CurOffset);
			if (!CurPhysAddr) break;

			//读并防止超出页
			UINT64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			Status = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((UINT64)PBuffer + CurOffset), ReadSize, &BytesRead, TRUE);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			//if (!NT_SUCCESS(NtRet)) break;
			if (BytesRead == 0) break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_UNSUCCESSFUL;
	}
	return Status;
}

PEPROCESS PhysicalMemory2::GetProcessById(HANDLE ProcessId)
{
	if ((UINT64)ProcessId < 4)
		return NULL;

	PEPROCESS PProcess = NULL;
	PLIST_ENTRY ListEntry = (LIST_ENTRY*)((UINT64)PsInitialSystemProcess + ActiveProcessLinks);
	PLIST_ENTRY ListEnd = ListEntry;
	do {
		PEPROCESS TempPProcess = (PEPROCESS)((UINT64)ListEntry - ActiveProcessLinks);
		if (PsGetProcessExitStatus(TempPProcess) == 0x103) {
			if (ProcessId == PsGetProcessId(TempPProcess)) {
				PProcess = TempPProcess;
				break;
			}
		}
		ListEntry = ListEntry->Blink;
	} while (ListEntry != ListEnd);

	return PProcess;
}

UINT64 PhysicalMemory2::ByPassCr3(PHYSICAL_ADDRESS PhysicalAddress, PVOID NewAddress)
{
	//第二步找到MMPTE基址
	PfnBase = PfnBase & 0xFFFFFFFFFFFFFFF0;

	if (!PteBase && !PfnBase)
		return 0;

	//第三步找到CR3的MMPFN.PteAddress来替换
	UINT64 Index = PhysicalAddress.QuadPart >> 0xC;

	//保存旧的OldPteAddress，可以在映射后恢复，也可以不恢复，目前未发现不恢复会出现问题
	UINT64 OldPteAddress = *(PUINT64)(Index * 0x30 + (UINT64)PfnBase + 8);

	//第4步得到开始申请的非分页内存的PTE，进行替换
	UINT64 MemPte = (((UINT64)NewAddress & 0xFFFFFFFFFFFF) >> 0xC) * 8 + (UINT64)PteBase;
	*(PUINT64)(Index * 0x30 + (UINT64)PfnBase + 8) = MemPte;

	return OldPteAddress;
}

VOID PhysicalMemory2::ByUnPassCr3(PHYSICAL_ADDRESS PhysicalAddress, UINT64 OldPteAddress)
{

	PfnBase = PfnBase & 0xFFFFFFFFFFFFFFF0;

	if (!PfnBase)
		return;

	//第三步找到CR3的MMPFN.PteAddress来替换
	UINT64 Index = PhysicalAddress.QuadPart >> 0xC;
	*(PUINT64)(Index * 0x30 + (UINT64)PfnBase + 8) = OldPteAddress;
}

UINT64 PhysicalMemory2::GetPteBase()
{
	UINT64 BaseAddr = 0;
	UINT64 func = (UINT64)GetProcAddress((PWCHAR)L"MmGetVirtualForPhysical");
	BaseAddr = *(PUINT64)(func + 0x22);
	return BaseAddr;
}


UINT64 PhysicalMemory2::GetPfnBase()
{
	UINT64 BaseAddr = 0;
	ULONG64 func = (ULONG64)GetProcAddress((PWCHAR)L"MmGetVirtualForPhysical");
	BaseAddr = *(PUINT64)(func + 0x10);
	return BaseAddr;
}