#include "PuppetMemory.h"
#include "Utils.h"
#include <intrin.h>

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

EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process
(
	IN PEPROCESS Process
);
EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb
(
	IN PEPROCESS Process
);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);


LONG GetDirectoryTableOffset()
{
	RTL_OSVERSIONINFOW Version;
	RtlGetVersion(&Version);
	switch (Version.dwBuildNumber)
	{
	case 17763:
		return 0x0278;
		break;
	case 18363:
		return 0x0280;
		break;
	case 19041:
		return 0x0388;
		break;
	case 19042:
		return 0x0388;
		break;
	case 19043:
		return 0x0388;
		break;
	case 19569:
		return 0x0388;
		break;
	case 20180:
		return 0x0388;
		break;
	case 22000:
		return 0x0390;
		break;
	case 22621:
		return 0x0390;
		break;
	}
	return 0x0388;
}

ULONG64 GetEprocessVadOffsets()
{
	ULONG64 BaseAddrrss = 0;

	if (BaseAddrrss) return BaseAddrrss;

	UNICODE_STRING uName;

	RtlInitUnicodeString(&uName, L"PsGetProcessExitStatus");

	PCHAR Function = (PCHAR)MmGetSystemRoutineAddress(&uName);

	BaseAddrrss = *((PULONG)&Function[2]);

	BaseAddrrss += 4;

	return BaseAddrrss;
}

ULONG64 GetEprocessPebOffsets()
{
	ULONG64 BaseAddrrss = 0;

	if (BaseAddrrss) return BaseAddrrss;

	UNICODE_STRING uName;

	RtlInitUnicodeString(&uName, L"PsGetProcessPeb");

	PCHAR Function = (PCHAR)MmGetSystemRoutineAddress(&uName);

	BaseAddrrss = *((PULONG)&Function[3]);

	return BaseAddrrss;
}

ULONG64 GetPhyicalAddress(ULONG64 Cr3, ULONG64 VirtualAddress)
{
	Cr3 &= ~0xf;

	ULONG64 PageOffset = VirtualAddress & ~(~0 << 12);

	ULONG64 PteAddress = ((VirtualAddress >> 12) & (0x1ffll));

	ULONG64 PtAddress = ((VirtualAddress >> 21) & (0x1ffll));

	ULONG64 PdAddress = ((VirtualAddress >> 30) & (0x1ffll));

	ULONG64 PdbAddress = ((VirtualAddress >> 39) & (0x1ffll));

	SIZE_T ReadSize = 0;

	ULONG64 PdpeAddress = 0;

	ReadPhysicalAddress((PVOID)(Cr3 + 8 * PdbAddress), &PdpeAddress, sizeof(PdpeAddress), &ReadSize);

	if (~PdpeAddress & 1)return NULL;

	ULONG64 PdeAddress = 0;

	ReadPhysicalAddress((PVOID)((PdpeAddress & (~0xfull << 8) & 0xfffffffffull) + 8 * PdAddress), &PdeAddress, sizeof(PdeAddress), &ReadSize);

	if (~PdeAddress & 1)return NULL;

	if (PdeAddress & 0x80)return (PdeAddress & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

	ULONG64 NewPteAddress = 0;

	ReadPhysicalAddress((PVOID)((PdeAddress & (~0xfull << 8) & 0xfffffffffull) + 8 * PtAddress), &NewPteAddress, sizeof(NewPteAddress), &ReadSize);

	if (~NewPteAddress & 1)return NULL;

	if (NewPteAddress & 0x80)return (NewPteAddress & (~0xfull << 8) & 0xfffffffffull) + (VirtualAddress & ~(~0ull << 21));

	VirtualAddress = 0;

	ReadPhysicalAddress((PVOID)((NewPteAddress & (~0xfull << 8) & 0xfffffffffull) + 8 * PteAddress), &VirtualAddress, sizeof(VirtualAddress), &ReadSize);

	VirtualAddress &= (~0xfull << 8) & 0xfffffffffull;

	if (!VirtualAddress)return NULL;

	return VirtualAddress + PageOffset;
}

NTSTATUS ReadPhysicalAddress(PVOID PhysicalAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesTransferred)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	static PVOID MapAddress = NULL;

	static KSPIN_LOCK MapLock = NULL;

	if (!PhysicalAddress) return Status;

	if (MapAddress == NULL)MapAddress = MmAllocateMappingAddress(PAGE_SIZE, POOLTAG);

	if (MapAddress != NULL)
	{
		KIRQL pKirql = KeAcquireSpinLockRaiseToDpc(&MapLock);

		ULONG64 PteBase = *(ULONG64*)((PCHAR)MmGetVirtualForPhysical + 0x22);

		PVOID PteAddress = (ULONG64*)(PteBase + (((ULONG64)MapAddress & 0xFFFFFFFFFFFF) >> 12) * 8);

		ULONG64 OldPte = *(ULONG64*)PteAddress;

		*(ULONG64*)PteAddress = ((((ULONG64)PhysicalAddress >> 12) & 0xFFFFFFFFFF) << 12) | 0x103;

		__invlpg(MapAddress);

		memmove(Buffer, (PVOID)((ULONG64)MapAddress + ((ULONG64)PhysicalAddress & 0xFFF)), Size);

		*BytesTransferred = Size;

		*(ULONG64*)PteAddress = OldPte;

		KeReleaseSpinLock(&MapLock, pKirql);

		Status = STATUS_SUCCESS;
	}

	return Status;
}

NTSTATUS WritePhysicalAddress(PVOID PhysicalAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesTransferred)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	static PVOID MapAddress = NULL;

	static KSPIN_LOCK MapLock = NULL;

	if (!PhysicalAddress) return Status;

	if (MapAddress == NULL)MapAddress = MmAllocateMappingAddress(PAGE_SIZE, 'Nin');

	if (MapAddress != NULL)
	{
		KIRQL pKirql = KeAcquireSpinLockRaiseToDpc(&MapLock);

		ULONG64 PteBase = *(ULONG64*)((PCHAR)MmGetVirtualForPhysical + 0x22);

		PVOID PteAddress = (ULONG64*)(PteBase + (((ULONG64)MapAddress & 0xFFFFFFFFFFFF) >> 12) * 8);

		ULONG64 OldPte = *(ULONG64*)PteAddress;

		*(ULONG64*)PteAddress = ((((ULONG64)PhysicalAddress >> 12) & 0xFFFFFFFFFF) << 12) | 0x103;

		__invlpg(MapAddress);

		memmove((PVOID)((ULONG64)MapAddress + ((ULONG64)PhysicalAddress & 0xFFF)), Buffer, Size);

		*BytesTransferred = Size;

		*(ULONG64*)PteAddress = OldPte;

		KeReleaseSpinLock(&MapLock, pKirql);

		Status = STATUS_SUCCESS;
	}

	return Status;
}

NTSTATUS ReadProcessMemoryByInvlpg(ULONG ProcessPid, PVOID BaseAddress, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || (UINT64)BaseAddress <= 0 || (ULONG64)BaseAddress <= 0x10000 || (ULONG64)BaseAddress > 0x7FFFFFFFFFFF || Size <= 0 || (UINT64)Buffer <= 0) return Status;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (eProcess != NULL)
	{
		__try
		{
			ULONG64 TargetAddress = (ULONG64)BaseAddress;

			SIZE_T CurOffset = 0;

			SIZE_T TotalSize = Size;

			PUCHAR Var = (PUCHAR)eProcess;

			ULONG64 CR3 = *(ULONG64*)(Var + 0x28);

			if (!CR3) CR3 = *(ULONG64*)(Var + GetDirectoryTableOffset());

			while (TotalSize)
			{
				ULONG64 CurPhysAddr = GetPhyicalAddress(CR3, TargetAddress + CurOffset);

				if (!CurPhysAddr) break;

				ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);

				SIZE_T BytesRead = 0;

				Status = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((UINT_PTR)Buffer + CurOffset), ReadSize, &BytesRead);

				TotalSize -= BytesRead;

				CurOffset += BytesRead;

				if (!NT_SUCCESS(Status)) break;

				if (BytesRead == 0) break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = STATUS_UNSUCCESSFUL;
		}
	}

	return Status;
}

NTSTATUS WriteProcessMemoryByInvlpg(ULONG ProcessPid, PVOID BaseAddress, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || (UINT64)BaseAddress <= 0 || (ULONG64)BaseAddress <= 0x10000 || (ULONG64)BaseAddress > 0x7FFFFFFFFFFF || Size <= 0 || (UINT64)Buffer <= 0) return Status;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (eProcess != NULL)
	{
		__try
		{
			ULONG64 TargetAddress = (ULONG64)BaseAddress;

			SIZE_T CurOffset = 0;

			SIZE_T TotalSize = Size;

			PUCHAR Var = (PUCHAR)eProcess;

			ULONG64 CR3 = *(ULONG64*)(Var + 0x28);

			if (!CR3) CR3 = *(ULONG64*)(Var + GetDirectoryTableOffset());

			while (TotalSize)
			{
				ULONG64 CurPhysAddr = GetPhyicalAddress(CR3, TargetAddress + CurOffset);

				if (!CurPhysAddr) break;

				ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);

				SIZE_T BytesWritten = 0;

				Status = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)Buffer + CurOffset), WriteSize, &BytesWritten);

				TotalSize -= BytesWritten;

				CurOffset += BytesWritten;

				if (!NT_SUCCESS(Status)) break;

				if (BytesWritten == 0) break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = STATUS_UNSUCCESSFUL;
		}
	}

	return Status;
}

NTSTATUS GetProcessModuleByPhyical(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || (UINT64)ProcessName <= 0 || (UINT64)Buffer <= 0) return Status;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (eProcess == NULL) return Status;

	ANSI_STRING AnsiBuffer = { 0 };

	UNICODE_STRING QueryModuleName = { 0 };

	AnsiBuffer.Buffer = ProcessName;

	AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(ProcessName);

	RtlAnsiStringToUnicodeString(&QueryModuleName, &AnsiBuffer, TRUE);

	__try
	{
		ULONG64 BaseAddress = 0;

		BOOLEAN IsWow64 = (PsGetProcessWow64Process(eProcess) != NULL) ? TRUE : FALSE;

		if (IsWow64)
		{
			PEB32 Peb32 = { 0 };

			if (NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, PsGetProcessWow64Process(eProcess), &Peb32, sizeof(PEB32))))
			{
				PEB_LDR_DATA32 LdrData32 = { 0 };

				if (NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)Peb32.Ldr, &LdrData32, sizeof(PEB_LDR_DATA32))))
				{
					ULONG PListEnrty32 = LdrData32.InMemoryOrderModuleList.Flink;

					ULONG PListEnrtyEnd32 = PListEnrty32;

					LIST_ENTRY32 ListEnrty32 = { 0 };

					if (NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)PListEnrty32, &ListEnrty32, sizeof(LIST_ENTRY32))))
					{
						do
						{
							LDR_DATA_TABLE_ENTRY32 DataTable32 = { 0 };

							if (!NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)(PListEnrty32 - sizeof(LIST_ENTRY32)), (PVOID)&DataTable32, sizeof(LDR_DATA_TABLE_ENTRY32)))) break;

							WCHAR name[200] = L"X";

							if (!NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)DataTable32.BaseDllName.Buffer, &name, DataTable32.BaseDllName.Length))) break;

							UNICODE_STRING ModuleName = { 0 };

							RtlInitUnicodeString(&ModuleName, name);

							if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
							{
								BaseAddress = DataTable32.DllBase;

								Status = STATUS_SUCCESS;

								break;
							}

							PListEnrty32 = ListEnrty32.Flink;

							if (!NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)PListEnrty32, &ListEnrty32, sizeof(LIST_ENTRY32)))) break;

						} while (PListEnrty32 != PListEnrtyEnd32);
					}
				}
			}
		}
		else
		{
			PEB64 Peb64 = { 0 };

			if (NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, PsGetProcessPeb(eProcess), &Peb64, sizeof(PEB64))))
			{
				PEB_LDR_DATA64 LdrData64 = { 0 };

				if (NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)Peb64.Ldr, &LdrData64, sizeof(PEB_LDR_DATA64))))
				{
					ULONG_PTR PListEnrty64 = LdrData64.InMemoryOrderModuleList.Flink;

					ULONG_PTR PListEnrtyEnd64 = PListEnrty64;

					LIST_ENTRY64 ListEnrty64 = { 0 };

					if (NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)PListEnrty64, &ListEnrty64, sizeof(LIST_ENTRY64))))
					{
						do
						{
							LDR_DATA_TABLE_ENTRY64 DataTable64 = { 0 };

							if (!NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)(PListEnrty64 - sizeof(LIST_ENTRY64)), &DataTable64, sizeof(LDR_DATA_TABLE_ENTRY64)))) break;

							WCHAR name[200] = L"X";

							if (!NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)DataTable64.BaseDllName.Buffer, &name, DataTable64.BaseDllName.Length))) break;

							UNICODE_STRING ModuleName = { 0 };

							RtlInitUnicodeString(&ModuleName, name);

							if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
							{
								BaseAddress = DataTable64.DllBase;

								Status = STATUS_SUCCESS;

								break;
							}

							PListEnrty64 = ListEnrty64.Flink;

							if (!NT_SUCCESS(ReadProcessMemoryByInvlpg(ProcessPid, (PVOID)PListEnrty64, &ListEnrty64, sizeof(LIST_ENTRY64)))) break;

						} while (PListEnrty64 != PListEnrtyEnd64);
					}
				}
			}
		}
		if (NT_SUCCESS(Status))
		{
			*(ULONG64*)Buffer = BaseAddress;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_UNSUCCESSFUL;
	}

	RtlFreeUnicodeString(&QueryModuleName);

	return Status;
}

NTSTATUS GetProcessModuleByAttach(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || (UINT64)ProcessName <= 0 || (UINT64)Buffer <= 0) return Status;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (!eProcess) return Status;

	//PVOID Data = RtlAllocateMemory(8);
	PVOID Data = ExAllocatePoolWithTag(NonPagedPool, 8, POOLTAG);

	if (!Data || !MmIsAddressValid(Data)) return Status;

	memset(Data, 0, 8);

	ANSI_STRING AnsiBuffer = { 0 };

	UNICODE_STRING QueryModuleName = { 0 };

	RtlInitAnsiString(&AnsiBuffer, ProcessName);

	RtlAnsiStringToUnicodeString(&QueryModuleName, &AnsiBuffer, TRUE);

	KAPC_STATE ApcState = { 0 };

	KeStackAttachProcess(eProcess, &ApcState);

	__try
	{
		ULONG64 BaseAddress = 0;

		BOOLEAN IsWow64 = (PsGetProcessWow64Process(eProcess) != NULL) ? TRUE : FALSE;

		if (IsWow64)
		{
			PPEB32 pPEB32 = (PPEB32)PsGetProcessWow64Process(eProcess);

			PLIST_ENTRY32 pListEntryStart32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);

			PLIST_ENTRY32 pListEntryEnd32 = pListEntryStart32;

			do {
				PLDR_DATA_TABLE_ENTRY32 pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(pListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

				UNICODE_STRING BaseDllName = { 0 };

				BaseDllName.Buffer = (PWCH)pLdrDataEntry32->BaseDllName.Buffer;

				BaseDllName.Length = pLdrDataEntry32->BaseDllName.Length;

				BaseDllName.MaximumLength = pLdrDataEntry32->BaseDllName.MaximumLength;

				if (RtlEqualUnicodeString(&BaseDllName, &QueryModuleName, TRUE))
				{
					BaseAddress = (ULONG64)pLdrDataEntry32->DllBase;

					Status = STATUS_SUCCESS;

					break;
				}

				pListEntryStart32 = (PLIST_ENTRY32)pListEntryStart32->Flink;

			} while (pListEntryStart32 != pListEntryEnd32);
		}
		else
		{
			PPEB64 pPEB64 = (PPEB64)PsGetProcessPeb(eProcess);

			PLIST_ENTRY64 pListEntryStart64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)pPEB64->Ldr)->InMemoryOrderModuleList.Flink);

			PLIST_ENTRY64 pListEntryEnd64 = pListEntryStart64;
			do {
				PLDR_DATA_TABLE_ENTRY64 pLdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(pListEntryStart64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

				if (RtlEqualUnicodeString(&pLdrDataEntry64->BaseDllName, &QueryModuleName, TRUE))
				{
					BaseAddress = (ULONG64)pLdrDataEntry64->DllBase;

					Status = STATUS_SUCCESS;

					break;
				}

				pListEntryStart64 = (PLIST_ENTRY64)pListEntryStart64->Flink;

			} while (pListEntryStart64 != pListEntryEnd64);
		}

		*(ULONG64*)Data = (ULONG64)BaseAddress;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&ApcState);

	if (NT_SUCCESS(Status)) *(ULONG64*)Buffer = *(ULONG64*)Data;

	RtlFreeUnicodeString(&QueryModuleName);

	//RtlFreeMemoryEx(Data);
	ExFreePool(Data);

	return Status;
}

NTSTATUS GetProcessModule(ULONG ProcessPid, PCHAR ProcessName, PVOID Buffer, ULONG Flags)
{
	if (Flags == 1)
	{
		GetProcessModuleByPhyical(ProcessPid, ProcessName, Buffer);
	}
	else if (Flags == 2)
	{
		GetProcessModuleByAttach(ProcessPid, ProcessName, Buffer);
	}
	return STATUS_SUCCESS;
}

NTSTATUS CopyProcessHandle(ULONG ProcessPid, PVOID OutBuffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || (UINT64)OutBuffer <= 0) return Status;

	HANDLE ProcessHandle = NULL;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (!eProcess) return Status;

	PUCHAR Var = (PUCHAR)eProcess;

	ULONG64 eProcessCr3 = *(ULONG64*)(Var + 0x28);

	if (!eProcessCr3) eProcessCr3 = *(ULONG64*)(Var + GetDirectoryTableOffset());

	if (eProcessCr3 != NULL)
	{
		//ULONG64 PuppetProcess = (ULONG64)RtlAllocateMemory(PAGE_SIZE * 2);
		ULONG64 PuppetProcess = (ULONG64)ExAllocatePoolWithTag(NonPagedPool, 8, POOLTAG);

		if (!PuppetProcess)return Status;

		if (PuppetProcess & 0xfff) PuppetProcess = (PuppetProcess + PAGE_SIZE) & ~0xfff;

		INT ObHeaderCookie = ((UINT8)(((ULONG64)IoGetCurrentProcess() - 0x30) >> 0x08)) ^ (*(UINT8*)((ULONG64)IoGetCurrentProcess() - 0x18)) ^ 7;

		ULONG64 CopyProcessOffset = (ULONG64)IoGetCurrentProcess() & 0xfff;

		RtlCopyMemory((PVOID)PuppetProcess, PAGE_ALIGN(IoGetCurrentProcess()), PAGE_SIZE);

		*(ULONG64*)(PuppetProcess + CopyProcessOffset + 0x28) = eProcessCr3;

		*(ULONG64*)(PuppetProcess + CopyProcessOffset - 0x18) = (UINT8)ObHeaderCookie ^ (UINT8)0x07 ^ (UINT8)((PuppetProcess + CopyProcessOffset - 0x30) >> 0x08);

		*(ULONG64*)(PuppetProcess + CopyProcessOffset + GetEprocessVadOffsets()) = *(ULONG64*)((ULONG64)eProcess + GetEprocessVadOffsets());

		*(ULONG64*)(PuppetProcess + CopyProcessOffset + GetEprocessPebOffsets()) = *(ULONG64*)((ULONG64)eProcess + GetEprocessPebOffsets());

		PEPROCESS pCopyEproecss = (PEPROCESS)(PuppetProcess + CopyProcessOffset);

		if (pCopyEproecss != NULL)
		{
			if (NT_SUCCESS(ObOpenObjectByPointer(pCopyEproecss, 0, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &ProcessHandle)))
			{
				RtlCopyMemory(OutBuffer, &ProcessHandle, sizeof(ProcessHandle));

				Status = STATUS_SUCCESS;
			}
		}
	}

	return Status;
}

NTSTATUS QueryVirtualMemory(ULONG ProcessPid, ULONG64 BaseAddress, PVOID Buffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || (UINT64)BaseAddress <= 0 || (ULONG64)BaseAddress <= 0x10000 || (ULONG64)BaseAddress > 0x7FFFFFFFFFFF || (UINT64)Buffer <= 0) return STATUS_UNSUCCESSFUL;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (eProcess != NULL)
	{
		KAPC_STATE ApcState = { 0 };

		KeStackAttachProcess(eProcess, &ApcState);

		__try
		{
			MEMORY_BASIC_INFORMATION Mbi;

			Status = ZwQueryVirtualMemory(eProcess, (PVOID)BaseAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

			if (NT_SUCCESS(Status))
			{
				RtlCopyMemory(Buffer, &Mbi, sizeof(Mbi));
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = STATUS_UNSUCCESSFUL;
		}

		KeUnstackDetachProcess(&ApcState);
	}

	return Status;
}

NTSTATUS SetProtectVirtualMemory(ULONG ProcessPid, ULONG64 BaseAddress, SIZE_T Size, ULONG Protect)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (ProcessPid <= 0 || BaseAddress <= 0 || (ULONG64)BaseAddress <= 0x10000 || (ULONG64)BaseAddress > 0x7FFFFFFFFFFF || Size <= 0) return STATUS_UNSUCCESSFUL;

	PEPROCESS eProcess = GetProcessById((HANDLE)ProcessPid);

	if (eProcess != NULL)
	{
		KAPC_STATE ApcState = { 0 };

		KeStackAttachProcess(eProcess, &ApcState);

		__try
		{
			ULONG OldProtect = 0;

			Status = ZwProtectVirtualMemory(NtCurrentProcess(), (PVOID*) & BaseAddress, &Size, Protect, &OldProtect);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = STATUS_UNSUCCESSFUL;
		}

		KeUnstackDetachProcess(&ApcState);
	}

	return Status;
}
