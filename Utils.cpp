#include "Utils.h"
#include <stdarg.h>
#include <stdio.h>
#include <ntimage.h>

EXTERN_C NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process
(
	IN PEPROCESS Process
);

EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb
(
	IN PEPROCESS Process
);

EXTERN_C NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID* FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);



PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName)
{
	KAPC_STATE State;
	PVOID FunctionAddress = 0;
	if (TargetProcess != NULL)
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	do
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (UINT64)ModuleBase);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((UINT64)ModuleBase + ImageDataDirectory.VirtualAddress);
		ULONG* Address = (ULONG*)((UINT64)ModuleBase + ExportDirectory->AddressOfFunctions);
		ULONG* Name = (ULONG*)((UINT64)ModuleBase + ExportDirectory->AddressOfNames);
		USHORT* Ordinal = (USHORT*)((UINT64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

		STRING TargetExportedFunctionName;
		RtlInitString(&TargetExportedFunctionName, ExportedFunctionName);

		for (size_t i = 0; ExportDirectory->NumberOfFunctions; i++)
		{
			STRING CurrentExportedFunctionName;
			RtlInitString(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

			if (RtlCompareString(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
			{
				FunctionAddress = (PVOID)((UINT64)ModuleBase + Address[Ordinal[i]]);
				break;
			}
		}

	} while (0);

	if (TargetProcess != NULL)
		KeUnstackDetachProcess(&State);

	return FunctionAddress;
}

PVOID GetUserModeModule(PEPROCESS TargetProcess, CONST WCHAR* ModuleName, BOOLEAN IsWow64)
{
	if (TargetProcess == NULL)
		return NULL;

	KAPC_STATE State;
	PVOID Address = NULL;
	KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	UNICODE_STRING TargetModuleName;
	RtlCreateUnicodeString(&TargetModuleName, ModuleName);

	__try
	{
		do
		{
			if (IsWow64 == TRUE)
			{
				PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

				for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
					ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
					ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY32 Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

					UNICODE_STRING CurrentModuleName;
					RtlCreateUnicodeString(&CurrentModuleName, (PWCH)Entry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&CurrentModuleName, &TargetModuleName, TRUE) == 0)
					{
						Address = (PVOID)Entry->DllBase;
						break;
					}
				}
			}

			else
			{
				PPEB Peb = PsGetProcessPeb(TargetProcess);

				for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
					ListEntry != &Peb->Ldr->InLoadOrderModuleList;
					ListEntry = ListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

					UNICODE_STRING CurrentModuleName;
					RtlCreateUnicodeString(&CurrentModuleName, Entry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&CurrentModuleName, &TargetModuleName, TRUE) == 0)
					{
						Address = Entry->DllBase;
						break;
					}
				}
			}

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	KeUnstackDetachProcess(&State);
	return Address;
}




PEPROCESS PidToProcess(HANDLE Pid)
{
	PEPROCESS Process = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Status = PsLookupProcessByProcessId(Pid, &Process);
	if (NT_SUCCESS(Status))
		ObDereferenceObject(Process);
	return Process;
}



PEPROCESS GetCsrssProcess()
{
	PEPROCESS Process = 0;

	// Sometimes it doesn't return csrss process at the first try which is strange because it must exist
	do
	{
		Process = GetProcessByName(L"winlogon.exe");
	} while (Process == 0);

	return Process;
}

BOOLEAN RtlStringContains(PSTRING Str, PSTRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length);
	STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= 1)
	{
		if (RtlEqualString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

BOOLEAN GetProcessInfo(CONST CHAR* Name, UINT64* ImageSize, PVOID* ImageBase)
{
	ULONG Bytes;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Bytes);
	PSYSTEM_MODULE_INFORMATION Mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Bytes, POOLTAG);
	if (Mods == NULL)
		return FALSE;

	RtlSecureZeroMemory(Mods, Bytes);

	Status = ZwQuerySystemInformation(SystemModuleInformation, Mods, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(Mods, POOLTAG);
		return FALSE;
	}

	STRING TargetProcessName;
	RtlInitString(&TargetProcessName, Name);

	for (ULONG i = 0; i < Mods->ModulesCount; i++)
	{
		STRING CurrentModuleName;
		RtlInitString(&CurrentModuleName, (PCSZ)Mods->Modules[i].FullPathName);

		if (RtlStringContains(&CurrentModuleName, &TargetProcessName, TRUE) != NULL)
		{
			if (Mods->Modules[i].ImageSize != NULL)
			{
				*ImageSize = Mods->Modules[i].ImageSize;
				*ImageBase = Mods->Modules[i].ImageBase;
				ExFreePoolWithTag(Mods, POOLTAG);
				return TRUE;
			}
		}
	}

	ExFreePoolWithTag(Mods, POOLTAG);
	return FALSE;
}

BOOLEAN GetSectionData(CONST CHAR* ImageName, CONST CHAR* SectionName, UINT64* SectionSize, PVOID* SectionBaseAddress)
{
	UINT64 ImageSize = 0;
	PVOID ImageBase = 0;

	if (GetProcessInfo(ImageName, &ImageSize, &ImageBase) == FALSE)
		return FALSE;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (UINT64)ImageBase);
	ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

	STRING TargetSectionName;
	RtlInitString(&TargetSectionName, SectionName);

	for (ULONG i = 0; i < NumSections; i++)
	{
		STRING CurrentSectionName;
		RtlInitString(&CurrentSectionName, (PCSZ)Section->Name);
		if (CurrentSectionName.Length > 8)
			CurrentSectionName.Length = 8;

		if (RtlCompareString(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
		{
			*SectionSize = Section->Misc.VirtualSize;
			*SectionBaseAddress = (PVOID)((UINT64)ImageBase + (UINT64)Section->VirtualAddress);

			return TRUE;
		}
		Section++;
	}

	return FALSE;
}

BOOLEAN FindCodeCaves()
{
	KAPC_STATE State;
	UINT64     KernelTextSectionSize = 0;
	UINT64     Win32kTextSectionSize = 0;
	UINT64     volmgrTextSectionSize = 0;
	PVOID      KernelTextSectionBase = NULL;
	PVOID      Win32kBaseTextSectionBase = NULL;
	PVOID      volmgrTextSectionBase = NULL;


	if (GetSectionData("ntoskrnl.exe", ".text", &KernelTextSectionSize, &KernelTextSectionBase) == FALSE)
	{
		ShvOsDebugPrint("Couldn't get ntoskrnl.exe .text section data");
		return FALSE;
	}

	if (GetSectionData("volmgr.sys", ".text", &volmgrTextSectionSize, &volmgrTextSectionBase) == FALSE)
	{
		ShvOsDebugPrint("Couldn't get volmgr.sys .text section data");
		return FALSE;
	}

	PEPROCESS CsrssProcess = GetCsrssProcess();
	KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);


	if (GlobalConfig::Instance().CurrentWindowsBuildNumber > WINDOWS_8_1)
	{
		if (GetSectionData("win32kfull.sys", ".text", &Win32kTextSectionSize, &Win32kBaseTextSectionBase) == FALSE)
		{
			ShvOsDebugPrint("Couldn't get win32k .text section data");
			return FALSE;
		}
		ShvOsDebugPrint("win32kfull.sys\n");
	}
	else
	{
		if (GetSectionData("win32k.sys", ".text", &Win32kTextSectionSize, &Win32kBaseTextSectionBase) == FALSE)
		{
			ShvOsDebugPrint("Couldn't get win32k .text section data");
			return FALSE;
		}
		ShvOsDebugPrint("win32k.sys\n");
	}

	UINT64 Win32kCodeCaveIndex = 0;
	UINT64 Win32kCodeCaveSize = 0;

	for (UINT64 MemoryLocation = (UINT64)Win32kBaseTextSectionBase; MemoryLocation < Win32kTextSectionSize + (UINT64)Win32kBaseTextSectionBase, Win32kCodeCaveIndex < 200; MemoryLocation++)
	{

		if (*(UCHAR*)MemoryLocation == 0xCC || *(UCHAR*)MemoryLocation == 0x90)
		{
			Win32kCodeCaveSize++;
		}
		else
		{
			Win32kCodeCaveSize = 0;
		}

		if (Win32kCodeCaveSize == 15)
		{
			// Ignore if at page boundary
			if (PAGE_ALIGN(MemoryLocation) != PAGE_ALIGN(MemoryLocation - 13))
				continue;
			GlobalConfig::Instance().Win32kCodeCaves[Win32kCodeCaveIndex] = MemoryLocation - 13;
			Win32kCodeCaveIndex++;
		}
	}
	ShvOsDebugPrint("Win32kCodeCaveIndex:[%p]\n", Win32kCodeCaveIndex);

	KeUnstackDetachProcess(&State);

	UINT64 KernelCodeCaveIndex = 0;

	UINT64 KernelCodeCaveSize = 0;

	for (UINT64 MemoryLocation = (UINT64)KernelTextSectionBase; MemoryLocation < KernelTextSectionSize + (UINT64)KernelTextSectionBase, KernelCodeCaveIndex < 200; MemoryLocation++)
	{

		if (*(UCHAR*)MemoryLocation == 0xCC || *(UCHAR*)MemoryLocation == 0x90)
		{
			KernelCodeCaveSize++;
		}
		else
		{
			KernelCodeCaveSize = 0;
		}

		if (KernelCodeCaveSize == 15)
		{
			// Ignore if at page boundary
			if (PAGE_ALIGN(MemoryLocation) != PAGE_ALIGN(MemoryLocation - 13))
				continue;

			GlobalConfig::Instance().KernelCodeCaves[KernelCodeCaveIndex] = MemoryLocation - 13;
			KernelCodeCaveIndex++;
		}
	}
	ShvOsDebugPrint("KernelCodeCaveIndex:[%p]\n", KernelCodeCaveIndex);


	UINT64 volmgrCodeCaveIndex = 0;

	UINT64 volmgrCodeCaveSize = 0;

	for (UINT64 MemoryLocation = (UINT64)volmgrTextSectionBase; MemoryLocation < volmgrTextSectionSize + (UINT64)volmgrTextSectionBase, volmgrCodeCaveIndex < 1; MemoryLocation++)
	{

		if (*(UCHAR*)MemoryLocation == 0xCC || *(UCHAR*)MemoryLocation == 0x90)
		{
			volmgrCodeCaveSize++;
		}
		else
		{
			volmgrCodeCaveSize = 0;
		}

		if (volmgrCodeCaveSize == 15)
		{
			// Ignore if at page boundary
			if (PAGE_ALIGN(MemoryLocation) != PAGE_ALIGN(MemoryLocation - 13))
				continue;

			GlobalConfig::Instance().volmgrCodeCaves[volmgrCodeCaveIndex] = MemoryLocation - 13;
			volmgrCodeCaveIndex++;
		}
	}
	ShvOsDebugPrint("volmgrCodeCaveIndex:[%d]\n", volmgrCodeCaveIndex);

	return TRUE;
}

VOID
ShvOsDebugPrint(
	_In_ PCCH Format,
	...
)
{
	va_list arglist;

	va_start(arglist, Format);

#ifdef DEBUG_PRINTEX

	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, arglist);

#endif // DEBUG_PRINTEX


#ifdef FILE_LOG
	CHAR Str[100] = "";
	sprintf(Str, Format, arglist);
	FileLog(Str);

#endif // FILE_LOG


#ifdef NOTHING_PRINT

	UNREFERENCED_PARAMETER(Format);
	UNREFERENCED_PARAMETER(arglist);

#endif // NOTHING_PRINT

	va_end(arglist);
}

PVOID FindSignature(PVOID Memory, UINT64 Size, PCSZ Pattern, PCSZ Mask)
{
	UINT64 SigLength = strlen(Mask);
	if (SigLength > Size) return NULL;

	for (UINT64 i = 0; i < Size - SigLength; i++)
	{
		BOOLEAN Found = TRUE;
		for (UINT64 j = 0; j < SigLength; j++)
			Found &= Mask[j] == '?' || Pattern[j] == *((PCHAR)Memory + i + j);

		if (Found)
			return (PCHAR)Memory + i;
	}
	return NULL;
}

int MathPower(int Base, int Exponent)
{
	int Result = 1;
	for (;;)
	{
		if (Exponent & 1)
		{
			Result *= Base;
		}

		Exponent >>= 1;
		if (!Exponent)
		{
			break;
		}
		Base *= Base;
	}
	return Result;
}

NTSTATUS ReadProcessMemoryByMmCopyVirtualMemory(UINT32 pid, PVOID virtualAddress, PVOID destinationBuffer, size_t bufferSize, size_t* numberOfBytes)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS curr_process;
	PEPROCESS from_process;
	KPROCESSOR_MODE previous_mode;
	size_t bytes_copied = 0;


	UINT8* virtual_address_max = reinterpret_cast<UINT8*>(virtualAddress) + bufferSize;
	UINT8* dst_buffer_max = reinterpret_cast<UINT8*>(destinationBuffer) + bufferSize;

	if (virtual_address_max < virtualAddress)
		return STATUS_ACCESS_VIOLATION;

	if (dst_buffer_max < destinationBuffer)
		return STATUS_ACCESS_VIOLATION;


	if (virtual_address_max > reinterpret_cast<UINT8*>(0x7FFFFFFFFFFF) || dst_buffer_max > reinterpret_cast<UINT8*>(0x7FFFFFFFFFFF))
		return STATUS_ACCESS_VIOLATION;

	if (!bufferSize)
	{
		return status;
	}

	curr_process = PsGetCurrentProcess();
	previous_mode = ExGetPreviousMode();
	from_process = GetProcessById((HANDLE)pid);
	status = MmCopyVirtualMemory(from_process, virtualAddress, curr_process, destinationBuffer, bufferSize, previous_mode, &bytes_copied);

	if (ARGUMENT_PRESENT(numberOfBytes)) {
		__try
		{
			*numberOfBytes = bytes_copied;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			NOTHING;
		}
	}

	return status;
}
EXTERN_C BOOLEAN ShvVmCall(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9);
EXTERN_C BOOLEAN ShvVmCallEx(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9, UINT64 r10, UINT64 r11, UINT64 r12, UINT64 r13, UINT64 r14, UINT64 r15);

NTSTATUS ReadProcessMemoryByVtCr3(UINT32 pid, PVOID virtualAddress, PVOID destinationBuffer, size_t bufferSize, size_t* numberOfBytes)
{
	PEPROCESS PProcess = NULL;


	PProcess = GetProcessById((HANDLE)pid);


	if (!PProcess)
		return STATUS_UNSUCCESSFUL;

	UINT64 TargetCr3 = GetCr3(PProcess);


	PVOID BufferTemp = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOLTAG);

	if (BufferTemp == NULL)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	BOOLEAN IsReadSuccess = ShvVmCallEx(VMCALL_READ_MEMORY_BY_TARGET_CR3, TargetCr3, (UINT64)virtualAddress, (UINT64)BufferTemp, (UINT64)bufferSize, 0, 0, 0, 0, 0);

	RtlCopyMemory(destinationBuffer, BufferTemp, bufferSize);

	ExFreePool(BufferTemp);


	if (numberOfBytes)
		if (IsReadSuccess)
			*numberOfBytes = bufferSize;
		else
			*numberOfBytes = 0;


	return STATUS_SUCCESS;
}


NTSTATUS ReadProcessMemoryByVtHostMmCopyMemory(UINT32 pid, PVOID virtualAddress, PVOID destinationBuffer, size_t bufferSize, size_t* numberOfBytes)
{

	if ((UINT64)virtualAddress <= 0x10000 || (UINT64)virtualAddress > 0x7FFFFFFFFFFF)
	{
		return STATUS_UNSUCCESSFUL;
	}


	size_t TempNumberOfBytes;
	PEPROCESS PProcess = NULL;

	PProcess = GetProcessById((HANDLE)pid);
	if (!PProcess)
		return STATUS_UNSUCCESSFUL;

	UINT64 TargetCr3 = GetCr3(PProcess);

	PVOID BufferTemp = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOLTAG);

	if (BufferTemp == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	BOOLEAN IsReadSuccess = ShvVmCallEx(VMCALL_READ_MEMORY_BY_TARGET_CR3_AND_MMCOPYMEMORY, TargetCr3, (UINT64)virtualAddress, (UINT64)BufferTemp, (UINT64)bufferSize, (UINT64)&TempNumberOfBytes, 0, 0, 0, 0);



	RtlCopyMemory(destinationBuffer, BufferTemp, bufferSize);

	ExFreePool(BufferTemp);

	if (IsReadSuccess)
	{
		if (numberOfBytes)
			*numberOfBytes = TempNumberOfBytes;

		return STATUS_SUCCESS;
	}
	else
	{
		//ShvOsDebugPrint("VtReadProcessMemoryHostMmCopyMemory Faild Cr3:[%p] virtualAddress:[%p]\n", TargetCr3, virtualAddress);
		if (numberOfBytes)
			*numberOfBytes = 0;
		return STATUS_UNSUCCESSFUL;
	}


}


NTSTATUS WriteProcessMemoryByVtCr3(UINT32 pid, PVOID virtualAddress, PVOID sourceBuffer, size_t bufferSize, size_t* numberOfBytes)
{
	PEPROCESS PProcess = NULL;

	PProcess = GetProcessById((HANDLE)pid);
	if (!PProcess)
		return STATUS_UNSUCCESSFUL;

	UINT64 Cr3 = GetCr3(PProcess);

	PVOID BufferTemp = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOLTAG);

	if (BufferTemp == NULL)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlCopyMemory(BufferTemp, sourceBuffer, bufferSize);

	BOOLEAN IsWriteSuccess = ShvVmCallEx(VMCALL_WRITE_MEMORY, Cr3, (UINT64)virtualAddress, (UINT64)BufferTemp, (UINT64)bufferSize, 0, 0, 0, 0, 0);

	ExFreePool(BufferTemp);

	if (numberOfBytes)
		if (IsWriteSuccess)
			*numberOfBytes = bufferSize;
		else
			*numberOfBytes = 0;

	return STATUS_SUCCESS;
}

NTSTATUS WriteProcessMemoryByVtHostMmMapIoSpace(UINT32 pid, PVOID virtualAddress, PVOID sourceBuffer, size_t bufferSize, size_t* numberOfBytes)
{
	SIZE_T TempNumberOfBytes;
	PEPROCESS PProcess = NULL;

	PProcess = GetProcessById((HANDLE)pid);
	if (!PProcess)
		return STATUS_UNSUCCESSFUL;

	UINT64 Cr3 = GetCr3(PProcess);

	PVOID BufferTemp = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOLTAG);

	if (BufferTemp == NULL)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlCopyMemory(BufferTemp, sourceBuffer, bufferSize);

	BOOLEAN IsWriteSuccess = ShvVmCallEx(VMCALL_WRITE_MEMORY_BY_TARGET_CR3_AND_MMMAPIOSPACE, Cr3, (UINT64)virtualAddress, (UINT64)BufferTemp, (UINT64)bufferSize, (UINT64)&TempNumberOfBytes, 0, 0, 0, 0);

	ExFreePool(BufferTemp);

	if (IsWriteSuccess)
	{
		if (numberOfBytes)
			*numberOfBytes = TempNumberOfBytes;
		return STATUS_SUCCESS;
	}
	else
	{
		if (numberOfBytes)
			*numberOfBytes = 0;
		return STATUS_UNSUCCESSFUL;
	}

}



NTSTATUS WriteProcessMemoryByMdl(UINT32 pid, PVOID virtualAddress, PVOID sourceBuffer, size_t bufferSize, size_t* numberOfBytes)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PMDL mdl;
	KAPC_STATE apc;
	KPROCESSOR_MODE previos_mode = ExGetPreviousMode();
	size_t number_of_bytes_temp = 0;
	UINT8* virtual_address_max = reinterpret_cast<UINT8*>(virtualAddress) + bufferSize;
	UINT8* src_buffer_max = reinterpret_cast<UINT8*>(sourceBuffer) + bufferSize;

	if (virtual_address_max < virtualAddress)
		return STATUS_ACCESS_VIOLATION;

	if (src_buffer_max < sourceBuffer)
		return STATUS_ACCESS_VIOLATION;

	if (virtual_address_max > reinterpret_cast<UINT8*>(0x7FFFFFFEFFFF) || src_buffer_max > reinterpret_cast<UINT8*>(0x7FFFFFFEFFFF))
		return STATUS_ACCESS_VIOLATION;


	status = PsLookupProcessByProcessId((HANDLE)pid, &process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	const PVOID buffer_temp = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOLTAG);

	if (buffer_temp == NULL)
	{
		ObDereferenceObject(process);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlCopyMemory(buffer_temp, sourceBuffer, bufferSize);

	KeStackAttachProcess(process, &apc);

	if (!MmIsAddressValid(virtualAddress))
	{
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*numberOfBytes = number_of_bytes_temp;

		return STATUS_ACCESS_VIOLATION;
	}

	mdl = IoAllocateMdl(virtualAddress, (ULONG)bufferSize, 0, 0, NULL);
	if (mdl == NULL)
	{
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*numberOfBytes = number_of_bytes_temp;
		return STATUS_NO_MEMORY;
	}

	MmBuildMdlForNonPagedPool(mdl);

	__try
	{
		MmProbeAndLockPages(mdl, previos_mode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

		//ShvOsDebugPrint("MmProbeAndLockPages Execption!\n");
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*numberOfBytes = number_of_bytes_temp;
		return STATUS_UNSUCCESSFUL;
	}

#pragma prefast(push)
#pragma prefast(disable:__WARNING_MODIFYING_MDL, "Trust me I'm a scientist")
	const CSHORT OriginalMdlFlags = mdl->MdlFlags;
	mdl->MdlFlags |= MDL_PAGES_LOCKED;
	mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

	PVOID mapped = 0;
	__try
	{
		mapped = MmMapLockedPagesSpecifyCache(mdl, previos_mode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//ShvOsDebugPrint("MmProbeAndLockPages Execption!\n");
		mdl->MdlFlags = OriginalMdlFlags;
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*numberOfBytes = number_of_bytes_temp;
		return STATUS_NONE_MAPPED;
	}

	if (mapped == NULL)
	{
		mdl->MdlFlags = OriginalMdlFlags;
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		ExFreePool(buffer_temp);
		*numberOfBytes = number_of_bytes_temp;
		return STATUS_NONE_MAPPED;
	}

	__try
	{
#pragma warning(push)
#pragma warning(disable:6386)
		RtlCopyMemory(mapped, buffer_temp, bufferSize);
#pragma warning(pop)

		number_of_bytes_temp = bufferSize;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		number_of_bytes_temp = 0;
		status = STATUS_ACCESS_VIOLATION;
	}

	MmUnmapLockedPages(mapped, mdl);
	mdl->MdlFlags = OriginalMdlFlags;
#pragma prefast(pop)

	IoFreeMdl(mdl);
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);
	ExFreePool(buffer_temp);
	*numberOfBytes = number_of_bytes_temp;

	return status;
}




NTSTATUS GetProcessModuleFunc(HANDLE Pid, PVOID Module, CHAR* Name, PVOID POutBuffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS PMyProcess = PsGetCurrentProcess();
	PEPROCESS PEProcess = 0;

	if ((UINT64)Pid < 4 || (UINT64)Module <= 0 || (UINT64)Name <= 0 || (UINT64)POutBuffer <= 0)
		return Status;

	Status = PsLookupProcessByProcessId(Pid, &PEProcess);

	if (!NT_SUCCESS(Status))
		return Status;

	PVOID PData = ExAllocatePoolWithTag(NonPagedPool, 8, POOLTAG);
	if (!PData || !MmIsAddressValid(PData))
		return Status;
	RtlZeroMemory(PData, 8);

	//模块名转换
	ANSI_STRING AnsiBuffer = { 0 };
	UNICODE_STRING QueryName = { 0 };
	AnsiBuffer.Buffer = Name;
	AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(Name);
	RtlAnsiStringToUnicodeString(&QueryName, &AnsiBuffer, TRUE);//转换

	KAPC_STATE  Apc = { 0 };
	if (PEProcess != PMyProcess)
		KeStackAttachProcess(PEProcess, &Apc);

	__try {
		ULONG64 PFuncAddr = 0;
		HANDLE HMod = (HANDLE)Module;
		//判断目标进程x86 or x64
		BOOLEAN IsWow64 = (PsGetProcessWow64Process(PEProcess) != NULL) ? TRUE : FALSE;
		if (IsWow64) {//x86
			IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)HMod;
			IMAGE_OPTIONAL_HEADER32* opthdr = (IMAGE_OPTIONAL_HEADER32*)((UCHAR*)HMod + dosheader->e_lfanew + 24);

			//查找导出表 
			PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((UCHAR*)dosheader + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			PULONG pAddressOfFunctions = (ULONG*)((UCHAR*)HMod + exports->AddressOfFunctions);
			PULONG pAddressOfNames = (ULONG*)((UCHAR*)HMod + exports->AddressOfNames);
			PUSHORT pAddressOfNameOrdinals = (USHORT*)((UCHAR*)HMod + exports->AddressOfNameOrdinals);

			//对比函数名 
			for (ULONG i = 0; i < exports->NumberOfNames; i++)
			{
				USHORT index = pAddressOfNameOrdinals[i];
				ULONG offset = pAddressOfFunctions[index];
				PUCHAR pFuncName = (PUCHAR)((UCHAR*)HMod + pAddressOfNames[i]);

				ANSI_STRING AnsiStringSec = { 0 };
				RtlInitString(&AnsiStringSec, (PCSZ)pFuncName);
				UNICODE_STRING FuncName = { 0 };
				RtlAnsiStringToUnicodeString(&FuncName, &AnsiStringSec, TRUE);
				if (RtlEqualUnicodeString(&FuncName, &QueryName, TRUE))
				{
					RtlFreeUnicodeString(&FuncName);// 释放内存
					PFuncAddr = (ULONG64)HMod + offset;
					Status = STATUS_SUCCESS;
					break;
				}
				RtlFreeUnicodeString(&FuncName);// 释放内存
			}

		}
		else {//x64
			IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)HMod;
			IMAGE_OPTIONAL_HEADER64* opthdr = (IMAGE_OPTIONAL_HEADER64*)((UCHAR*)HMod + dosheader->e_lfanew + 24);

			//查找导出表 
			PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((UCHAR*)dosheader + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			PULONG pAddressOfFunctions = (ULONG*)((UCHAR*)HMod + exports->AddressOfFunctions);
			PULONG pAddressOfNames = (ULONG*)((UCHAR*)HMod + exports->AddressOfNames);
			PUSHORT pAddressOfNameOrdinals = (USHORT*)((UCHAR*)HMod + exports->AddressOfNameOrdinals);

			//对比函数名 
			for (ULONG i = 0; i < exports->NumberOfNames; i++)
			{
				USHORT index = pAddressOfNameOrdinals[i];
				ULONG offset = pAddressOfFunctions[index];
				PUCHAR pFuncName = (PUCHAR)((UCHAR*)HMod + pAddressOfNames[i]);

				ANSI_STRING AnsiStringSec = { 0 };
				RtlInitString(&AnsiStringSec, (PCSZ)pFuncName);
				UNICODE_STRING FuncName = { 0 };
				RtlAnsiStringToUnicodeString(&FuncName, &AnsiStringSec, TRUE);
				if (RtlEqualUnicodeString(&FuncName, &QueryName, TRUE))
				{
					RtlFreeUnicodeString(&FuncName);// 释放内存
					PFuncAddr = (ULONG64)HMod + offset;
					Status = STATUS_SUCCESS;
					break;
				}
				RtlFreeUnicodeString(&FuncName);// 释放内存
			}
		}
		*(ULONG_PTR*)PData = PFuncAddr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {//发生异常
		Status = STATUS_UNSUCCESSFUL;
	}

	if (PEProcess != PMyProcess)
		KeUnstackDetachProcess(&Apc);

	if (NT_SUCCESS(Status))
		*(ULONG_PTR*)POutBuffer = *(ULONG_PTR*)PData;

	RtlFreeUnicodeString(&QueryName);// 释放内存
	ExFreePool(PData);
	return Status;
}
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

NTSTATUS GetProcessModule(HANDLE Pid, CHAR* Name, PVOID POutBuffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	if ((UINT64)Pid < 4 || (UINT64)Name <= 0 || (UINT64)POutBuffer <= 0)
		return Status;

	PEPROCESS PMyProcess = PsGetCurrentProcess();
	PEPROCESS PEProcess = 0;

	Status = PsLookupProcessByProcessId(Pid, &PEProcess);
	if (!NT_SUCCESS(Status))
		return Status;

	PVOID PData = ExAllocatePoolWithTag(NonPagedPool, 8, POOLTAG);
	if (!PData || !MmIsAddressValid(PData))
		return Status;
	RtlZeroMemory(PData, 8);

	//模块名转换
	ANSI_STRING AnsiBuffer = { 0 };
	UNICODE_STRING QueryName = { 0 };
	AnsiBuffer.Buffer = Name;
	AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(Name);
	RtlAnsiStringToUnicodeString(&QueryName, &AnsiBuffer, TRUE);//转换

	KAPC_STATE  Apc = { 0 };
	if (PEProcess != PMyProcess)
		KeStackAttachProcess(PEProcess, &Apc);

	__try {
		ULONG64 BaseAddress = 0;
		//判断目标进程x86 or x64
		BOOLEAN IsWow64 = (PsGetProcessWow64Process(PEProcess) != NULL) ? TRUE : FALSE;
		if (IsWow64) {//x86
			PPEB32 pPEB32 = (PPEB32)PsGetProcessWow64Process(PEProcess);
			PLIST_ENTRY32 pListEntryStart32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);
			PLIST_ENTRY32 pListEntryEnd32 = pListEntryStart32;

			do {
				PLDR_DATA_TABLE_ENTRY32 pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(pListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
				UNICODE_STRING BaseDllName = { 0 };
				BaseDllName.Buffer = (PWCH)pLdrDataEntry32->BaseDllName.Buffer;
				BaseDllName.Length = pLdrDataEntry32->BaseDllName.Length;
				BaseDllName.MaximumLength = pLdrDataEntry32->BaseDllName.MaximumLength;
				if (RtlEqualUnicodeString(&BaseDllName, &QueryName, TRUE))
				{
					BaseAddress = (ULONG64)pLdrDataEntry32->DllBase;
					Status = STATUS_SUCCESS;
					break;
				}
				pListEntryStart32 = (PLIST_ENTRY32)pListEntryStart32->Flink;

			} while (pListEntryStart32 != pListEntryEnd32);
		}
		else {//x64
			PPEB64 pPEB64 = (PPEB64)PsGetProcessPeb(PEProcess);
			PLIST_ENTRY64 pListEntryStart64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)pPEB64->Ldr)->InMemoryOrderModuleList.Flink);
			PLIST_ENTRY64 pListEntryEnd64 = pListEntryStart64;
			do {
				PLDR_DATA_TABLE_ENTRY64 pLdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(pListEntryStart64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

				if (RtlEqualUnicodeString(&pLdrDataEntry64->BaseDllName, &QueryName, TRUE))
				{
					BaseAddress = (ULONG64)pLdrDataEntry64->DllBase;
					Status = STATUS_SUCCESS;
					break;
				}
				pListEntryStart64 = (PLIST_ENTRY64)pListEntryStart64->Flink;

			} while (pListEntryStart64 != pListEntryEnd64);
		}
		*(ULONG_PTR*)PData = (ULONG_PTR)BaseAddress;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {//发生异常
		Status = STATUS_UNSUCCESSFUL;
	}

	if (PEProcess != PMyProcess)
		KeUnstackDetachProcess(&Apc);

	if (NT_SUCCESS(Status)) *(ULONG_PTR*)POutBuffer = *(ULONG_PTR*)PData;
	RtlFreeUnicodeString(&QueryName);// 释放内存
	ExFreePool(PData);
	return Status;
}

TIME_FIELDS GetTime()
{
	LARGE_INTEGER GelinTime = { 0 };
	LARGE_INTEGER LocalTime = { 0 };
	TIME_FIELDS NowFields;

	KeQuerySystemTime(&GelinTime);
	ExSystemTimeToLocalTime(&GelinTime, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &NowFields);
	return NowFields;
}

/**
文件日志
*/
VOID FileLog(CHAR* LogText)
{
	UNICODE_STRING FileName = { 0 };
	RtlInitUnicodeString(&FileName, FileLogPath);
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;

	NTSTATUS result = ZwCreateFile(&FileHandle, FILE_APPEND_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (NT_SUCCESS(result)) {
		CHAR Str[200] = "";
		TIME_FIELDS time = GetTime();
		sprintf(Str, "%04d-%02d-%02d %02d:%02d:%02d\t Content:%s\n", time.Year, time.Month, time.Day, time.Hour, time.Minute, time.Milliseconds, LogText);
		ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Str, (ULONG)strlen(Str), NULL, NULL);
		ZwClose(FileHandle);
	}
}


UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess)
{
	UNICODE_STRING TruncatedFullImageName = { 0 };

	__try
	{
		PUNICODE_STRING FullImageName = (PUNICODE_STRING) * (ULONG64*)((ULONG64)TargetProcess + GlobalConfig::Instance().SeAuditProcessCreationInfoOffset);
		if (FullImageName->Buffer != NULL || FullImageName->Length != 0)
		{
			for (size_t i = FullImageName->Length / 2; i > 0; i--)
			{
				if (FullImageName->Buffer[i] == L'\\')
				{
					RtlInitUnicodeString(&TruncatedFullImageName, &FullImageName->Buffer[i + 1]);
					break;
				}
			}
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return TruncatedFullImageName;
}

BOOLEAN RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length) / sizeof(WCHAR);
	UNICODE_STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= sizeof(WCHAR))
	{
		if (RtlEqualUnicodeString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

NTSTATUS CreateThread(PVOID TargetEP)
{
	OBJECT_ATTRIBUTES objAddr = { 0 };
	HANDLE threadHandle = 0;
	NTSTATUS status = STATUS_SUCCESS;
	InitializeObjectAttributes(&objAddr, NULL, OBJ_KERNEL_HANDLE, 0, NULL);
	status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, &objAddr, NULL, NULL, (PKSTART_ROUTINE)TargetEP, NULL);
	return status;
}


// 使得当前线程睡眠
VOID KeSleep(IN LONG lSeccond)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= lSeccond;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}


/**
获取进程eprocess
*/
PEPROCESS GetProcessById(HANDLE ProcessId)
{
	if ((UINT64)ProcessId < 4)
		return NULL;

	PEPROCESS PProcess = NULL;
	PLIST_ENTRY ListEntry = (LIST_ENTRY*)((UINT64)PsInitialSystemProcess + GlobalConfig::Instance().ActiveProcessLinksOffset);
	PLIST_ENTRY ListEnd = ListEntry;
	do {
		PEPROCESS TempPProcess = (PEPROCESS)((UINT64)ListEntry - GlobalConfig::Instance().ActiveProcessLinksOffset);
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

PETHREAD GetThreadByTid(HANDLE ThreadId)
{
	if ((UINT64)ThreadId < 4)
		return NULL;

	PETHREAD PThread = NULL;
	PLIST_ENTRY ListEntry = (LIST_ENTRY*)((UINT64)PsInitialSystemProcess + GlobalConfig::Instance().ActiveProcessLinksOffset);
	PLIST_ENTRY ListEnd = ListEntry;
	do {
		PEPROCESS TempPProcess = (PEPROCESS)((UINT64)ListEntry - GlobalConfig::Instance().ActiveProcessLinksOffset);
		if (PsGetProcessExitStatus(TempPProcess) == 0x103) {

			PLIST_ENTRY ThreadListEntry = (PLIST_ENTRY)((UINT64)TempPProcess + GlobalConfig::Instance().ThreadListHeadOffset);
			PLIST_ENTRY ThreadListEnd = ThreadListEntry;
			do {
				PETHREAD TempPThread = (PETHREAD)((UINT64)ThreadListEntry - GlobalConfig::Instance().ThreadListEntryOffset);
				if (ThreadId == PsGetThreadId(TempPThread))
				{
					PThread = TempPThread;
					break;
				}
				ThreadListEntry = ThreadListEntry->Blink;
			} while (ThreadListEntry != ThreadListEnd);

		}
		ListEntry = ListEntry->Blink;
	} while (ListEntry != ListEnd);

	return PThread;
}

UINT64 GetCr3(PEPROCESS PProcess)
{
	UINT64 Cr3 = NULL;
	Cr3 = *(UINT64*)((UINT64)PProcess + GlobalConfig::Instance().DirectoryTableBaseOffset);
	if (!Cr3) Cr3 = *(UINT64*)((UINT64)PProcess + GlobalConfig::Instance().UserDirectoryTableBaseOffset);

	return Cr3;
}

/**
获取函数地址
*/
PVOID GetProcAddress(WCHAR* FuncName)
{
	UNICODE_STRING u_FuncName = { 0 };
	RtlInitUnicodeString(&u_FuncName, FuncName);
	return MmGetSystemRoutineAddress(&u_FuncName);
}