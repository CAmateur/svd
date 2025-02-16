#include "UserHook.h"
#include "MdlLock.h"
#include "Utils.h"

EXTERN_C BOOLEAN ShvVmCall(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9);
EXTERN_C BOOLEAN ShvVmCallEx(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9, UINT64 r10, UINT64 r11, UINT64 r12, UINT64 r13, UINT64 r14, UINT64 r15);

LIST_ENTRY UserHook::EptHookUserListHead = { 0 };
KSPIN_LOCK UserHook::EptHookUserListLock = { 0 };

VOID UserHook::Initialize()
{
	InitializeListHead(&UserHook::EptHookUserListHead);
	KeInitializeSpinLock(&UserHook::EptHookUserListLock);
}

VOID UserHook::Destory()
{
	UINT64 ProcessId = 0;
	while (GetEptHookUserProcessId(&ProcessId))
	{
		RemoveALLEptHookUserListNodeByPid(ProcessId);
	}
}

BOOLEAN UserHook::AddEptHookUserListNode(UINT64 ProcessId, PEPT_HOOK_USER_PARAM	Param)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&UserHook::EptHookUserListLock, &OldIrql);
	PEPT_HOOK_USER_LIST PEptHookR3Node = (PEPT_HOOK_USER_LIST)ExAllocatePoolWithTag(PagedPool, sizeof(EPT_HOOK_USER_LIST), POOLTAG);
	if (!PEptHookR3Node)
	{
		KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
		return FALSE;
	}
	RtlZeroMemory(PEptHookR3Node, sizeof(EPT_HOOK_USER_LIST));
	PEptHookR3Node->Param.Type = Param->Type;
	PEptHookR3Node->Param.ProcessId = Param->ProcessId;
	PEptHookR3Node->Param.TargetPagePhysicalAddress = Param->TargetPagePhysicalAddress;
	PEptHookR3Node->Param.TargetVirtualAddress = Param->TargetVirtualAddress;
	PEptHookR3Node->Param.TargetPageVirtualAddress = Param->TargetPageVirtualAddress;
	PEptHookR3Node->Param.FakePagePhysicalAddress = Param->FakePagePhysicalAddress;
	PEptHookR3Node->Param.FakePageVirtualAddress = Param->FakePageVirtualAddress;
	PEptHookR3Node->Param.PMdl = Param->PMdl;

	InsertHeadList(&UserHook::EptHookUserListHead, &PEptHookR3Node->EptHookR3List);
	KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
	return TRUE;
}

BOOLEAN UserHook::GetEptHookUserListNodeByPid(UINT64 ProcessId, PEPT_HOOK_USER_PARAM PParam)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&UserHook::EptHookUserListLock, &OldIrql);

	PLIST_ENTRY Current = &UserHook::EptHookUserListHead;
	while (&UserHook::EptHookUserListHead != Current->Flink)
	{
		Current = Current->Flink;
		PEPT_HOOK_USER_LIST PEptHookR3Node = CONTAINING_RECORD(Current, EPT_HOOK_USER_LIST, EptHookR3List);
		if (PEptHookR3Node->Param.ProcessId == ProcessId)
		{
			if (PParam)
			{
				PParam->Type = PEptHookR3Node->Param.Type;
				PParam->ProcessId = PEptHookR3Node->Param.ProcessId;
				PParam->TargetVirtualAddress = PEptHookR3Node->Param.TargetVirtualAddress;
				PParam->TargetPhysicalAddress = PEptHookR3Node->Param.TargetPhysicalAddress;
				PParam->TargetPageVirtualAddress = PEptHookR3Node->Param.TargetPageVirtualAddress;
				PParam->TargetPagePhysicalAddress = PEptHookR3Node->Param.TargetPagePhysicalAddress;
				PParam->FakePageVirtualAddress = PEptHookR3Node->Param.FakePageVirtualAddress;
				PParam->FakePagePhysicalAddress = PEptHookR3Node->Param.FakePagePhysicalAddress;
				PParam->PMdl = PEptHookR3Node->Param.PMdl;
			}
			KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
	return FALSE;
}
BOOLEAN UserHook::GetEptHookUserListNode(UINT64 ProcessId, PVOID TargetVirtualAddress, PEPT_HOOK_USER_PARAM PParam)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&UserHook::EptHookUserListLock, &OldIrql);

	PLIST_ENTRY Current = &UserHook::EptHookUserListHead;
	while (&UserHook::EptHookUserListHead != Current->Flink)
	{
		Current = Current->Flink;
		PEPT_HOOK_USER_LIST PEptHookR3Node = CONTAINING_RECORD(Current, EPT_HOOK_USER_LIST, EptHookR3List);
		if (PEptHookR3Node->Param.ProcessId == ProcessId && PEptHookR3Node->Param.TargetVirtualAddress == (UINT64)TargetVirtualAddress)
		{
			if (PParam)
			{
				PParam->Type = PEptHookR3Node->Param.Type;
				PParam->ProcessId = PEptHookR3Node->Param.ProcessId;
				PParam->TargetVirtualAddress = PEptHookR3Node->Param.TargetVirtualAddress;
				PParam->TargetPhysicalAddress = PEptHookR3Node->Param.TargetPhysicalAddress;
				PParam->TargetPageVirtualAddress = PEptHookR3Node->Param.TargetPageVirtualAddress;
				PParam->TargetPagePhysicalAddress = PEptHookR3Node->Param.TargetPagePhysicalAddress;
				PParam->FakePageVirtualAddress = PEptHookR3Node->Param.FakePageVirtualAddress;
				PParam->FakePagePhysicalAddress = PEptHookR3Node->Param.FakePagePhysicalAddress;
				PParam->PMdl = PEptHookR3Node->Param.PMdl;
			}
			KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
	return FALSE;
}

BOOLEAN UserHook::IsExistUserEptBreakPint(UINT64 ProcessId, PVOID TargetVirtualAddress, PEPT_HOOK_USER_PARAM PParam)
{
	UINT64 TargetPageVirtualAddress = ((UINT64)TargetVirtualAddress & ~0xfff);
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&UserHook::EptHookUserListLock, &OldIrql);

	PLIST_ENTRY Current = &UserHook::EptHookUserListHead;
	while (&UserHook::EptHookUserListHead != Current->Flink)
	{
		Current = Current->Flink;
		PEPT_HOOK_USER_LIST PEptHookR3Node = CONTAINING_RECORD(Current, EPT_HOOK_USER_LIST, EptHookR3List);
		if (PEptHookR3Node->Param.ProcessId == ProcessId && PEptHookR3Node->Param.TargetPageVirtualAddress == TargetPageVirtualAddress)
		{
			if (PParam)
			{
				PParam->Type = PEptHookR3Node->Param.Type;
				PParam->ProcessId = PEptHookR3Node->Param.ProcessId;
				PParam->TargetVirtualAddress = PEptHookR3Node->Param.TargetVirtualAddress;
				PParam->TargetPhysicalAddress = PEptHookR3Node->Param.TargetPhysicalAddress;
				PParam->TargetPageVirtualAddress = PEptHookR3Node->Param.TargetPageVirtualAddress;
				PParam->TargetPagePhysicalAddress = PEptHookR3Node->Param.TargetPagePhysicalAddress;
				PParam->FakePageVirtualAddress = PEptHookR3Node->Param.FakePageVirtualAddress;
				PParam->FakePagePhysicalAddress = PEptHookR3Node->Param.FakePagePhysicalAddress;
				PParam->PMdl = PEptHookR3Node->Param.PMdl;
			}
			KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
	return FALSE;
}

BOOLEAN UserHook::RemoveEptHookUserListNode(UINT64 ProcessId, PVOID TargetVirtualAddress)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&UserHook::EptHookUserListLock, &OldIrql);

	PLIST_ENTRY Current = &UserHook::EptHookUserListHead;
	while (&UserHook::EptHookUserListHead != Current->Flink)
	{
		Current = Current->Flink;
		PEPT_HOOK_USER_LIST PEptHookR3Node = CONTAINING_RECORD(Current, EPT_HOOK_USER_LIST, EptHookR3List);
		if (PEptHookR3Node->Param.ProcessId == ProcessId && PEptHookR3Node->Param.TargetVirtualAddress == (UINT64)TargetVirtualAddress)
		{
			RemoveEntryList(&PEptHookR3Node->EptHookR3List);
			ExFreePool(PEptHookR3Node);
			KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
	return FALSE;
}

BOOLEAN UserHook::RemoveALLEptHookUserListNodeByPid(UINT64 ProcessId)
{
	NTSTATUS Status;
	EPT_HOOK_USER_PARAM Param = { 0 };
	PEPROCESS Process;
	KAPC_STATE ApcState;
	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("RemoveALLEptHookUserListNodeByPid Get process faild\n");
		return FALSE;
	}
	KeStackAttachProcess(Process, &ApcState);

	while (GetEptHookUserListNodeByPid(ProcessId, &Param))
	{

		UINT64 TargetPagePhysicalAddress = Param.TargetPagePhysicalAddress;
		//UINT64 FakePagePhysicalAddress = Param.FakePagePhysicalAddress;

		KAFFINITY AffinityMask;
		for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
		{
			AffinityMask = MathPower(2, (int)i);
			KeSetSystemAffinityThread(AffinityMask);

			if (Param.Type == (UINT64)VMCALL_USER_EPT_HOOK)
				ShvVmCallEx((UINT64)VMCALL_USER_EPT_UNHOOK, TargetPagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0, 0);

			if (Param.Type == (UINT64)VMCALL_EPT_CHANGE_PAGE_NO_RW)
				ShvVmCallEx((UINT64)VMCALL_EPT_RECOVER_PAGE_ATTRIBUTE, TargetPagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0, 0);
		}

		Memory::UnlockMemory(Param.PMdl);

		if (Param.FakePageVirtualAddress)
			ExFreePool((PVOID)Param.FakePageVirtualAddress);

		RemoveEptHookUserListNode(Param.ProcessId, (PVOID)Param.TargetVirtualAddress);
		RtlZeroMemory(&Param, sizeof(EPT_HOOK_USER_PARAM));
	}
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);
	return TRUE;
}
BOOLEAN UserHook::GetEptHookUserProcessId(UINT64* ProcessId)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&UserHook::EptHookUserListLock, &OldIrql);

	PLIST_ENTRY Current = &UserHook::EptHookUserListHead;
	while (&UserHook::EptHookUserListHead != Current->Flink)
	{
		Current = Current->Flink;
		PEPT_HOOK_USER_LIST PEptHookR3Node = CONTAINING_RECORD(Current, EPT_HOOK_USER_LIST, EptHookR3List);
		if (PEptHookR3Node->Param.ProcessId)
		{
			if (ProcessId)
				*ProcessId = PEptHookR3Node->Param.ProcessId;

			KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&UserHook::EptHookUserListLock, OldIrql);
	return FALSE;
}

BOOLEAN UserHook::HookUserFreely(UINT64 ProcessId, PVOID TargetVirtualAddress, PVOID Buffer)
{

	if (GetEptHookUserListNode(ProcessId, TargetVirtualAddress, NULL))
	{
		ShvOsDebugPrint("TargetVirtualAddress has hooked\n");
		return TRUE;
	}

	PVOID TargetPageVirtualAddress = (PVOID)((UINT64)TargetVirtualAddress & ~0xfff);
	PMDL Mdl;
	NTSTATUS Status;
	EPT_HOOK_USER_PARAM	Param = { 0 };


	PVOID FakePageVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!FakePageVirtualAddress)
	{
		ShvOsDebugPrint("ExAllocatePoolWithTag faild\n");
		return FALSE;
	}

	RtlCopyMemory(FakePageVirtualAddress, Buffer, PAGE_SIZE);

	PEPROCESS Process;
	KAPC_STATE ApcState;


	Status = Memory::LockMemory(ProcessId, TargetPageVirtualAddress, PAGE_SIZE, &Mdl);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(FakePageVirtualAddress);
		ShvOsDebugPrint("Lock faild\n");
		return FALSE;
	}

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("Get process faild\n");
		ExFreePool(FakePageVirtualAddress);
		return FALSE;
	}



	KeStackAttachProcess(Process, &ApcState);
	UINT64 TargetPagePhysicalAddress = MmGetPhysicalAddress(TargetPageVirtualAddress).QuadPart;
	UINT64 FakePagePhysicalAddress = MmGetPhysicalAddress(FakePageVirtualAddress).QuadPart;

	KAFFINITY AffinityMask;
	for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCallEx((UINT64)VMCALL_USER_EPT_HOOK, TargetPagePhysicalAddress, FakePagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0);
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);

	Param.Type = (UINT64)VMCALL_USER_EPT_HOOK;
	Param.ProcessId = ProcessId;
	Param.TargetVirtualAddress = (UINT64)TargetVirtualAddress;
	Param.TargetPageVirtualAddress = (UINT64)TargetPageVirtualAddress;
	Param.TargetPagePhysicalAddress = TargetPagePhysicalAddress;
	Param.FakePagePhysicalAddress = FakePagePhysicalAddress;
	Param.FakePageVirtualAddress = (UINT64)FakePageVirtualAddress;
	Param.PMdl = Mdl;

	return AddEptHookUserListNode(ProcessId, &Param);
}



BOOLEAN UserHook::AntiHookAndMonitorUserPageAccessFreely(UINT64 ProcessId, PVOID TargetVirtualAddress)
{
	if (GetEptHookUserListNode(ProcessId, TargetVirtualAddress, NULL))
	{
		ShvOsDebugPrint("TargetVirtualAddress has been AntiHooked And Monitored faild\n");
		return TRUE;
	}
	PMDL Mdl;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	EPT_HOOK_USER_PARAM	Param = { 0 };


	PVOID TargetPageVirtualAddress = (PVOID)((UINT64)TargetVirtualAddress & ~0xfff);

	PVOID FakePageVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!FakePageVirtualAddress)
	{
		ShvOsDebugPrint("ExAllocatePoolWithTag faild\n");
		return FALSE;
	}

	PEPROCESS        CsrssProcess = GetCsrssProcess();
	KAPC_STATE State;
	KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

	__try
	{
		RtlCopyMemory(FakePageVirtualAddress, TargetPageVirtualAddress, PAGE_SIZE);
	}
	__except (1)
	{
		KeUnstackDetachProcess(&State);
		ShvOsDebugPrint("ReadProcessMemory faild\n");
		ExFreePool(FakePageVirtualAddress);
		return FALSE;
	}


	KeUnstackDetachProcess(&State);

	//Status = ReadProcessMemory((UINT32)ProcessId, TargetPageVirtualAddress, FakePageVirtualAddress, PAGE_SIZE, NULL);

	//if (!NT_SUCCESS(Status))
	//{
	//	ShvOsDebugPrint("ReadProcessMemory faild\n");
	//	ExFreePool(FakePageVirtualAddress);
	//	return FALSE;
	//}


	Status = Memory::LockMemory(ProcessId, TargetPageVirtualAddress, PAGE_SIZE, &Mdl);
	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("Lock faild\n");
		ExFreePool(FakePageVirtualAddress);
		return FALSE;
	}
	PEPROCESS Process;
	KAPC_STATE ApcState;

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("Get process faild\n");
		ExFreePool(FakePageVirtualAddress);
		return FALSE;
	}

	KeStackAttachProcess(Process, &ApcState);

	UINT64 TargetPagePhysicalAddress = MmGetPhysicalAddress(TargetPageVirtualAddress).QuadPart;
	UINT64 FakePagePhysicalAddress = MmGetPhysicalAddress(FakePageVirtualAddress).QuadPart;

	KAFFINITY AffinityMask;
	for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCallEx((UINT64)VMCALL_USER_EPT_HOOK, TargetPagePhysicalAddress, FakePagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0);
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);

	Param.Type = (UINT64)VMCALL_USER_EPT_HOOK;
	Param.ProcessId = ProcessId;
	Param.TargetVirtualAddress = (UINT64)TargetVirtualAddress;
	Param.TargetPageVirtualAddress = (UINT64)TargetPageVirtualAddress;
	Param.TargetPagePhysicalAddress = TargetPagePhysicalAddress;
	Param.FakePagePhysicalAddress = FakePagePhysicalAddress;
	Param.FakePageVirtualAddress = (UINT64)FakePageVirtualAddress;
	Param.PMdl = Mdl;

	return AddEptHookUserListNode(ProcessId, &Param);
}


BOOLEAN UserHook::MonitorUserPageAccessFreely(UINT64 ProcessId, PVOID TargetVirtualAddress)
{
	if (GetEptHookUserListNode(ProcessId, TargetVirtualAddress, NULL))
	{
		ShvOsDebugPrint("TargetVirtualAddress has been Monitored faild\n");
		return TRUE;
	}
	PVOID TargetPageVirtualAddress = (PVOID)((UINT64)TargetVirtualAddress & ~0xfff);
	PMDL Mdl;
	NTSTATUS Status;
	EPT_HOOK_USER_PARAM	Param = { 0 };
	Status = Memory::LockMemory(ProcessId, TargetPageVirtualAddress, PAGE_SIZE, &Mdl);
	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("Lock faild\n");
		return FALSE;
	}

	PEPROCESS Process;
	KAPC_STATE ApcState;

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("Get process faild\n");
		return FALSE;
	}

	KeStackAttachProcess(Process, &ApcState);
	UINT64 TargetPagePhysicalAddress = MmGetPhysicalAddress(TargetPageVirtualAddress).QuadPart;


	KAFFINITY AffinityMask;
	for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCallEx((UINT64)VMCALL_EPT_CHANGE_PAGE_NO_RW, TargetPagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0, 0);
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);
	Param.Type = (UINT64)VMCALL_EPT_CHANGE_PAGE_NO_RW;
	Param.ProcessId = ProcessId;
	Param.TargetVirtualAddress = (UINT64)TargetVirtualAddress;
	Param.TargetPagePhysicalAddress = TargetPagePhysicalAddress;
	Param.PMdl = Mdl;

	return AddEptHookUserListNode(ProcessId, &Param);
}

BOOLEAN UserHook::HookUser(UINT64 ProcessId, PVOID TargetVirtualAddress)
{

	if (GetEptHookUserListNode(ProcessId, TargetVirtualAddress, NULL))
	{
		ShvOsDebugPrint("TargetVirtualAddress has been hooked faild\n");
		return TRUE;
	}

	PVOID TargetPageVirtualAddress = (PVOID)((UINT64)TargetVirtualAddress & ~0xfff);
	PMDL Mdl;
	NTSTATUS Status;
	EPT_HOOK_USER_PARAM	Param = { 0 };


	PVOID FakePageVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!FakePageVirtualAddress)
	{
		ShvOsDebugPrint("ExAllocatePoolWithTag faild\n");
		return FALSE;
	}

	//这里复制的内容来自我们请求HookUser的进程地址为TargetPageVirtualAddress
	RtlCopyMemory(FakePageVirtualAddress, TargetPageVirtualAddress, PAGE_SIZE);

	PEPROCESS Process;
	KAPC_STATE ApcState;


	Status = Memory::LockMemory(ProcessId, TargetPageVirtualAddress, PAGE_SIZE, &Mdl);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(FakePageVirtualAddress);
		ShvOsDebugPrint("Lock faild\n");
		return FALSE;
	}

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(FakePageVirtualAddress);
		ShvOsDebugPrint("Get process faild\n");
		return FALSE;
	}



	KeStackAttachProcess(Process, &ApcState);
	UINT64 TargetPagePhysicalAddress = MmGetPhysicalAddress(TargetPageVirtualAddress).QuadPart;
	UINT64 FakePagePhysicalAddress = MmGetPhysicalAddress(FakePageVirtualAddress).QuadPart;

	KAFFINITY AffinityMask;
	for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCallEx((UINT64)VMCALL_USER_EPT_HOOK, TargetPagePhysicalAddress, FakePagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0);
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);

	Param.Type = (UINT64)VMCALL_USER_EPT_HOOK;
	Param.ProcessId = ProcessId;
	Param.TargetVirtualAddress = (UINT64)TargetVirtualAddress;
	Param.TargetPageVirtualAddress = (UINT64)TargetPageVirtualAddress;
	Param.TargetPagePhysicalAddress = TargetPagePhysicalAddress;
	Param.FakePagePhysicalAddress = FakePagePhysicalAddress;
	Param.FakePageVirtualAddress = (UINT64)FakePageVirtualAddress;
	Param.PMdl = Mdl;

	return AddEptHookUserListNode(ProcessId, &Param);
}


BOOLEAN UserHook::UserEptBreakPoint(UINT64 ProcessId, PVOID TargetVirtualAddress, SIZE_T TargetVirtualAddressInstructionLength, INT32 RegisterIndex, PBREAKPOINT_FILTER_DATA PFilterData)
{
	if (!TargetVirtualAddress || !TargetVirtualAddressInstructionLength || !PFilterData)
	{
		ShvOsDebugPrint("UserEptBreakPoint TargetVirtualAddress  PFilterData Or TargetVirtualAddressInstructionLength Is NULL\n");
		return FALSE;
	}

	BREAKPOINT_FILTER_DATA FilterData = { 0 };
	RtlCopyMemory(&FilterData, PFilterData, sizeof(BREAKPOINT_FILTER_DATA));

	EPT_HOOK_USER_PARAM EptBreakPointInfo = { 0 };
	PVOID TargetVirtualAddressPageOffset = (PVOID)((UINT64)TargetVirtualAddress & 0xfff);
	UCHAR BreakPoint = 0xCC;
	PEPROCESS Process;
	NTSTATUS Status;
	KAPC_STATE ApcState = { 0 };

	//检查同一页内是否存在BreakPoint的信息，如果有则直接操作FakePageVirtualAddress
	//如果没有则申请FakePageVirtualAddress
	if (IsExistUserEptBreakPint(ProcessId, TargetVirtualAddress, &EptBreakPointInfo))
	{
		ShvOsDebugPrint("EptBreakPoint Same Page Or Exist Hookd Data\n");
		// 获取被HOOK的进程结构体，用于附加
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
		if (!NT_SUCCESS(Status))
		{
			ShvOsDebugPrint("Get process faild\n");
			return FALSE;
		}

		KeStackAttachProcess(Process, &ApcState);

		RtlCopyMemory(PVOID(EptBreakPointInfo.FakePageVirtualAddress + (UINT64)TargetVirtualAddressPageOffset), &BreakPoint, sizeof(UCHAR));

		KAFFINITY AffinityMask;
		for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
		{
			AffinityMask = MathPower(2, (int)i);
			KeSetSystemAffinityThread(AffinityMask);
			ShvVmCallEx((UINT64)VMCALL_USER_EPT_BREAKPOINT_HOOK, ProcessId, (UINT64)TargetVirtualAddress, EptBreakPointInfo.TargetPagePhysicalAddress, EptBreakPointInfo.FakePagePhysicalAddress, TargetVirtualAddressInstructionLength, RegisterIndex, (UINT64)&FilterData, 0, 0);
		}

		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(Process);
		return TRUE;
	}


	PVOID TargetPageVirtualAddress = (PVOID)((UINT64)TargetVirtualAddress & ~0xfff);
	PMDL Mdl;

	PVOID FakePageVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!FakePageVirtualAddress)
	{
		ShvOsDebugPrint("ExAllocatePoolWithTag faild\n");
		return FALSE;
	}

	Status = Memory::LockMemory(ProcessId, TargetPageVirtualAddress, PAGE_SIZE, &Mdl);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(FakePageVirtualAddress);
		ShvOsDebugPrint("Lock faild\n");
		return FALSE;
	}

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(FakePageVirtualAddress);
		ShvOsDebugPrint("Get process faild\n");
		return FALSE;
	}

	KeStackAttachProcess(Process, &ApcState);

	RtlCopyMemory(FakePageVirtualAddress, TargetPageVirtualAddress, PAGE_SIZE);
	RtlCopyMemory(PVOID((UINT64)FakePageVirtualAddress + (UINT64)TargetVirtualAddressPageOffset), &BreakPoint, sizeof(UCHAR));

	UINT64 TargetPagePhysicalAddress = MmGetPhysicalAddress(TargetPageVirtualAddress).QuadPart;
	UINT64 FakePagePhysicalAddress = MmGetPhysicalAddress(FakePageVirtualAddress).QuadPart;

	KAFFINITY AffinityMask;
	for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCallEx((UINT64)VMCALL_USER_EPT_BREAKPOINT_HOOK, ProcessId, (UINT64)TargetVirtualAddress, TargetPagePhysicalAddress, FakePagePhysicalAddress, TargetVirtualAddressInstructionLength, RegisterIndex, (UINT64)&FilterData, 0, 0);
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);

	EPT_HOOK_USER_PARAM	Param = { 0 };
	Param.Type = (UINT64)VMCALL_USER_EPT_HOOK;
	Param.ProcessId = ProcessId;
	Param.TargetVirtualAddress = (UINT64)TargetVirtualAddress;
	Param.TargetPageVirtualAddress = (UINT64)TargetPageVirtualAddress;
	Param.TargetPagePhysicalAddress = TargetPagePhysicalAddress;
	Param.FakePagePhysicalAddress = FakePagePhysicalAddress;
	Param.FakePageVirtualAddress = (UINT64)FakePageVirtualAddress;
	Param.PMdl = Mdl;

	return AddEptHookUserListNode(ProcessId, &Param);
}

BOOLEAN UserHook::UserEptUnBreakPoint(UINT64 ProcessId, PVOID TargetVirtualAddress, UCHAR OldValue)
{
	EPT_HOOK_USER_PARAM EptBreakPointInfo = { 0 };
	PVOID TargetVirtualAddressPageOffset = (PVOID)((UINT64)TargetVirtualAddress & 0xfff);

	PEPROCESS Process;
	NTSTATUS Status;
	KAPC_STATE ApcState = { 0 };
	if (IsExistUserEptBreakPint(ProcessId, TargetVirtualAddress, &EptBreakPointInfo))
	{
		// 获取被HOOK的进程结构体，用于附加
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
		if (!NT_SUCCESS(Status))
		{
			ShvOsDebugPrint("UserEptUnBreakPoint Get process faild\n");
			return FALSE;
		}

		KeStackAttachProcess(Process, &ApcState);

		RtlCopyMemory(PVOID((UINT64)EptBreakPointInfo.FakePageVirtualAddress + (UINT64)TargetVirtualAddressPageOffset), &OldValue, sizeof(UCHAR));

		KAFFINITY AffinityMask;
		for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
		{
			AffinityMask = MathPower(2, (int)i);
			KeSetSystemAffinityThread(AffinityMask);
			ShvVmCallEx((UINT64)VMCALL_INVEPT_CONTEXT, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		}

		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(Process);
		return TRUE;
	}
	else
	{
		ShvOsDebugPrint("UserEptUnBreakPoint Faild\n");
		return FALSE;
	}
}


BOOLEAN UserHook::UnHookUser(UINT64 ProcessId, PVOID TargetVirtualAddress)
{
	NTSTATUS Status;
	EPT_HOOK_USER_PARAM Param = { 0 };
	if (!GetEptHookUserListNode(ProcessId, TargetVirtualAddress, &Param))
	{
		ShvOsDebugPrint("UnHookUser GetEptHookUserList Can't Find TargetVirtualAddress\n");
		return FALSE;
	}

	PEPROCESS Process;
	KAPC_STATE ApcState;

	// 获取被HOOK的进程结构体，用于附加
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);

	if (!NT_SUCCESS(Status))
	{
		ShvOsDebugPrint("UnHookUser Get process faild\n");
		return FALSE;
	}

	KeStackAttachProcess(Process, &ApcState);

	UINT64 TargetPagePhysicalAddress = Param.TargetPagePhysicalAddress;
	UINT64 FakePagePhysicalAddress = Param.FakePagePhysicalAddress;

	KAFFINITY AffinityMask;
	for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);

		if (Param.Type == (UINT64)VMCALL_USER_EPT_HOOK)
			ShvVmCallEx((UINT64)VMCALL_USER_EPT_HOOK, FakePagePhysicalAddress, TargetPagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0);

		if (Param.Type == (UINT64)VMCALL_EPT_CHANGE_PAGE_NO_RW)
			ShvVmCallEx((UINT64)VMCALL_EPT_RECOVER_PAGE_ATTRIBUTE, TargetPagePhysicalAddress, 0, 0, 0, 0, 0, 0, 0, 0);
	}
	Memory::UnlockMemory(Param.PMdl);

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);

	if (Param.FakePageVirtualAddress)
		ExFreePool((PVOID)Param.FakePageVirtualAddress);

	RemoveEptHookUserListNode(Param.ProcessId, (PVOID)Param.TargetVirtualAddress);
	return TRUE;
}