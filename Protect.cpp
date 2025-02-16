#include "Protect.h"
#include "Utils.h"


typedef struct _PROCESSID_AND_THREADID_LIST
{
	LIST_ENTRY ProcessIdAndThreadIdListEntry;
	CLIENT_ID ClientId;
}PROCESSID_AND_THREADID_LIST, * PPROCESSID_AND_THREADID_LIST;

LIST_ENTRY Protect::ProcessIdAndThreadIdListHead = { 0 };
KSPIN_LOCK Protect::ProcessIdAndThreadIdListLock = { 0 };

VOID Protect::Initialize()
{
	KeInitializeSpinLock(&Protect::ProcessIdAndThreadIdListLock);
	InitializeListHead(&Protect::ProcessIdAndThreadIdListHead);
}

VOID Protect::Destory()
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Protect::ProcessIdAndThreadIdListHead;
	while (&Protect::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		RemoveEntryList(&PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
		ExFreePool(PProcessIdAndThreadIdList);
	}
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
}


BOOLEAN Protect::AddProcessId(UINT64 ProcessId)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = (PPROCESSID_AND_THREADID_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSID_AND_THREADID_LIST), POOLTAG);
	if (!PProcessIdAndThreadIdList)
	{
		KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
		return FALSE;
	}
	RtlZeroMemory(PProcessIdAndThreadIdList, sizeof(PROCESSID_AND_THREADID_LIST));

	PProcessIdAndThreadIdList->ClientId.UniqueProcess = (HANDLE)ProcessId;
	InsertHeadList(&ProcessIdAndThreadIdListHead, &PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return TRUE;
}

BOOLEAN Protect::AddThreadId(UINT64 ThreadId)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = (PPROCESSID_AND_THREADID_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSID_AND_THREADID_LIST), POOLTAG);
	if (!PProcessIdAndThreadIdList)
	{
		KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
		return FALSE;
	}
	RtlZeroMemory(PProcessIdAndThreadIdList, sizeof(PROCESSID_AND_THREADID_LIST));

	PProcessIdAndThreadIdList->ClientId.UniqueThread = (HANDLE)ThreadId;
	InsertHeadList(&ProcessIdAndThreadIdListHead, &PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return TRUE;
}

BOOLEAN Protect::AddProcessIdAndThreadId(CLIENT_ID ClientId)
{
	//ShvOsDebugPrint("Protect GetProcessIdAndThreadIdListNodeCount:[%d]\n", GetProcessIdAndThreadIdListNodeCount());

	if (ClientId.UniqueProcess && !IsExistProcessId((UINT64)ClientId.UniqueProcess))
	{
		return AddProcessId((UINT64)ClientId.UniqueProcess);
	}

	if (ClientId.UniqueThread && !IsExistThreadId((UINT64)ClientId.UniqueThread))
	{
		return AddThreadId((UINT64)ClientId.UniqueThread);
	}

	return FALSE;
}

BOOLEAN Protect::IsExistProcessId(UINT64 ProcessId)
{

	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Protect::ProcessIdAndThreadIdListHead;
	while (&Protect::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueProcess == (HANDLE)ProcessId)
		{
			KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Protect::IsExistThreadId(UINT64 ThreadId)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Protect::ProcessIdAndThreadIdListHead;
	while (&Protect::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueThread == (HANDLE)ThreadId)
		{
			KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Protect::RemoveProcessIdAndThreadId(CLIENT_ID ClientId)
{
	if (ClientId.UniqueProcess)
		return RemoveProcessId((UINT64)ClientId.UniqueProcess);
	else if (ClientId.UniqueThread)
		return RemoveThreadId((UINT64)ClientId.UniqueThread);
	return FALSE;
}



BOOLEAN Protect::RemoveProcessId(UINT64 ProcessId)
{
	//ShvOsDebugPrint("GetProcessIdAndThreadIdListNodeCount:[%d]\n", GetProcessIdAndThreadIdListNodeCount());
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Protect::ProcessIdAndThreadIdListHead;
	while (&Protect::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueProcess == (HANDLE)ProcessId)
		{
			RemoveEntryList(&PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
			ExFreePool(PProcessIdAndThreadIdList);
			KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Protect::RemoveThreadId(UINT64 ThreadId)
{
	//ShvOsDebugPrint("GetProcessIdAndThreadIdListNodeCount:[%d]\n", GetProcessIdAndThreadIdListNodeCount());
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Protect::ProcessIdAndThreadIdListHead;
	while (&Protect::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueThread == (HANDLE)ThreadId)
		{
			RemoveEntryList(&PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
			ExFreePool(PProcessIdAndThreadIdList);
			KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

UINT64 Protect::GetProcessIdAndThreadIdListNodeCount()
{
	UINT64 Count = 0;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Protect::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Protect::ProcessIdAndThreadIdListHead;
	while (&Protect::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		Count++;
	}
	KeReleaseSpinLock(&Protect::ProcessIdAndThreadIdListLock, OldIrql);
	return Count;
}
