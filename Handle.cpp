#include "Handle.h"
#include "Utils.h"
typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;
	LONG ExtraInfoPages;
	UINT64 TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG UniqueProcessId;
	ULONG Flags;
	EX_PUSH_LOCK HandleContentionEvent;
	EX_PUSH_LOCK HandleTableLock;
	// More fields here...
} HANDLE_TABLE, * PHANDLE_TABLE;
typedef union _EXHANDLE
{
	struct
	{
		ULONG TagBits : 2;
		ULONG Index : 30;
	} u;
	PVOID GenericHandleOverlay;
	UINT64 Value;
} EXHANDLE, * PEXHANDLE;

typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
	union
	{
		UINT64 VolatileLowValue; // Size=8 Offset=0
		UINT64 LowValue; // Size=8 Offset=0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
		struct
		{
			UINT64 Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
			UINT64 RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
			UINT64 Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
			UINT64 ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
		};
	};
	union
	{
		UINT64 HighValue; // Size=8 Offset=8
		struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
		union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
		struct
		{
			ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
			ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
			ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
		};
	};
	ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;


typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);
EXTERN_C BOOLEAN NTAPI ExEnumHandleTable(
	IN PHANDLE_TABLE HandleTable,
	IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	IN PVOID EnumParameter,
	OUT PHANDLE Handle);

EXTERN_C VOID FASTCALL ExfUnblockPushLock(
	IN OUT PEX_PUSH_LOCK PushLock,
	IN OUT PVOID WaitBlock
);



UCHAR HandleCallback(
	PHANDLE_TABLE HandleTable,
	PHANDLE_TABLE_ENTRY HandleTableEntry,
	HANDLE Handle,
	PVOID EnumParameter)
{
#define ExpIsValidObjectEntry(Entry) ( (Entry) && (Entry->LowValue != 0) && (Entry->HighValue != -2) )

	UCHAR Result = 0;
	if (MmIsAddressValid(EnumParameter))
	{

		PHANDLE_INFORMATION Info = (PHANDLE_INFORMATION)EnumParameter;

		if (Info->Handle == (UINT64)Handle)
		{

			if (MmIsAddressValid(HandleTableEntry))
				if (ExpIsValidObjectEntry(HandleTableEntry))
					if (HandleTableEntry->GrantedAccessBits != Info->Access)
					{
						//DbgPrintEx(0, 0, "[%s] process %ld handle 0x%llx access 0x%lx -> 0x%lx \n",__FUNCTION__, Info->ProcessId, Info->Handle, HandleTableEntry->GrantedAccessBits, Info->Access);
						//ShvOsDebugPrint("process %ld handle 0x%llx access 0x%lx -> 0x%lx \n", Info->ProcessId, Info->Handle, HandleTableEntry->GrantedAccessBits, Info->Access);

						HandleTableEntry->GrantedAccessBits = Info->Access;
						Result = 1;
					}
		}

	}

	if (HandleTableEntry) _InterlockedExchangeAdd8((PCHAR)&HandleTableEntry->VolatileLowValue, 1);
	if (HandleTable && HandleTable->HandleContentionEvent) ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);

	return Result;
}

typedef struct _PROCESSID_AND_THREADID_LIST
{
	LIST_ENTRY ProcessIdAndThreadIdListEntry;
	CLIENT_ID ClientId;
	PVOID PObject;
	INT32 Times;
}PROCESSID_AND_THREADID_LIST, * PPROCESSID_AND_THREADID_LIST;

LIST_ENTRY Handle::ProcessIdAndThreadIdListHead = { 0 };
KSPIN_LOCK Handle::ProcessIdAndThreadIdListLock = { 0 };

VOID Handle::Initialize()
{
	KeInitializeSpinLock(&Handle::ProcessIdAndThreadIdListLock);
	InitializeListHead(&Handle::ProcessIdAndThreadIdListHead);
}

VOID Handle::Destory()
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		RemoveEntryList(&PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
		ExFreePool(PProcessIdAndThreadIdList);
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
}


VOID Handle::HandleGrantAccess(HANDLE_INFORMATION HandleInfo)
{

	PEPROCESS PProcess = 0;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)HandleInfo.ClientId.UniqueProcess, &PProcess);
	if (NT_SUCCESS(Status))
	{

		// Win10 1909的句柄表偏移为0x418,如果换了系统请修改,不然一个大蓝屏马上出现你眼前
		PHANDLE_TABLE PObjectTable = *(PHANDLE_TABLE*)((UINT64)PProcess + GlobalConfig::Instance().ObjectTable);
		if (MmIsAddressValid(PObjectTable)) ExEnumHandleTable(PObjectTable, &HandleCallback, &HandleInfo, NULL);

		ObDereferenceObject(PProcess);
	}

}



BOOLEAN Handle::AddProcessIdAndThreadId(CLIENT_ID ClientId)
{
	//ShvOsDebugPrint("GetProcessIdAndThreadIdListNodeCount:[%d]\n", GetProcessIdAndThreadIdListNodeCount());
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = (PPROCESSID_AND_THREADID_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSID_AND_THREADID_LIST), POOLTAG);
	if (!PProcessIdAndThreadIdList)
	{
		KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
		return FALSE;
	}
	RtlZeroMemory(PProcessIdAndThreadIdList, sizeof(PROCESSID_AND_THREADID_LIST));

	PProcessIdAndThreadIdList->ClientId.UniqueProcess = ClientId.UniqueProcess;
	PProcessIdAndThreadIdList->ClientId.UniqueThread = ClientId.UniqueThread;
	PProcessIdAndThreadIdList->PObject = NULL;
	InsertHeadList(&ProcessIdAndThreadIdListHead, &PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return TRUE;
}

BOOLEAN Handle::AddObjectByProcessId(HANDLE ProcessId, PVOID PObject)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueProcess == ProcessId)
		{
			PProcessIdAndThreadIdList->PObject = PObject;
			PProcessIdAndThreadIdList->Times++;
			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Handle::AddObjectByThreadId(HANDLE ThreadId, PVOID PObject)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueThread == ThreadId)
		{
			PProcessIdAndThreadIdList->PObject = PObject;
			PProcessIdAndThreadIdList->Times++;
			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Handle::IsExistProcessId(UINT64 ProcessId)
{

	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueProcess == (HANDLE)ProcessId)
		{
			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Handle::IsExistThreadId(UINT64 ThreadId)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueThread == (HANDLE)ThreadId)
		{
			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Handle::ISExistObject(PVOID PObject)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->PObject && PProcessIdAndThreadIdList->PObject == PObject)
		{
			PProcessIdAndThreadIdList->Times--;
			if (PProcessIdAndThreadIdList->Times == 0)
				PProcessIdAndThreadIdList->PObject = NULL;

			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Handle::RemoveProcessIdAndThreadId(CLIENT_ID ClientId)
{
	if (ClientId.UniqueProcess)
		return RemoveProcessId((UINT64)ClientId.UniqueProcess);
	else if (ClientId.UniqueThread)
		return RemoveThreadId((UINT64)ClientId.UniqueThread);
	return FALSE;
}

BOOLEAN Handle::RemoveProcessId(UINT64 ProcessId)
{
	//ShvOsDebugPrint("GetProcessIdAndThreadIdListNodeCount:[%d]\n", GetProcessIdAndThreadIdListNodeCount());
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueProcess == (HANDLE)ProcessId)
		{
			RemoveEntryList(&PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
			ExFreePool(PProcessIdAndThreadIdList);
			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

BOOLEAN Handle::RemoveThreadId(UINT64 ThreadId)
{
	//ShvOsDebugPrint("GetProcessIdAndThreadIdListNodeCount:[%d]\n", GetProcessIdAndThreadIdListNodeCount());
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		PPROCESSID_AND_THREADID_LIST PProcessIdAndThreadIdList = CONTAINING_RECORD(Current, PROCESSID_AND_THREADID_LIST, ProcessIdAndThreadIdListEntry);
		if (PProcessIdAndThreadIdList && PProcessIdAndThreadIdList->ClientId.UniqueThread == (HANDLE)ThreadId)
		{
			RemoveEntryList(&PProcessIdAndThreadIdList->ProcessIdAndThreadIdListEntry);
			ExFreePool(PProcessIdAndThreadIdList);
			KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return FALSE;
}

UINT64 Handle::GetProcessIdAndThreadIdListNodeCount()
{
	UINT64 Count = 0;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&Handle::ProcessIdAndThreadIdListLock, &OldIrql);

	PLIST_ENTRY Current = &Handle::ProcessIdAndThreadIdListHead;
	while (&Handle::ProcessIdAndThreadIdListHead != Current->Flink)
	{
		Current = Current->Flink;
		Count++;
	}
	KeReleaseSpinLock(&Handle::ProcessIdAndThreadIdListLock, OldIrql);
	return Count;
}
