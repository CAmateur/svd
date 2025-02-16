#include "DebugSystem.h"
#include "EptHook.h"
#include "UserHook.h"
#include<ntimage.h>
#include<ntstrsafe.h>
#include "Handle.h"
#include "Protect.h"
#include "CallBack.h"
VOID ShvOsDebugPrint(_In_ PCCH Format, ...);


// 静态成员变量定义
VOID(NTAPI* DebugSystem::OriginalKiDispatchException)(PEXCEPTION_RECORD, PKEXCEPTION_FRAME, PKTRAP_FRAME, KPROCESSOR_MODE, BOOLEAN) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalNtCreateDebugObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalNtDebugActiveProcess)(HANDLE, HANDLE) = nullptr;
VOID(NTAPI* DebugSystem::OriginalDbgkCreateThread)(PETHREAD) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalDbgkExitThread)(NTSTATUS) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalDbgkExitProcess)(NTSTATUS) = nullptr;
VOID(NTAPI* DebugSystem::OriginalDbgkMapViewOfSection)(PEPROCESS, PVOID, PVOID) = nullptr;
VOID(NTAPI* DebugSystem::OriginalDbgkUnMapViewOfSection)(PEPROCESS, PVOID) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalNtWaitForDebugEvent)(HANDLE, BOOLEAN, PLARGE_INTEGER, PDBGUI_WAIT_STATE_CHANGE) = nullptr;
VOID(NTAPI* DebugSystem::OriginalDbgkpCloseObject)(PEPROCESS, PVOID, ULONG_PTR, ULONG_PTR) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalNtDebugContinue)(HANDLE, PCLIENT_ID, NTSTATUS) = nullptr;
BOOLEAN(NTAPI* DebugSystem::OriginalDbgkForwardException)(PEXCEPTION_RECORD, BOOLEAN, BOOLEAN) = nullptr;
VOID(NTAPI* DebugSystem::OriginalDbgkpMarkProcessPeb)(PEPROCESS) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalNtTerminateProcess)(HANDLE, NTSTATUS) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalNtTerminateThread)(HANDLE, NTSTATUS) = nullptr;
NTSTATUS(NTAPI* DebugSystem::OriginalObpReferenceObjectByHandleWithTag)(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, PVOID UnKnown) = nullptr;
LONG_PTR(FASTCALL* DebugSystem::OriginalObfDereferenceObjectWithTag)(PVOID Object, ULONG Tag) = nullptr;


POBJECT_TYPE DebugSystem::DbgkDebugObjectType = nullptr;
FAST_MUTEX DebugSystem::DbgkpProcessDebugPortMutex = { 0 };
LIST_ENTRY DebugSystem::DebugStateListHead = { 0 };
KSPIN_LOCK DebugSystem::DebugStateListLock = { 0 };

EXTERN_C VOID PsSetProcessFaultInformation(
	IN PEPROCESS Process,
	PULONG64 arg2
);

EXTERN_C PPEB PsGetProcessPeb(IN PEPROCESS);

EXTERN_C NTSTATUS PsReferenceProcessFilePointer(
	IN PEPROCESS PROCESS,
	OUT PFILE_OBJECT* FileObject
);
EXTERN_C NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID* Object
);

EXTERN_C VOID ZwFlushInstructionCache(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in SIZE_T Length
);

EXTERN_C PIMAGE_NT_HEADERS RtlImageNtHeader(
	PVOID Base
);
EXTERN_C BOOLEAN KeIsAttachedProcess();

FORCEINLINE
VOID
ProbeForWriteHandle(
	IN PHANDLE Address
)

{

	if (Address >= (HANDLE* const)MM_USER_PROBE_ADDRESS) {
		Address = (HANDLE* const)MM_USER_PROBE_ADDRESS;
	}

	*((volatile HANDLE*)Address) = *Address;
	return;
}
int ExSystemExceptionFilter()
{
	return(ExGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH
		);
}
VOID NewDbgkpDeleteProcedure(PVOID)
{
	return;
}

VOID NTAPI DebugSystem::NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance)
{
	if (PreviousMode != KernelMode)
	{

		HANDLE Pid = PsGetCurrentProcessId();
		if (DebugSystem::GetStateByDebugeePid((UINT64)Pid, NULL))
		{

			//if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
			//{
			//	switch (ExceptionRecord->ExceptionCode)
			//	{
			//	case STATUS_BREAKPOINT:
			//		ExceptionRecord->ExceptionCode = STATUS_WX86_BREAKPOINT;
			//		break;
			//	case STATUS_SINGLE_STEP:
			//		ExceptionRecord->ExceptionCode = STATUS_WX86_SINGLE_STEP;
			//		break;
			//	}
			//}

			//User
			if (NewDbgkForwardException(ExceptionRecord, TRUE, FALSE))
			{
				////int 2d 不返回，直接下发异常到异常处理
				//if (*(PUSHORT)((ULONG64)(TrapFrame->Rip) - 3) != 0x2DCD)//int 2d
				//	return;
				return;
			}

			//if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
			//{
			//	switch (ExceptionRecord->ExceptionCode)
			//	{
			//	case STATUS_WX86_BREAKPOINT:
			//		ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
			//		break;
			//	case STATUS_WX86_SINGLE_STEP:
			//		ExceptionRecord->ExceptionCode = STATUS_SINGLE_STEP;
			//		break;
			//	}
			//}
		}

	}
	return OriginalKiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);

}

NTSTATUS DebugSystem::NewNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus)
{


	PETHREAD PThread = NULL;
	if (ThreadHandle)
	{
		ObReferenceObjectByHandle(ThreadHandle,
			PROCESS_TERMINATE,
			*PsThreadType,
			ExGetPreviousMode(),
			(PVOID*)&PThread,
			NULL);
	}
	else
	{
		PThread = PsGetCurrentThread();
	}
	if (PThread)
	{

		UINT64 Tid = (UINT64)PsGetThreadId(PThread);

		while (Handle::IsExistThreadId(Tid))
		{
			Handle::RemoveThreadId(Tid);
		}

		while (Protect::IsExistThreadId(Tid))
		{
			Protect::RemoveThreadId(Tid);
		}

		if (ThreadHandle)
			ObDereferenceObject(PThread);
	}
	return OriginalNtTerminateThread(ThreadHandle, ExitStatus);
}
LONG_PTR FASTCALL DebugSystem::NewObfDereferenceObjectWithTag(PVOID Object, ULONG Tag)
{
	if (Handle::ISExistObject(Object))
		return NULL;

	return OriginalObfDereferenceObjectWithTag(Object, Tag);
}
NTSTATUS DebugSystem::NewObpReferenceObjectByHandleWithTag(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, PVOID UnKnown)
{
	NTSTATUS Status;
	//我们hook的ce函数魔改了OpenProcess，因此这个Handle有可能是Pid，因此首先要
	//查询这个Handle是否在我们的链表中
	//if (ObjectType == *PsProcessType && Handle::IsExistProcessId((UINT64)Handle & 0x7FFFFFFFFFFFFFFF))
	//{
	//	PEPROCESS Process;
	//	Status = PsLookupProcessByProcessId((HANDLE)((UINT64)Handle & 0x7FFFFFFFFFFFFFFF), &Process);
	//	if (!NT_SUCCESS(Status))
	//		return Status;
	//	*Object = Process;
	//	return Status;
	//}
	//else if (ObjectType == *PsThreadType && Handle::IsExistThreadId((UINT64)Handle))
	//{
	//	//我们hook的ce函数魔改了OpenThread，因此这个Handle有可能是Tid，因此首先要
	//	//查询这个Handle是否在我们的链表中
	//	PETHREAD Thread = NULL;
	//	Status = PsLookupThreadByThreadId((HANDLE)Handle, &Thread);
	//	if (!NT_SUCCESS(Status))
	//		return Status;
	//	*Object = Thread;
	//	return Status;
	//}


	if (ObjectType == *PsProcessType && Handle::IsExistProcessId((UINT64)Handle & 0x7FFFFFFFFFFFFFFF))
	{
		HANDLE ProcessId = (HANDLE)((UINT64)Handle & 0x7FFFFFFFFFFFFFFF);
		PEPROCESS Process = GetProcessById(ProcessId);
		if (!Process)
		{
			*Object = Process;
			return STATUS_UNSUCCESSFUL;
		}

		Handle::AddObjectByProcessId(ProcessId, (PVOID)Process);
		*Object = Process;
		return STATUS_SUCCESS;
	}
	//else if (ObjectType == *PsThreadType && Handle::IsExistThreadId((UINT64)Handle))
	//{
	//	PETHREAD Thread = GetThreadByTid(Handle);
	//	if (!Thread)
	//	{
	//		*Object = Thread;
	//		ShvOsDebugPrint("NewObpReferenceObjectByHandleWithTag Thread is NULL\n");
	//		return STATUS_UNSUCCESSFUL;
	//	}
	//	Handle::AddObjectByThreadId(Handle, Thread);
	//	return STATUS_SUCCESS;
	//}
	else if (ObjectType == *PsThreadType && Handle::IsExistThreadId((UINT64)Handle))
	{
		//我们hook的ce函数魔改了OpenThread，因此这个Handle有可能是Tid，因此首先要
		//查询这个Handle是否在我们的链表中
		PETHREAD Thread = NULL;
		Status = PsLookupThreadByThreadId((HANDLE)Handle, &Thread);
		if (!NT_SUCCESS(Status))
			return Status;
		*Object = Thread;
		return Status;
	}

	Status = OriginalObpReferenceObjectByHandleWithTag(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, UnKnown);

	HANDLE CurrentProcessId = PsGetProcessId(PsGetCurrentProcess());
	if (Protect::IsExistProcessId((UINT64)CurrentProcessId))
	{
		return Status;
	}

	if (ObjectType == *PsProcessType && Object && *Object && Protect::IsExistProcessId((UINT64)PsGetProcessId((PEPROCESS)(*Object))))
	{
		*Object = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	if (ObjectType == *PsThreadType && Object && *Object && Protect::IsExistThreadId((UINT64)PsGetThreadId((PETHREAD)(*Object))))
	{
		*Object = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	return Status;
}
INT64 DebugSystem::NewDbgkpSuppressDbgMsg(PVOID Teb)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpSuppressDbgMsg\n");
#else

#endif 
	PVOID v1; // rdx
	PEWOW64PROCESS v2; // rcx
	INT64 v5; // [rsp+0h] [rbp-18h]

	UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(KeGetCurrentThread());
	//PEPROCESS Process = KeGetCurrentThread()->ApcState.Process;
	PEPROCESS Process = (PEPROCESS)*ApcStateProcessAddress;

	v1 = Teb;
	v5 = 0;
	UINT64* SameTebFlagsAddress = GetSameTebFlagsAddress(Teb);
	if (SLOBYTE(*(UINT16*)SameTebFlagsAddress) >= 0)
	{
		UINT64* WoW64ProcessAddress = GetWoW64ProcessAddress(Process);
		if (*WoW64ProcessAddress)
		{
			v2 = (PEWOW64PROCESS)*WoW64ProcessAddress;
			if (v2)
			{
				UINT64* MachineAddress = GetMachineAddress(Process);
				USHORT Machine = *(USHORT*)MachineAddress;
				if (Machine == 0x14C || Machine == 0x1C4)
					v5 = *((char*)Teb + 0x2FCA) < 0;
			}
		}
	}
	else
	{
		v5 = 1;
}
	return v5;
}
NTSTATUS DebugSystem::NewDbgkpPostModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpPostModuleMessages\n");
#else

#endif 
	PPEB Peb = *(PPEB*)GetPebAddress(Process);
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY LdrHead, LdrNext;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DBGKM_APIMSG ApiMsg;
	ULONG i;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING Name;
	PIMAGE_NT_HEADERS NtHeaders;
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	if (Peb == NULL) {
		return STATUS_SUCCESS;
	}

	__try {
		Ldr = Peb->Ldr;

		LdrHead = &Ldr->InLoadOrderModuleList;

		ProbeForRead(LdrHead, sizeof(LIST_ENTRY), sizeof(UCHAR));
		for (LdrNext = LdrHead->Flink, i = 0;
			LdrNext != LdrHead && i < 500;	// DbgkpMaxModuleMsgs ->500<-
			LdrNext = LdrNext->Flink, i++) {

			//
			// First image got send with process create message
			//
			if (i > 0) {
				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				LdrEntry = CONTAINING_RECORD(LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForRead(LdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(UCHAR));

				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;
				ApiMsg.u.LoadDll.NamePointer = NULL;

				ProbeForRead(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

				NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders) {
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}

				FnMmGetFileNameForAddress MmGetFileNameForAddress = (FnMmGetFileNameForAddress)GlobalConfig::Instance().MmGetFileNameForAddress;
				Status = MmGetFileNameForAddress(NtHeaders, &Name);

				if (NT_SUCCESS(Status)) {
					InitializeObjectAttributes(&oa,
						&Name,
						OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						NULL,
						NULL);

					Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
						GENERIC_READ | SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_SYNCHRONOUS_IO_NONALERT);

					if (!NT_SUCCESS(Status)) {
						ApiMsg.u.LoadDll.FileHandle = NULL;
					}
					ExFreePool(Name.Buffer);
				}

				if (DebugObject)
				{
					Status = NewDbgkpQueueMessage(
						Process,
						Thread,
						&ApiMsg,
						DEBUG_EVENT_NOWAIT,
						DebugObject);
				}
				else
				{
					NewDbgkpSendApiMessage(
						Process,
						DEBUG_EVENT_READ | DEBUG_EVENT_NOWAIT,
						&ApiMsg);

					Status = STATUS_UNSUCCESSFUL;
				}

				if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
					ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
				}

			}
			ProbeForRead(LdrNext, sizeof(LIST_ENTRY), sizeof(UCHAR));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	}

#if defined(_WIN64)
	UINT64* WoW64ProcessAddress = GetWoW64ProcessAddress(Process);
	UINT64* WoW64ProcessPebAddress = GetWoW64ProcessPebAddress((PEWOW64PROCESS)*WoW64ProcessAddress);
	if (*WoW64ProcessAddress != NULL && *WoW64ProcessPebAddress != NULL) {
		PPEB32 Peb32;
		PPEB_LDR_DATA32 Ldr32;
		PLIST_ENTRY32 LdrHead32, LdrNext32;
		PLDR_DATA_TABLE_ENTRY32 LdrEntry32;
		//PWCHAR pSys;

		Peb32 = (PPEB32)*WoW64ProcessPebAddress;

		__try {
			Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);

			LdrHead32 = (PLIST_ENTRY32)&Ldr32->InLoadOrderModuleList;

			ProbeForRead(LdrHead32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink), i = 0;
				LdrNext32 != LdrHead32 && i < 500;
				LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink), i++) {

				if (i > 0) {
					RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

					LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					ProbeForRead(LdrEntry32, sizeof(LDR_DATA_TABLE_ENTRY32), sizeof(UCHAR));

					ApiMsg.ApiNumber = DbgKmLoadDllApi;
					ApiMsg.u.LoadDll.BaseOfDll = (PVOID)UlongToPtr(LdrEntry32->DllBase);
					ApiMsg.u.LoadDll.NamePointer = NULL;

					ProbeForRead(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

					NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
					if (NtHeaders) {
						ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
						ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
					}

					FnMmGetFileNameForAddress MmGetFileNameForAddress = (FnMmGetFileNameForAddress)GlobalConfig::Instance().MmGetFileNameForAddress;
					Status = MmGetFileNameForAddress(NtHeaders, &Name);

					if (NT_SUCCESS(Status)) {

						InitializeObjectAttributes(&oa,
							&Name,
							OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							NULL,
							NULL);

						Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
							GENERIC_READ | SYNCHRONIZE,
							&oa,
							&iosb,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							FILE_SYNCHRONOUS_IO_NONALERT);

						if (!NT_SUCCESS(Status)) {
							ApiMsg.u.LoadDll.FileHandle = NULL;
						}
						ExFreePool(Name.Buffer);
					}

					if (DebugObject)
					{
						Status = NewDbgkpQueueMessage(Process,
							Thread,
							&ApiMsg,
							DEBUG_EVENT_NOWAIT,
							DebugObject);
					}
					else
					{
						NewDbgkpSendApiMessage(
							Process,
							DEBUG_EVENT_READ | DEBUG_EVENT_NOWAIT,
							&ApiMsg);

						Status = STATUS_UNSUCCESSFUL;
					}

					if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
						ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
					}
				}

				ProbeForRead(LdrNext32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

#endif
	return STATUS_SUCCESS;
	}
NTSTATUS DebugSystem::NewDbgkpSendApiMessage(
	PEPROCESS Process,
	ULONG Flags,
	PDBGKM_APIMSG ApiMsg)
{

#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpSendApiMessage\n");
#else

#endif 
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN SuspendProcess;
	PETHREAD Thread;
	Thread = PsGetCurrentThread();

	// TODO 这里不发送etw事件
	//PUINT16 PerfGlobalGroupMask = GetPerfGlobalGroupMask();
	//EtwTraceDebuggerEventFn EtwTraceDebuggerEvent = GetEtwTraceDebuggerEventFn();
	//if (*PerfGlobalGroupMask & 0x400000)
	//	EtwTraceDebuggerEvent(Thread->Tcb.ApcState.Process, KeGetCurrentThread(), 1);

	do {
		SuspendProcess = FALSE;

		UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(Thread);

		if (Process == (PEPROCESS)*ApcStateProcessAddress && (Flags & 1))
		{
			FnDbgkpSuspendProcess DbgkpSuspendProcess = (FnDbgkpSuspendProcess)GlobalConfig::Instance().DbgkpSuspendProcess;
			SuspendProcess = DbgkpSuspendProcess(Process);
		}

		ApiMsg->ReturnedStatus = STATUS_PENDING;

		Status = NewDbgkpQueueMessage(
			Process,
			PsGetCurrentThread(),
			ApiMsg,
			(Flags & DEBUG_EVENT_NOWAIT) != 0 ? 0x40 : 0,
			NULL
		);

		//Status = DbgkpQueueMessage(
		//	Process, 
		//	PsGetCurrentThread(), 
		//	ApiMsg, 
		//	(Flags & DEBUG_EVENT_NOWAIT) != 0 ? 0x40 : 0, 
		//	NULL);

		ZwFlushInstructionCache((HANDLE)-1, NULL, 0);

		if (SuspendProcess) {
			FnPsThawMultiProcess PsThawMultiProcess = (FnPsThawMultiProcess)GlobalConfig::Instance().PsThawMultiProcess;
			PsThawMultiProcess(Process, 0, 1);
			KeLeaveCriticalRegion();
	}
} while (NT_SUCCESS(Status) && ApiMsg->ReturnedStatus == DBG_REPLY_LATER);

	return Status;
}
ULONG64 DebugSystem::MyPsWow64GetProcessNtdllType(PEPROCESS Process)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("MyPsWow64GetProcessNtdllType\n");
#else

#endif

	EWOW64PROCESS* Result;
	UINT64* WoW64ProcessAddress = GetWoW64ProcessAddress(Process);
	Result = (EWOW64PROCESS*)*WoW64ProcessAddress;
	if (Result)
		return Result->NtdllType;
	return (ULONG64)Result;
}


VOID DebugSystem::NewDbgkSendSystemDllMessages(
	PETHREAD Thread,
	PDEBUG_OBJECT DebugObject,
	PDBGKM_APIMSG ApiMsg)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkSendSystemDllMessages\n");
#else

#endif 
	PEPROCESS Process = NULL;
	PDBGKM_LOAD_DLL LoadDllArgs = NULL;
	PVOID ImageBase = NULL;
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	PVOID Teb = NULL;

	BOOLEAN IsStackAttach;

	NTSTATUS Status;

	KAPC_STATE ApcState = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

#if defined(_WIN64)
	PVOID Wow64Process;
#endif

	if (Thread)
	{
		UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(Thread);
		Process = (PEPROCESS)*ApcStateProcessAddress;
	}

	else
	{
		UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(KeGetCurrentThread());
		Process = (PEPROCESS)*ApcStateProcessAddress;
	}


#if defined(_WIN64)
	UINT64* WoW64ProcessAddress = GetWoW64ProcessAddress(Process);
	Wow64Process = (PVOID)*WoW64ProcessAddress;
#endif

	LoadDllArgs = &ApiMsg->u.LoadDll;

	for (int i = 0; i < 7; ++i)
	{
		FnPsQuerySystemDllInfo PsQuerySystemDllInfo = (FnPsQuerySystemDllInfo)GlobalConfig::Instance().PsQuerySystemDllInfo;
		PSYSTEM_DLL_ENTRY SystemDllEntry = PsQuerySystemDllInfo(i);

		if (SystemDllEntry && (i <= 0 || ((LONG32)SystemDllEntry->Type & 8) != 0 && Wow64Process && i == MyPsWow64GetProcessNtdllType(Process)))
		{
			memset(LoadDllArgs, 0, sizeof(DBGKM_LOAD_DLL));

			ImageBase = SystemDllEntry->ImageBase;
			LoadDllArgs->BaseOfDll = ImageBase;

			if (Thread && i)
			{
				IsStackAttach = TRUE;
				KeStackAttachProcess((PEPROCESS)Process, &ApcState);
			}
			else
			{
				IsStackAttach = FALSE;
			}

			NtHeaders = RtlImageNtHeader(ImageBase);

			if (NtHeaders)
			{
				LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}

			if (Thread == NULL)
			{
				UINT64* MiscFlagsAddress = GetMiscFlagsAddress(KeGetCurrentThread());
				LONG MiscFlags = *(LONG*)MiscFlagsAddress;
				if (_bittest(&MiscFlags, 0xa) || KeIsAttachedProcess())
					Teb = NULL;
				else
				{
					UINT64* TebAddress = GetTebAddress(KeGetCurrentThread());
					Teb = (PVOID)*TebAddress;
				}


				if (Teb)
				{
					UINT64* StaticUnicodeBufferAddress = GetTebStaticUnicodeBufferAddress(Teb);
					__try
					{

						RtlStringCbCopyW((NTSTRSAFE_PWSTR)StaticUnicodeBufferAddress, 0x20A, SystemDllEntry->StaticUnicodeBuffer);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						if (IsStackAttach)
							KeUnstackDetachProcess(&ApcState);
						continue;
					}

					//Teb->NtTib.ArbitraryUserPointer = StaticUnicodeBufferAddress;
					//LoadDllArgs->NamePointer = Teb->NtTib.ArbitraryUserPointer;
					UINT64* NtTibArbitraryUserPointerAddress = GetNtTibArbitraryUserPointerAddress(Teb);
					*NtTibArbitraryUserPointerAddress = (UINT64)StaticUnicodeBufferAddress;
					LoadDllArgs->NamePointer = (PVOID)StaticUnicodeBufferAddress;
				}
			}

			if (IsStackAttach)
				KeUnstackDetachProcess(&ApcState);

			InitializeObjectAttributes(
				&oa,
				&SystemDllEntry->FullName,
				OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			Status = ZwOpenFile(
				&LoadDllArgs->FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&oa,
				&IoStatusBlock,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_SYNCHRONOUS_IO_NONALERT);

			if (!NT_SUCCESS(Status))
			{
				LoadDllArgs->FileHandle = NULL;
			}

			DBGKM_FORMAT_API_MSG(*ApiMsg, DbgKmLoadDllApi, sizeof(*LoadDllArgs));

			if (Thread)
			{
				Status = NewDbgkpQueueMessage(Process, Thread, ApiMsg, 2, DebugObject);
				if (!NT_SUCCESS(Status) && LoadDllArgs->FileHandle)
				{
					ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
				}
			}
			else
			{
				NewDbgkpSendApiMessage(Process, 3, ApiMsg);

				if (LoadDllArgs->FileHandle)
				{
					ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
				}

				if (Teb)
				{
					UINT64* NtTibArbitraryUserPointerAddress = GetNtTibArbitraryUserPointerAddress(Teb);
					*NtTibArbitraryUserPointerAddress = 0;

				}
				}
			}
		}
	}
NTSTATUS DebugSystem::NewDbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpPostFakeProcessCreateMessages\n");
#else

#endif

	NTSTATUS Status;
	KAPC_STATE ApcState;
	PETHREAD Thread;
	PETHREAD LastThread;

	//
	// Attach to the process so we can touch its address space
	//
	KeStackAttachProcess((PEPROCESS)Process, &ApcState);


	Status = DebugSystem::NewDbgkpPostFakeThreadMessages(
		Process,
		DebugObject,
		NULL,
		&Thread,
		&LastThread);

	if (NT_SUCCESS(Status)) {
		Status = DebugSystem::NewDbgkpPostModuleMessages(Process, Thread, DebugObject);

		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(LastThread);
			LastThread = NULL;
		}
		ObDereferenceObject(Thread);
	}
	else {
		LastThread = NULL;
	}
	KeUnstackDetachProcess(&ApcState);

	*pLastThread = LastThread;

	return Status;
}

NTSTATUS DebugSystem::NewDbgkpPostFakeThreadMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD StartThread,
	OUT PETHREAD* pFirstThread,
	OUT PETHREAD* pLastThread)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpPostFakeThreadMessages\n");
#else

#endif 

	NTSTATUS Status;
	PETHREAD Thread, FirstThread, LastThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	NTSTATUS Status1;

	LastThread = FirstThread = NULL;

	Status = STATUS_UNSUCCESSFUL;

	FnPsGetNextProcessThread PsGetNextProcessThread = (FnPsGetNextProcessThread)GlobalConfig::Instance().PsGetNextProcessThread;

	if (StartThread != NULL)
	{
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(FirstThread);
	}
	else
	{
		StartThread = PsGetNextProcessThread(Process, NULL);
		First = TRUE;
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = PsGetNextProcessThread(Process, Thread))
	{

		Flags = DEBUG_EVENT_NOWAIT;

		//
		// Keep a track ont he last thread we have seen.
		// We use this as a starting point for new threads after we
		// really attach so we can pick up any new threads.
		//
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
		LastThread = Thread;
		ObReferenceObject(LastThread);

		UINT64* MiscFlagsAddress = GetMiscFlagsAddress(Thread);
		// 是否是系统线程
		if ((*(ULONG32*)MiscFlagsAddress & 0x400) == 0)
		{
			FnPsSynchronizeWithThreadInsertion PsSynchronizeWithThreadInsertion = (FnPsSynchronizeWithThreadInsertion)GlobalConfig::Instance().PsSynchronizeWithThreadInsertion;

			UINT64* CrossThreadFlagsAddress = GetCrossThreadFlagsAddress(Thread);

			if (*(ULONG32*)CrossThreadFlagsAddress & PS_CROSS_THREAD_FLAGS_DEADTHREAD
				|| (PsSynchronizeWithThreadInsertion(StartThread, Thread), *(ULONG32*)CrossThreadFlagsAddress & PS_CROSS_THREAD_FLAGS_DEADTHREAD))
			{

				//
				// Acquire rundown protection of the thread.
				// This stops the thread exiting so we know it can't send
				// it's termination message
				//
				UINT64* ThreadRundownProtectAddress = GetThreadRundownProtectAddress(Thread);
				if (ExAcquireRundownProtection((PEX_RUNDOWN_REF)ThreadRundownProtectAddress)) {
					Flags |= DEBUG_EVENT_RELEASE;

					//
					// Suspend the thread if we can for the debugger
					// We don't suspend terminating threads as we will not be giving details
					// of these to the debugger.
					//

					FnPsSuspendThread PsSuspendThread = (FnPsSuspendThread)GlobalConfig::Instance().PsSuspendThread;
					Status1 = PsSuspendThread(Thread, NULL);
					if (NT_SUCCESS(Status1)) {
						Flags |= DEBUG_EVENT_SUSPEND;
					}

				}
				else
				{
					//
					// Rundown protection failed for this thread.
					// This means the thread is exiting. We will mark this thread
					// later so it doesn't sent a thread termination message.
					// We can't do this now because this attach might fail.
					//
					Flags |= DEBUG_EVENT_PROTECT_FAILED;
				}

				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				if (First && (Flags & DEBUG_EVENT_PROTECT_FAILED) == 0) {
					IsFirstThread = TRUE;
				}
				else {
					IsFirstThread = FALSE;
				}

				if (IsFirstThread)
				{
					ApiMsg.ApiNumber = DbgKmCreateProcessApi;
					UINT64* SectionObjectAddress = GetSectionObjectAddress(Process);
					if (*SectionObjectAddress != NULL)  // system process doesn't have one of these!
					{

						FnDbgkpSectionToFileHandle DbgkpSectionToFileHandle = (FnDbgkpSectionToFileHandle)GlobalConfig::Instance().DbgkpSectionToFileHandle;
						ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle((PVOID)*SectionObjectAddress);
					}
					else
					{
						ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
					}

					UINT64* SectionBaseAddressAddress = GetSectionBaseAddressAddress(Process);
					ApiMsg.u.CreateProcessInfo.BaseOfImage = (PVOID)*SectionBaseAddressAddress;

					KAPC_STATE Apc;
					KeStackAttachProcess((PKPROCESS)Process, &Apc);

					__try
					{
						NtHeaders = RtlImageNtHeader((PVOID)*SectionBaseAddressAddress);
						if (NtHeaders)
						{
							ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; // Filling this in breaks MSDEV!
							//                        (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
							ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
							ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
						ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
						ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
					}

					KeUnstackDetachProcess(&Apc);
				}
				else
				{
					ApiMsg.ApiNumber = DbgKmCreateThreadApi;
					UINT64* Win32StartAddressAddress = GetWin32StartAddressAddress(Thread);
					ApiMsg.u.CreateThread.StartAddress = (PVOID)*Win32StartAddressAddress;
				}

				Status = DebugSystem::NewDbgkpQueueMessage(
					Process,
					Thread,
					&ApiMsg,
					Flags,
					DebugObject);

				FnPsResumeThread PsResumeThread = (FnPsResumeThread)GlobalConfig::Instance().PsResumeThread;

				if (!NT_SUCCESS(Status)) {
					if (Flags & DEBUG_EVENT_SUSPEND) {
						PsResumeThread(Thread, NULL);
					}
					if (Flags & DEBUG_EVENT_RELEASE) {
						UINT64* ThreadRundownProtectAddress_ = GetThreadRundownProtectAddress(Thread);
						ExReleaseRundownProtection((PEX_RUNDOWN_REF)ThreadRundownProtectAddress_);
					}
					if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
						ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
					}
					ObfDereferenceObject(Thread);
					break;
				}
				else if (IsFirstThread)
				{
					First = FALSE;
					ObReferenceObject(Thread);
					FirstThread = Thread;

					//DbgkSendSystemDllMessagesFn DbgkSendSystemDllMessages = GetDbgkSendSystemDllMessagesFn();
					//DbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
					NewDbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
				}
			}
		}

	}

	if (!NT_SUCCESS(Status)) {
		if (FirstThread) {
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	return Status;
}


NTSTATUS NTAPI DebugSystem::NewDbgkpQueueMessage(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpQueueMessage\n");
#else

#endif 
	DEBUG_EVENT StaticDebugEvent; // rbx		v5
	NTSTATUS Status; // ebx
	PDEBUG_EVENT DebugEvent; // rax
	PDEBUG_OBJECT DebugObject = NULL;	// v5
	ULONG ThreadCrossThreadFlags;

	if (Flags & DEBUG_EVENT_NOWAIT)
	{
		//DebugEvent = ExAllocatePoolWithQuotaTag(520, 0x168, 0x45676244);
		DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag(NonPagedPoolNx, sizeof(DEBUG_EVENT), POOLTAG);
		if (DebugEvent == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObfReferenceObject(Process);
		ObfReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();

		DebugObject = TargetDebugObject;
	}
	else
	{
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

		DebugObject = DebugSystem::GetDebugObject(Process);

		UINT64* CrossThreadFlagsAddress = GetCrossThreadFlagsAddress(Thread);
		ThreadCrossThreadFlags = *(ULONG32*)CrossThreadFlagsAddress;

		//
		// See if this create message has already been sent.
		//
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (ThreadCrossThreadFlags & PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION) {
				DebugObject = NULL;
			}
		}

		if (ApiMsg->ApiNumber == DbgKmLoadDllApi) {
			if (ThreadCrossThreadFlags & Flags & PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION) {
				DebugObject = NULL;
			}
		}

		//
		// See if this exit message is for a thread that never had a create
		//
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (SLOBYTE(ThreadCrossThreadFlags) < 0) {
				DebugObject = NULL;
			}
		}

		KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	}

	// TODO
	DebugEvent->Process = (PEPROCESS)Process;
	DebugEvent->Thread = (PETHREAD)Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	UINT64* CidAddress = GetCidAddress(Thread);
	RtlCopyMemory(&DebugEvent->ClientId, CidAddress, sizeof(CLIENT_ID));

	if (DebugObject == NULL)
	{
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		//
		// We must not use a debug port thats got no handles left.
		//
		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then don't use this object.
		//
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			//
			// Set the event to say there is an unread event in the object
			//
			if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		KeReleaseGuardedMutex(&DebugObject->Mutex);
	}

	if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
		KeReleaseGuardedMutex(&DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObfDereferenceObject(Process);
			ObfDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}

NTSTATUS DebugSystem::NewDbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread)
{

#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpSetProcessDebugObject\n");
#else

#endif 
	PETHREAD ThisThread; // r13		v3
	NTSTATUS Status; // edi		v4
	//register PVOID varPEProcess; // rsi	v6
	PETHREAD Thread = NULL; // r15	v8
	PLIST_ENTRY Entry; // r15	v9
	PDEBUG_EVENT DebugEvent; // rbx	v11
	PETHREAD FirstThread = NULL; // [rsp+38h] [rbp-28h]	BugCheckParameter2
	LIST_ENTRY TempList; // [rsp+48h] [rbp-18h]		P
	BOOLEAN First; // [rsp+A8h] [rbp+48h]		v28
	BOOLEAN GlobalHeld; // [rsp+B0h] [rbp+50h]	v29

	ThisThread = (PETHREAD)PsGetCurrentThread();

	InitializeListHead(&TempList);
	First = TRUE;
	Status = MsgStatus;
	GlobalHeld = FALSE;
	if (NT_SUCCESS(MsgStatus)) {
		Status = STATUS_SUCCESS;
	}
	else {
		LastThread = NULL;
		Status = MsgStatus;
	}


	if (NT_SUCCESS(Status))
	{

		while (TRUE)
		{
			ExAcquireFastMutex(&DebugSystem::DbgkpProcessDebugPortMutex);

			GlobalHeld = TRUE;
			if (DebugSystem::GetDebugObject(Process) != NULL)
			{
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}

			DebugSystem::SetDebugObject(Process, DebugObject);
			ObfReferenceObjectWithTag(LastThread, POOLTAG);
			FnPsGetNextProcessThread PsGetNextProcessThread = (FnPsGetNextProcessThread)GlobalConfig::Instance().PsGetNextProcessThread;
			Thread = PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL) {

				DebugSystem::SetDebugObject(Process, NULL);

				ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
				GlobalHeld = FALSE;
				ObfDereferenceObject(LastThread);
				// 为所有线程发送假的创建消息
				Status = DebugSystem::NewDbgkpPostFakeThreadMessages(Process, DebugObject, Thread, &FirstThread, &LastThread);
				if (!NT_SUCCESS(Status))
				{
					LastThread = NULL;
					break;
				}
				ObfDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	ExAcquireFastMutex(&DebugObject->Mutex);

	if (NT_SUCCESS(Status))
	{
		if (DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING)
		{
			DebugSystem::SetDebugObject(Process, NULL);
			Status = STATUS_DEBUGGER_INACTIVE;
		}
		else
		{
			ObfReferenceObject(DebugObject);
		}
	}

	for (Entry = DebugObject->EventList.Flink; Entry != &DebugObject->EventList;) {
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {

			Thread = DebugEvent->Thread;

			if (NT_SUCCESS(Status))
			{
				UINT64* CrossThreadFlagsAddress = GetCrossThreadFlagsAddress(Thread);
				if ((DebugObject->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0)
				{
					PS_SET_BITS(CrossThreadFlagsAddress, PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					if (First)
					{
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PS_SET_BITS(CrossThreadFlagsAddress, PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
				}
			}
			else
			{
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;

				UINT64* ThreadRundownProtectAddress = GetThreadRundownProtectAddress(Thread);
				ExReleaseRundownProtection((PEX_RUNDOWN_REF)ThreadRundownProtectAddress);
			}
		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld)
		ExReleaseFastMutex(&DebugSystem::DbgkpProcessDebugPortMutex);

	if (LastThread)
		ObfDereferenceObject(LastThread);

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		FnDbgkpWakeTarget DbgkpWakeTarget = (FnDbgkpWakeTarget)GlobalConfig::Instance().DbgkpWakeTarget;
		DbgkpWakeTarget(DebugEvent);
	}

	if (NT_SUCCESS(Status)) {
		NewDbgkpMarkProcessPeb(Process);
	}
	return Status;
	}

NTSTATUS NTAPI DebugSystem::NewNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewNtCreateDebugObject\n");
#else

#endif 


	NTSTATUS Status;
	HANDLE Handle;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	PreviousMode = ExGetPreviousMode();

	__try
	{
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle(DebugObjectHandle);
		}
		*DebugObjectHandle = NULL;
	}
	__except (ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}
	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}
	//
	// Create a new debug object and initialize it.
	//
	//

	Status = ObCreateObject(
		PreviousMode,
		DebugSystem::DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}
	//UINT64* PWoW64Process = (UINT64*)((UINT8*)PsGetCurrentProcess() + GlobalConfig::Instance().WoW64ProcessOffset);
	UINT64* PWoW64Process = GetWoW64ProcessAddress(PsGetCurrentProcess());

	if (*PWoW64Process != NULL)
	{
		DebugObject->Flags |= 4;
	}

	//
	// Insert the object into the handle table
	//
	Status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	__try {
		*DebugObjectHandle = Handle;
	}
	__except (ExSystemExceptionFilter()) {
		//
		// The caller changed the page protection or deleted the memory for the handle.
		// No point closing the handle as process rundown will do that and we don't know its still the same handle
		//
		Status = GetExceptionCode();
	}


	return Status;
	}

NTSTATUS NTAPI DebugSystem::NewNtDebugActiveProcess(
	IN HANDLE DebugeeProcessHandle,
	IN HANDLE DebugObjectHandle
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewNtDebugActiveProcess\n");
	ShvOsDebugPrint("DebugeeProcessHandle:[%p] DebugObjectHandle:[%p]\n", DebugeeProcessHandle, DebugObjectHandle);
#else
	ShvOsDebugPrint("NewNtDebugActiveProcess\n");
	ShvOsDebugPrint("DebugeeProcessHandle:[%p] DebugObjectHandle:[%p]\n", DebugeeProcessHandle, DebugObjectHandle);

#endif 

	UCHAR CurrentPreviousMode;

	PEPROCESS DebuggerProcess;	// 调试器进程
	PEPROCESS DebugeeProcess;	// 被调试进程

	PETHREAD Thread;
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PETHREAD LastThread;
	PS_PROTECTION SourceProcessProtection;
	PS_PROTECTION TargetProcessProtection;

	Thread = PsGetCurrentThread();
	CurrentPreviousMode = ExGetPreviousMode();

	// 获取被调试进程对象
	UINT64 DebuggerProcessId = (UINT64)PsGetCurrentProcessId();
	DEBUG_STATE DebugState = { 0 };
	DebugSystem::GetStateByDebuggerPid(DebuggerProcessId, &DebugState);

	Status = PsLookupProcessByProcessId((HANDLE)DebugState.DebugeePid, &DebugeeProcess);

	if (NT_SUCCESS(Status))
	{

		//DebuggerProcess = (PEPROCESS)Thread->Tcb.ApcState.Process;
		UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(Thread);
		DebuggerProcess = (PEPROCESS)*ApcStateProcessAddress;
		//如果被调试进程等于调试进程 || 被调试进程等于系统进程，则返回失败
		if (DebugeeProcess == DebuggerProcess || (PEPROCESS)DebugeeProcess == PsInitialSystemProcess)
		{
			ObfDereferenceObject(DebugeeProcess);
			return STATUS_ACCESS_DENIED;
		}

		UINT64* DebuggerPProtection = GetProtectionAddress(DebuggerProcess);
		UINT64* DebuggeePProtection = GetProtectionAddress(DebugeeProcess);

		//SourceProcessProtection = DebuggerProcess->Protection;
		//TargetProcessProtection = DebugeeProcess->Protection;
		SourceProcessProtection.Level = *(UINT8*)DebuggerPProtection;
		TargetProcessProtection.Level = *(UINT8*)DebuggeePProtection;

		// TODO
		FnPspCheckForInvalidAccessByProtection PspCheckForInvalidAccessByProtection = (FnPspCheckForInvalidAccessByProtection)GlobalConfig::Instance().PspCheckForInvalidAccessByProtection;
		if (PspCheckForInvalidAccessByProtection(CurrentPreviousMode, SourceProcessProtection, TargetProcessProtection))
		{
			ObfDereferenceObject(DebugeeProcess);
			return STATUS_PROCESS_IS_PROTECTED;
		}

		//if ((DebugeeProcess->Pcb.SecureState & 1) == 0)

		UINT64* DebuggeePcbSecureStateAddress = GetPcbSecureStateAddress(DebugeeProcess);
		if ((*(UINT8*)DebuggeePcbSecureStateAddress & 1) == 0)
		{
			// 是否非32位进程
			UINT64* DebuggerPWoW64Process = GetWoW64ProcessAddress(DebuggerProcess);
			UINT64* DebugeePWoW64Process = GetWoW64ProcessAddress(DebugeeProcess);

			if (*DebuggerPWoW64Process == NULL || *DebugeePWoW64Process != NULL)
			{
				Status = ObReferenceObjectByHandle(
					DebugObjectHandle,
					DEBUG_PROCESS_ASSIGN,
					DebugSystem::DbgkDebugObjectType,
					CurrentPreviousMode,
					(PVOID*)&DebugObject,
					NULL);

				if (NT_SUCCESS(Status))
				{
					//PEX_RUNDOWN_REF ref = &DebugeeProcess->RundownProtect;
					PEX_RUNDOWN_REF ref = (PEX_RUNDOWN_REF)GetRundownProtectAddress(DebugeeProcess);
					if (ExAcquireRundownProtection(ref))
					{
						//
						// Post the fake process create messages etc.
						//

						//DbgkpPostFakeProcessCreateMessagesProc DbgkpPostFakeProcessCreateMessages = GetDbgkpPostFakeProcessCreateMessagesProc();
						//Status = DbgkpPostFakeProcessCreateMessages(DebugeeProcess, DebugObject, &LastThread);
						Status = DebugSystem::NewDbgkpPostFakeProcessCreateMessages(DebugeeProcess, DebugObject, &LastThread);

						//
						// Set the debug port. If this fails it will remove any faked messages.
						//
						Status = DebugSystem::NewDbgkpSetProcessDebugObject(DebugeeProcess, DebugObject, Status, LastThread);
						ExReleaseRundownProtection(ref);
					}
					else
					{
						Status = STATUS_PROCESS_IS_TERMINATING;
					}
					ObfDereferenceObject(DebugObject);
				}
			}
			else {
				Status = STATUS_NOT_SUPPORTED;
			}
		}

		ObfDereferenceObject(DebugeeProcess);
	}
	return Status;
	}


VOID NTAPI DebugSystem::NewDbgkCreateThread(
	PETHREAD Thread
)
{

#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkCreateThread\n");
#else

#endif

	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	PEPROCESS Process;
	//PDBGKM_LOAD_DLL LoadDllArgs;
	//NTSTATUS Status;
	//OBJECT_ATTRIBUTES Obja;
	//IO_STATUS_BLOCK IoStatusBlock;
	PIMAGE_NT_HEADERS NtHeaders;
	//PVOID Teb;
	LONG OldFlags;

	PFILE_OBJECT FileObject;
#if defined(_WIN64)
	PVOID Wow64Process;
#endif

	//Process = (PEPROCESS_BY)Thread->Tcb.ApcState.Process;
	UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(Thread);
	Process = (PEPROCESS)*ApcStateProcessAddress;

#if defined(_WIN64)
	//Wow64Process = Process->WoW64Process;
	UINT64* WoW64ProcessAddress = GetWoW64ProcessAddress(Process);
	Wow64Process = (PVOID)*WoW64ProcessAddress;
#endif

	UINT64* ProcessFlagsAddress = GetFlagsAddress(Process);
	OldFlags = PS_TEST_SET_BITS(ProcessFlagsAddress, PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);

	FnPsCallImageNotifyRoutines PsCallImageNotifyRoutines = (FnPsCallImageNotifyRoutines)GlobalConfig::Instance().PsCallImageNotifyRoutines;

	if (!_bittest(&OldFlags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_PROCESS_EXITING | PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES))
	{
		//TODO 这里不通知，先看看有没有问题

		/*PULONG PspNotifyEnableMask = GetPspNotifyEnableMask();
		PUINT16 PerfGlobalGroupMask = GetPerfGlobalGroupMask();*/
		ULONG PspNotifyEnableMask = 0x1f;
		ULONG PerfGlobalGroupMask = 0x2005;

		if (PspNotifyEnableMask & 1 || PerfGlobalGroupMask & 4)
		{
			IMAGE_INFO_EX ImageInfoEx = { 0 };
			//PUNICODE_STRING UnicodeFileName;
			//POBJECT_NAME_INFORMATION FileNameInfo;

			//
			// notification of main .exe
			//
			UINT64* SectionBaseAddressAddress = GetSectionBaseAddressAddress(Process);
			ImageInfoEx.ImageInfo.Properties = 0;
			ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
			//ImageInfoEx.ImageInfo.ImageBase = Process->SectionBaseAddress;
			ImageInfoEx.ImageInfo.ImageBase = (PVOID)*SectionBaseAddressAddress;
			ImageInfoEx.ImageInfo.ImageSize = 0;

			__try
			{

				//NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
				NtHeaders = RtlImageNtHeader((PVOID)*SectionBaseAddressAddress);

				if (NtHeaders) {
#if defined(_WIN64)
					if (Wow64Process != NULL) {
						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, SizeOfImage);
					}
					else {
#endif
						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
#if defined(_WIN64)
					}
#endif
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ImageInfoEx.ImageInfo.ImageSize = 0;
			}
			ImageInfoEx.ImageInfo.ImageSelector = 0;
			ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

			//Status = SeLocateProcessImageName(Process, &UnicodeFileName);
			//if (!NT_SUCCESS(Status))
			//{
			//	UnicodeFileName = NULL;
			//}

			PsReferenceProcessFilePointer(Process, &FileObject);

			ImageInfoEx.FileObject = FileObject;
			UINT64* SeAuditProcessCreationInfoImageFileNameNameAddress = GetSeAuditProcessCreationInfoImageFileNameNameAddress(Process);
			PsCallImageNotifyRoutines(
				(PUNICODE_STRING)SeAuditProcessCreationInfoImageFileNameNameAddress,
				Process,
				&ImageInfoEx.ImageInfo,
				FileObject
			);

			//PsCallImageNotifyRoutines(
			//	Process->SeAuditProcessCreationInfo.ImageFileName,
			//	Process->UniqueProcessId,
			//	&ImageInfoEx.ImageInfo,
			//	FileObject
			//);

			//if (UnicodeFileName)
			//{
			//	ExFreePool(UnicodeFileName);
			//}

			ObfDereferenceObject(FileObject);

			int index = 0;
			for (index = 0; ; ++index)
			{
				if (index >= 7)
					break;

				FnPsQuerySystemDllInfo PsQuerySystemDllInfo = (FnPsQuerySystemDllInfo)GlobalConfig::Instance().PsQuerySystemDllInfo;
				PSYSTEM_DLL_ENTRY SystemDllEntry = PsQuerySystemDllInfo(index);

				if (SystemDllEntry && (index <= 0 || ((LONG32)SystemDllEntry->Type & 8) != 0 && Wow64Process != NULL && index == MyPsWow64GetProcessNtdllType(Process)))
				{

					//
					// and of ntdll.dll
					//
					ImageInfoEx.ImageInfo.Properties = 0;
					ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
					ImageInfoEx.ImageInfo.ImageBase = SystemDllEntry->ImageBase;
					ImageInfoEx.ImageInfo.ImageSize = 0;

					__try
					{
						NtHeaders = RtlImageNtHeader(SystemDllEntry->ImageBase);

						if (NtHeaders) {
#if defined(_WIN64)
							if (Wow64Process != NULL) {
								ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, SizeOfImage);
							}
							else {
#endif
								ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
#if defined(_WIN64)
							}
#endif
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						ImageInfoEx.ImageInfo.ImageSize = 0;
					}
					ImageInfoEx.ImageInfo.ImageSelector = 0;
					ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

					PSYSTEM_DLL_INFO SystemDll = CONTAINING_RECORD(SystemDllEntry, SYSTEM_DLL_INFO, Entry);

					FnPspReferenceSystemDll PspReferenceSystemDll = (FnPspReferenceSystemDll)GlobalConfig::Instance().PspReferenceSystemDll;
					//PSECTION Section = PspReferenceSystemDll((PEX_FAST_REF) * ((UINT64*)SystemDllEntry - 1));
					PSECTION Section = PspReferenceSystemDll((PEX_FAST_REF)SystemDll->Un1);

					FnMiSectionControlArea MiSectionControlArea = (FnMiSectionControlArea)GlobalConfig::Instance().MiSectionControlArea;
					PCONTROL_AREA ControlArea = MiSectionControlArea(Section);

					FnMiReferenceControlAreaFile MiReferenceControlAreaFile = (FnMiReferenceControlAreaFile)GlobalConfig::Instance().MiReferenceControlAreaFile;
					FileObject = MiReferenceControlAreaFile(ControlArea);

					if (FileObject != NULL)
					{
						FnObFastDereferenceObject ObFastDereferenceObject = (FnObFastDereferenceObject)GlobalConfig::Instance().ObFastDereferenceObject;
						ObFastDereferenceObject(
							(PEX_FAST_REF)SystemDll->Un1,
							Section
						);
					}

					//PsCallImageNotifyRoutines((PUNICODE_STRING) * ((UINT64*)SystemDllEntry + 1), Process, &ImageInfoEx.ImageInfo, FileObject);
					PsCallImageNotifyRoutines(&SystemDllEntry->FullName, Process, &ImageInfoEx.ImageInfo, FileObject);

					ObfDereferenceObject(FileObject);

				}
			}
		}
	}

	//Port = Process->DebugPort;
	//Port = debug_system::get_debug_object(Process);
	Port = DebugSystem::GetDebugObject(Process);

	if (Port == NULL) {
		return;
	}

	//
	// Make sure we only get one create process message
	//

	if ((OldFlags & PS_PROCESS_FLAGS_CREATE_REPORTED) == 0) {

		//
		// This is a create process
		//

		CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
		CreateThreadArgs->SubSystemKey = 0;

		CreateProcessArgs = &m.u.CreateProcessInfo;
		CreateProcessArgs->SubSystemKey = 0;

		FnDbgkpSectionToFileHandle DbgkpSectionToFileHandle = (FnDbgkpSectionToFileHandle)GlobalConfig::Instance().DbgkpSectionToFileHandle;
		UINT64* SectionObjectAddress = GetSectionObjectAddress(Process);
		//CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
		CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle((PVOID)*SectionObjectAddress);


		//CreateProcessArgs->BaseOfImage = Process->SectionBaseAddress;
		UINT64* SectionBaseAddress = GetSectionBaseAddressAddress(Process);
		CreateProcessArgs->BaseOfImage = (PVOID)*SectionBaseAddress;
		CreateThreadArgs->StartAddress = NULL;
		CreateProcessArgs->DebugInfoFileOffset = 0;
		CreateProcessArgs->DebugInfoSize = 0;


		__try
		{

			NtHeaders = RtlImageNtHeader((PVOID)*SectionBaseAddress);

			if (NtHeaders) {

#if defined(_WIN64)
				if (Wow64Process != NULL) {
					CreateThreadArgs->StartAddress = UlongToPtr(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, ImageBase) +
						DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, AddressOfEntryPoint));
				}
				else {
#endif
					CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) +
						DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));
#if defined(_WIN64)
				}
#endif

				//
				// The following fields are safe for Wow64 as the offsets
				// are the same for a PE32+ as a PE32 header.
				//

				CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			CreateThreadArgs->StartAddress = NULL;
			CreateProcessArgs->DebugInfoFileOffset = 0;
			CreateProcessArgs->DebugInfoSize = 0;
		}

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));

		//DbgkpSendApiMessageProc DbgkpSendApiMessage0 = GetDbgkpSendApiMessageProc();
		NewDbgkpSendApiMessage(Process, FALSE, &m);

		if (CreateProcessArgs->FileHandle != NULL) {
			ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
		}

		//DbgkSendSystemDllMessages(NULL, NULL, &m);
		NewDbgkSendSystemDllMessages(NULL, NULL, &m);

		UINT64* SameThreadPassiveFlagsAddress = GetSameThreadPassiveFlagsAddress(Thread);
		if (*(ULONG*)SameThreadPassiveFlagsAddress & PS_CROSS_THREAD_FLAGS_SYSTEM)
		{
			NewDbgkpPostModuleMessages(Process, Thread, NULL);
		}

	}
	else
	{
		CreateThreadArgs = &m.u.CreateThread;
		CreateThreadArgs->SubSystemKey = 0;
		UINT64* Win32StartAddressAddress = GetWin32StartAddressAddress(Thread);
		//CreateThreadArgs->StartAddress = Thread->Win32StartAddress;
		CreateThreadArgs->StartAddress = (PVOID)*Win32StartAddressAddress;

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));

		NewDbgkpSendApiMessage(Process, TRUE, &m);
	}
}

NTSTATUS NTAPI DebugSystem::NewDbgkExitThread(
	NTSTATUS ExitStatus
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkExitThread\n");
#else

#endif

	PVOID DebugPort;
	DBGKM_APIMSG m;
	PDBGKM_EXIT_THREAD args;
	PEPROCESS Process;
	PETHREAD Thread;

	NTSTATUS Status = STATUS_SUCCESS;

	Thread = PsGetCurrentThread();
	Process = PsGetCurrentProcess();

	//if (!(Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG))
	//{
	//}

	//DebugPort = Process->DebugPort;
	DebugPort = DebugSystem::GetDebugObject(Process);
	if (DebugPort)
	{
		UINT64* CrossThreadFlagsAddress = GetCrossThreadFlagsAddress(Thread);
		if (*(ULONG32*)CrossThreadFlagsAddress & PS_CROSS_THREAD_FLAGS_DEADTHREAD)
		{
			args = &m.u.ExitThread;
			args->ExitStatus = ExitStatus;

			DBGKM_FORMAT_API_MSG(m, DbgKmExitThreadApi, sizeof(*args));

			Status = NewDbgkpSendApiMessage(Process, TRUE, &m);
		}
	}

	return Status;
		}


NTSTATUS NTAPI DebugSystem::NewDbgkExitProcess(
	NTSTATUS ExitStatus
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkExitProcess\n");
#else

#endif

	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_EXIT_PROCESS args;
	PEPROCESS Process;
	PETHREAD Thread;

	NTSTATUS Status = STATUS_SUCCESS;

	Thread = PsGetCurrentThread();
	UINT64* ApcStateProcessAddress = GetApcStateProcessAddress(Thread);
	//Process = Thread->Tcb.ApcState.Process;
	Process = (PEPROCESS)*ApcStateProcessAddress;

	/*if (!(Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG))
	{
	}*/
	//Port = Process->DebugPort;
	Port = DebugSystem::GetDebugObject(Process);
	if (Port)
	{
		UINT64* CrossThreadFlagsAddress = GetCrossThreadFlagsAddress(Thread);
		if (*(ULONG32*)CrossThreadFlagsAddress & PS_CROSS_THREAD_FLAGS_DEADTHREAD)
		{
			//
			// this ensures that other timed lockers of the process will bail
			// since this call is done while holding the process lock, and lock duration
			// is controlled by debugger
			//
			UINT64* ExitTimeAddress = GetExitTimeAddress(Process);
			//KeQuerySystemTime(&Process->ExitTime);
			KeQuerySystemTime(ExitTimeAddress);

			args = &m.u.ExitProcess;
			args->ExitStatus = ExitStatus;

			DBGKM_FORMAT_API_MSG(m, DbgKmExitProcessApi, sizeof(*args));

			Status = NewDbgkpSendApiMessage(Process, FALSE, &m);
			//Status = DbgkpSendApiMessage(Process, FALSE, &m);
		}
	}

	return Status;
}


VOID NTAPI DebugSystem::NewDbgkMapViewOfSection(
	IN PEPROCESS Process,
	IN PVOID SectionObject,
	IN PVOID SectionBaseAddress
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkMapViewOfSection\n");
#else

#endif
	PVOID Port;
	DBGKM_APIMSG ApiMsg;
	PIMAGE_NT_HEADERS NtHeaders;
	PETHREAD Thread;
	PVOID Teb;
	HANDLE	HFile;


	//NTSTATUS Status = STATUS_SUCCESS;

	//Fn_DbgkMapViewOfSection DbgkMapViewOfSection = (Fn_DbgkMapViewOfSection)hook_DbgkMapViewOfSection->bridge();
	//DbgkMapViewOfSection(Process, SectionObject, SectionBaseAddress);
	//// 如果该`被调试进程`没有注册，则不向自定义的DebugObject发送事件，直接返回
	//uint64_t DebugeeProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	//if (!debug_system::get_state_by_debugee_pid(DebugeeProcessId, nullptr))
	//{
	//	return;
	//}

	Thread = PsGetCurrentThread();

	UINT64* TcbPreviousModeAddress = GetTcbPreviousModeAddress(Thread);
	//UINT64* PcbSecureStateAddress = GetPcbSecureStateAddress(Process);

	if (*(CHAR*)TcbPreviousModeAddress == KernelMode)
	{
		return;
	}

	//if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
	//	Port = NULL;
	//}
	//else {
	//	Port = Process->DebugPort;
	//}

	//Port = Process->DebugPort;
	Port = DebugSystem::GetDebugObject(Process);

	if (!Port)
	{
		return;
	}

	UINT64* MiscFlagsAddress = GetMiscFlagsAddress(Thread);

	if ((*(LONG*)MiscFlagsAddress & 0x400) != 0 || KeIsAttachedProcess())
		Teb = NULL;
	else
	{
		//Teb = Thread->Tcb.Teb;
		UINT64* TebAddress = GetTebAddress(Thread);
		Teb = (PVOID)*TebAddress;
	}


	// TODO
	//Fn_DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg = (Fn_DbgkpSuppressDbgMsg)get_ntfunc("get_DbgkpSuppressDbgMsg");
	UINT64* TcbProcessAddress = GetTcbProcessAddress(Thread);
	if (Teb != NULL || Process == (PEPROCESS)*TcbProcessAddress)
	{

		if (!DebugSystem::NewDbgkpSuppressDbgMsg(Teb))
		{
			UINT64* NtTibArbitraryUserPointerAddress = GetNtTibArbitraryUserPointerAddress(Teb);
			//ApiMsg.u.LoadDll.NamePointer = Teb->NtTib.ArbitraryUserPointer;
			ApiMsg.u.LoadDll.NamePointer = (PVOID)*NtTibArbitraryUserPointerAddress;
		}
		else
		{
			return;
		}

		FnDbgkpSectionToFileHandle DbgkpSectionToFileHandle = (FnDbgkpSectionToFileHandle)GlobalConfig::Instance().DbgkpSectionToFileHandle;
		HFile = DbgkpSectionToFileHandle(SectionObject);
		ApiMsg.u.LoadDll.FileHandle = HFile;
		ApiMsg.u.LoadDll.BaseOfDll = SectionBaseAddress;
		ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
		ApiMsg.u.LoadDll.DebugInfoSize = 0;

		__try {
			NtHeaders = RtlImageNtHeader(SectionBaseAddress);

			if (NtHeaders != NULL) {
				ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
			ApiMsg.u.LoadDll.DebugInfoSize = 0;
			ApiMsg.u.LoadDll.NamePointer = NULL;
		}

		ApiMsg.h.u1.Length = 0x500028;
		ApiMsg.h.u2.ZeroInit = 8;
		ApiMsg.ApiNumber = DbgKmLoadDllApi;

		NewDbgkpSendApiMessage(Process, TRUE, &ApiMsg);

		if (ApiMsg.u.LoadDll.FileHandle != NULL)
		{
			ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
	}
}
	}

VOID NTAPI DebugSystem::NewDbgkUnMapViewOfSection(
	IN PEPROCESS Process,
	IN PVOID BaseAddress
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkUnMapViewOfSection\n");
#else

#endif 
	PVOID Port;
	DBGKM_APIMSG ApiMsg;
	PVOID Teb;
	PETHREAD Thread;

	//Fn_DbgkUnMapViewOfSection DbgkUnMapViewOfSection = (Fn_DbgkUnMapViewOfSection)hook_DbgkUnMapViewOfSection->bridge();
	//DbgkUnMapViewOfSection(Process, BaseAddress);
	//// 如果该`被调试进程`没有注册，则不向自定义的DebugObject发送事件，直接返回
	//uint64_t DebugeeProcessId = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
	//if (!debug_system::get_state_by_debugee_pid(DebugeeProcessId, nullptr))
	//{
	//	return;
	//}



	Thread = PsGetCurrentThread();

	UINT64* TcbPreviousModeAddress = GetTcbPreviousModeAddress(Thread);
	if (*(CHAR*)TcbPreviousModeAddress == KernelMode)
	{
		return;
	}

	/*if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
		Port = NULL;
	}
	else {
		Port = PsGetCurrentProcess()->DebugPort;
	}*/

	//Port = Process->DebugPort;

	Port = DebugSystem::GetDebugObject(Process);
	if (!Port)
	{
		return;
	}


	UINT64* MiscFlagsAddress = GetMiscFlagsAddress(Thread);

	if ((*(LONG*)MiscFlagsAddress & 0x400) != 0 || KeIsAttachedProcess())
		Teb = NULL;
	else
	{
		//Teb = Thread->Tcb.Teb;
		UINT64* TebAddress = GetTebAddress(Thread);
		Teb = (PVOID)*TebAddress;
	}


	UINT64* TcbProcessAddress = GetTcbProcessAddress(Thread);
	if (Teb != NULL || Process == (PEPROCESS)*TcbProcessAddress)
	{

		if (DebugSystem::NewDbgkpSuppressDbgMsg(Teb))
		{
			return;
		}
	}

	ApiMsg.u.UnloadDll.BaseAddress = BaseAddress;
	ApiMsg.h.u1.Length = 0x380010;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmUnloadDllApi;
	NewDbgkpSendApiMessage(PsGetThreadProcess(KeGetCurrentThread()), 0x1, &ApiMsg);
}

NTSTATUS NTAPI DebugSystem::NewNtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewNtWaitForDebugEvent\n");
#else

#endif 
	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	LARGE_INTEGER Tmo = { 0 };
	LARGE_INTEGER StartTime = { 0 };
	DBGUI_WAIT_STATE_CHANGE tWaitStateChange;
	PEPROCESS Process;
	PETHREAD Thread;
	PLIST_ENTRY Entry, Entry2;
	PDEBUG_EVENT DebugEvent, DebugEvent2;
	BOOLEAN GotEvent;

	memset(&tWaitStateChange, 0, sizeof(DBGUI_WAIT_STATE_CHANGE));

	//char image_name[18] = { 0 };
	//memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	//Log("[NtWaitForDebugEvent] current process: %s\r\n", image_name);

	PreviousMode = ExGetPreviousMode();

	__try
	{
		if (ARGUMENT_PRESENT(Timeout)) {
			if (PreviousMode != KernelMode) {
				ProbeForRead(Timeout, sizeof(*Timeout), sizeof(UCHAR));
			}
			Tmo = *Timeout;
			Timeout = &Tmo;
			KeQuerySystemTime(&StartTime);
		}
		if (PreviousMode != KernelMode) {
			ProbeForWrite(WaitStateChange, sizeof(*WaitStateChange), sizeof(UCHAR));
		}

	}
	__except (ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}


	Status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		DEBUG_READ_EVENT,
		DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Process = NULL;
	Thread = NULL;

	while (1) {
		Status = KeWaitForSingleObject(
			&DebugObject->EventsPresent,
			Executive,
			PreviousMode,
			Alertable,
			Timeout);
		if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT || Status == STATUS_ALERTED || Status == STATUS_USER_APC) {
			break;
		}

		GotEvent = FALSE;

		DebugEvent = NULL;

		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then return an error.
		//
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {

			for (Entry = DebugObject->EventList.Flink;
				Entry != &DebugObject->EventList;
				Entry = Entry->Flink)
			{

				DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

				//
				// If this event has not been given back to the user yet and is not
				// inactive then pass it back.
				// We check to see if we have any other outstanding messages for this
				// thread as this confuses VC. You can only get multiple events
				// for the same thread for the attach faked messages.
				//
				if ((DebugEvent->Flags & (DEBUG_EVENT_READ | DEBUG_EVENT_INACTIVE)) == 0) {
					GotEvent = TRUE;
					for (Entry2 = DebugObject->EventList.Flink;
						Entry2 != Entry;
						Entry2 = Entry2->Flink) {

						DebugEvent2 = CONTAINING_RECORD(Entry2, DEBUG_EVENT, EventList);

						if (DebugEvent->ClientId.UniqueProcess == DebugEvent2->ClientId.UniqueProcess) {
							//
							// This event has the same process as an earlier event. Mark it as inactive.
							//
							DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
							DebugEvent->BackoutThread = NULL;
							GotEvent = FALSE;
							break;
						}
					}
					if (GotEvent) {
						break;
					}
				}
			}

			if (GotEvent) {
				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObReferenceObject(Thread);
				ObReferenceObject(Process);

				FnDbgkpConvertKernelToUserStateChange DbgkpConvertKernelToUserStateChange = (FnDbgkpConvertKernelToUserStateChange)GlobalConfig::Instance().DbgkpConvertKernelToUserStateChange;
				DbgkpConvertKernelToUserStateChange(&tWaitStateChange, DebugEvent);

				DebugEvent->Flags |= DEBUG_EVENT_READ;
			}
			else {
				//
				// No unread events there. Clear the event.
				//
				KeClearEvent(&DebugObject->EventsPresent);
			}
			Status = STATUS_SUCCESS;

		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);

		if (NT_SUCCESS(Status)) {
			//
			// If we woke up and found nothing
			//
			if (GotEvent == FALSE)
			{
				//
				// If timeout is a delta time then adjust it for the wait so far.
				//
				if (Tmo.QuadPart < 0) {
					LARGE_INTEGER NewTime;
					KeQuerySystemTime(&NewTime);
					Tmo.QuadPart = Tmo.QuadPart + (NewTime.QuadPart - StartTime.QuadPart);
					StartTime = NewTime;
					if (Tmo.QuadPart >= 0) {
						Status = STATUS_TIMEOUT;
						break;
					}
				}
			}
			else
			{
				//
				// Fixup needed handles. The caller could have guessed the thread id etc by now and made the target thread
				// continue. This isn't a problem as we won't do anything damaging to the system in this case. The caller
				// won't get the correct results but they set out to break us.
				//

				FnDbgkpOpenHandles DbgkpOpenHandles = (FnDbgkpOpenHandles)GlobalConfig::Instance().DbgkpOpenHandles;
				DbgkpOpenHandles(&tWaitStateChange, Process, Thread);
				ObDereferenceObject(Thread);
				ObDereferenceObject(Process);
				break;
			}
		}
		else {
			break;
		}
	}

	ObDereferenceObject(DebugObject);

	__try {
		*WaitStateChange = tWaitStateChange;
	}
	__except (ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		Status = GetExceptionCode();
	}
	return Status;
	}

VOID NTAPI DebugSystem::NewDbgkpCloseObject(
	IN PEPROCESS Process,
	IN PVOID Object,
	IN ULONG_PTR ProcessHandleCount,
	IN ULONG_PTR SystemHandleCount
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpCloseObject\n");
#else

#endif 
	PDEBUG_OBJECT DebugObject = (PDEBUG_OBJECT)Object;
	PDEBUG_EVENT DebugEvent;
	PLIST_ENTRY ListPtr;
	BOOLEAN Deref;

	UNREFERENCED_PARAMETER(ProcessHandleCount);

	//
	// If this isn't the last handle then do nothing.
	//
	if (SystemHandleCount > 1) {
		return;
	}

	FnPsTerminateProcess PsTerminateProcess = (FnPsTerminateProcess)GlobalConfig::Instance().PsTerminateProcess;
	FnDbgkpWakeTarget DbgkpWakeTarget = (FnDbgkpWakeTarget)GlobalConfig::Instance().DbgkpWakeTarget;
	FnPsGetNextProcess PsGetNextProcess = (FnPsGetNextProcess)GlobalConfig::Instance().PsGetNextProcess;

	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// Mark this object as going away and wake up any processes that are waiting.
	//
	DebugObject->Flags |= DEBUG_OBJECT_DELETE_PENDING;

	//
	// Remove any events and queue them to a temporary queue
	//
	ListPtr = DebugObject->EventList.Flink;
	InitializeListHead(&DebugObject->EventList);

	ExReleaseFastMutex(&DebugObject->Mutex);


	//
	// Wake anyone waiting. They need to leave this object alone now as its deleting
	//
	KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);

	//
	// Loop over all processes and remove the debug port from any that still have it.
	// Debug port propagation was disabled by setting the delete pending flag above so we only have to do this
	// once. No more refs can appear now.
	//
	for (Process = PsGetNextProcess(NULL);
		Process != NULL;
		Process = PsGetNextProcess(Process)) {

		UINT64* PDebugPort = (UINT64*)((UINT8*)Process + GlobalConfig::Instance().DebugPortOffset);
		if (*PDebugPort == (UINT64)DebugObject) {
			Deref = FALSE;
			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			if (*PDebugPort == (UINT64)DebugObject) {
				*PDebugPort = NULL;
				Deref = TRUE;
			}

			ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

			if (Deref) {
				NewDbgkpMarkProcessPeb(Process);

				//
				// If the caller wanted process deletion on debugger dying (old interface) then kill off the process.
				//
				if (DebugObject->Flags & DEBUG_OBJECT_KILL_ON_CLOSE) {
					PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
				}
				ObDereferenceObject(DebugObject);
			}
		}
	}



	//
	// Wake up all the removed threads.
	//
	while (ListPtr != &DebugObject->EventList) {
		DebugEvent = CONTAINING_RECORD(ListPtr, DEBUG_EVENT, EventList);
		ListPtr = ListPtr->Flink;
		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}


	}

NTSTATUS NTAPI DebugSystem::NewNtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewNtDebugContinue\n");
#else

#endif 
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent, FoundDebugEvent;
	KPROCESSOR_MODE PreviousMode;
	CLIENT_ID Clid;
	PLIST_ENTRY Entry;
	BOOLEAN GotEvent;

	//char image_name[18] = { 0 };
	//memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	//Log("[NtDebugContinue] current process: %s\r\n", image_name);

	PreviousMode = ExGetPreviousMode();

	__try
	{
		if (PreviousMode != KernelMode) {
			ProbeForRead(ClientId, sizeof(*ClientId), sizeof(UCHAR));
		}
		Clid = *ClientId;
	}
	__except (ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}

	switch (ContinueStatus) {
	case DBG_EXCEPTION_HANDLED:
	case DBG_EXCEPTION_NOT_HANDLED:
	case DBG_REPLY_LATER:
	case DBG_TERMINATE_THREAD:
	case DBG_TERMINATE_PROCESS:
	case DBG_CONTINUE:
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	Status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		DEBUG_READ_EVENT,
		DebugSystem::DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	GotEvent = FALSE;
	FoundDebugEvent = NULL;

	ExAcquireFastMutex(&DebugObject->Mutex);

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		Entry = Entry->Flink) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

		//
		// Make sure the client ID matches and that the debugger saw all the events.
		// We don't allow the caller to start a thread that it never saw a message for.
		//
		if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess)
		{
			if (!GotEvent)
			{
				if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread && (DebugEvent->Flags & DEBUG_EVENT_READ) != 0)
				{
					RemoveEntryList(Entry);
					FoundDebugEvent = DebugEvent;
					GotEvent = TRUE;
				}
			}
			else
			{
				//
				// VC breaks if it sees more than one event at a time
				// for the same process.
				//
				DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
				break;
			}
		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	ObDereferenceObject(DebugObject);

	FnDbgkpWakeTarget DbgkpWakeTarget = (FnDbgkpWakeTarget)GlobalConfig::Instance().DbgkpWakeTarget;
	//PUINT16 PerfGlobalGroupMask = GetPerfGlobalGroupMask();
	//EtwTraceDebuggerEventFn EtwTraceDebuggerEvent = GetEtwTraceDebuggerEventFn();

	if (GotEvent) {
		// TODO
		//if (*PerfGlobalGroupMask & 0x400000)
		//	EtwTraceDebuggerEvent(FoundDebugEvent->Process, FoundDebugEvent->Thread, 2);

		FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
		FoundDebugEvent->Status = STATUS_SUCCESS;
		DbgkpWakeTarget(FoundDebugEvent);
	}
	else {
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
	}


VOID NTAPI DebugSystem::NewDbgkpMarkProcessPeb(
	PEPROCESS Process
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkpMarkProcessPeb\n");
#else

#endif 
	KAPC_STATE ApcState;

	//
	// Acquire process rundown protection as we are about to look at the processes address space
	//

	PEX_RUNDOWN_REF ref = (PEX_RUNDOWN_REF)GetRundownProtectAddress(Process);
	if (ExAcquireRundownProtection(ref))
	{
		if (PsGetProcessPeb(Process) != NULL) {
			KeStackAttachProcess((PEPROCESS)Process, &ApcState);

			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			//__try {
			//	PPEB Peb = PsGetProcessPeb(Process);
			//	PBOOLEAN BeingDebugged = &Peb->BeingDebugged;

			//	//PDEBUG_OBJECT Port = debug_system::get_debug_object(Process);
			//	PDEBUG_OBJECT Port = DebugSystem::GetDebugObject(Process);
			//	// 这里修改被调试进程的PEB，会被3环的反调试检测到，所以不修改
			//	// 导致的另一个问题就是，调试器不触发系统断点，所以HOOK 3环被调试进程的系统断点函数
			//	//*BeingDebugged = (BOOLEAN)(Port != NULL ? TRUE : FALSE);
			//}
			//__except (EXCEPTION_EXECUTE_HANDLER) {
			//}

			ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

			KeUnstackDetachProcess(&ApcState);

		}
		ExReleaseRundownProtection(ref);
	}
	}


BOOLEAN NTAPI DebugSystem::NewDbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance
)
{
#ifdef OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewDbgkForwardException\n");
#else

#endif 
	PEPROCESS Process;
	PVOID Port;
	ULONG64 v21;
	DBGKM_APIMSG m;
	PDBGKM_EXCEPTION args;
	NTSTATUS st = STATUS_SUCCESS;
	BOOLEAN LpcPort;

	//char image_name[18] = { 0 };
	//memcpy(image_name, ((PEPROCESS_BY)PsGetCurrentProcess())->ImageFileName, 15);
	//Log("DbgkForwardException, Process: %s, ExceptionCode: %x\r\n", image_name, ExceptionRecord->ExceptionCode);

	args = &m.u.Exception;

	//
	// Initialize the debug LPC message with default information.
	//
	DBGKM_FORMAT_API_MSG(m, DbgKmExceptionApi, sizeof(*args));

	Process = PsGetCurrentProcess();

	if (SecondChance)
	{
		v21 = 1;
		PsSetProcessFaultInformation(Process, &v21);
	}

	if (DebugException) {
		/*if (PsApiGetThreadCrossThreadFlags(KeGetCurrentThread()) & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
			Port = NULL;
		}
		else
		{
			Port = PsApiGetProcessDebugPort(Process);
		}*/

		//Port = debug_system::get_debug_object(Process);
		Port = DebugSystem::GetDebugObject(Process);
		LpcPort = FALSE;
	}
	else {
		FnPsCaptureExceptionPort PsCaptureExceptionPort = (FnPsCaptureExceptionPort)GlobalConfig::Instance().PsCaptureExceptionPort;
		Port = PsCaptureExceptionPort(Process);
		m.h.u2.ZeroInit = LPC_EXCEPTION;
		LpcPort = TRUE;
	}

	//
	// If the destination LPC port address is NULL, then return FALSE.
	//
	if (Port == NULL && DebugException)
		return FALSE;

	//
	// Fill in the remainder of the debug LPC message.
	//
	args->ExceptionRecord = *ExceptionRecord;
	args->FirstChance = !SecondChance;

	//
	// Send the debug message to the destination LPC port.
	//
	if (LpcPort) {
		if (Port != NULL)
		{
			FnDbgkpSendApiMessageLpc DbgkpSendApiMessageLpc = (FnDbgkpSendApiMessageLpc)GlobalConfig::Instance().DbgkpSendApiMessageLpc;
			st = DbgkpSendApiMessageLpc(&m, Port, DebugException);
			ObfDereferenceObject(Port);
		}

		m.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
	}
	else
	{
		st = NewDbgkpSendApiMessage(Process, DebugException, &m);
	}

	//
	// If the send was not successful, then return a FALSE indicating that
	// the port did not handle the exception. Otherwise, if the debug port
	// is specified, then look at the return status in the message.
	//
	if (!NT_SUCCESS(st))
		return FALSE;

	if (m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED) {
		if (!DebugException)
		{
			FnDbgkpSendErrorMessage DbgkpSendErrorMessage = (FnDbgkpSendErrorMessage)GlobalConfig::Instance().DbgkpSendErrorMessage;
			st = DbgkpSendErrorMessage(ExceptionRecord, 2, &m);
			st = STATUS_UNSUCCESSFUL;
			return NT_SUCCESS(st);
		}
		return FALSE;
		}
	return NT_SUCCESS(st);
	}

NTSTATUS DebugSystem::NewNtTerminateProcess(
	OPTIONAL HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus)
{
#ifdef  OUTPUT_DEBUG_INFO
	ShvOsDebugPrint("NewNtTerminateProcess\n");
#endif //  OUTPUT_DEBUG_INFO

	PEPROCESS Process = NULL;
	if (ProcessHandle)
	{
		ObReferenceObjectByHandle(ProcessHandle,
			PROCESS_TERMINATE,
			*PsProcessType,
			ExGetPreviousMode(),
			(PVOID*)&Process,
			NULL);
	}
	else
	{
		Process = PsGetCurrentProcess();
	}
	if (Process)
	{
#ifdef  OUTPUT_DEBUG_INFO
		ShvOsDebugPrint("RemoveStateByDebugeePid\n");
#endif //  OUTPUT_DEBUG_INFO

		//提权进程信息的清理
		UINT64 Pid = (UINT64)PsGetProcessId(Process);
		if (DebugSystem::GetStateByDebuggerPid(Pid, NULL))
		{
			Handle::Destory();
		}
		else
		{
			while (Handle::IsExistProcessId(Pid))
			{
				Handle::RemoveProcessId(Pid);
			}
		}

		//保护进程信息的清除
		if (Protect::IsExistProcessId(Pid))
			Protect::Destory();

		//调试信息的清除
		DebugSystem::RemoveStateByDebugeePid(Pid);
		//目标进程的User ept hook 卸载
		UserHook::RemoveALLEptHookUserListNodeByPid(Pid);


		//Ace CallBack Hook的卸载
		UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(Process);
		UNICODE_STRING TargetImageName = { 0 };
		RtlInitUnicodeString(&TargetImageName, L"hpjyhd.exe");
		if (RtlUnicodeStringContains(&ProcessImageName, &TargetImageName, TRUE))//不区分大小写，只关注特定进程
		{
			CallBack::Destory();
		}


		if (ProcessHandle)
			ObDereferenceObject(Process);
	}

	return OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
}

VOID DebugSystem::Initialize()
{
	ExInitializeFastMutex(&DbgkpProcessDebugPortMutex);
	KeInitializeSpinLock(&DebugSystem::DebugStateListLock);
	InitializeListHead(&DebugSystem::DebugStateListHead);
	DebugSystem::InitDebugObjectType();
	DebugSystem::HookDebugFunctions();
}

VOID DebugSystem::Destory()
{
	UnHookDebugFunctions();
	UINT64 DebugeePid = 0;
	while (GetDebugeePid(&DebugeePid))
	{
		RemoveStateByDebugeePid(DebugeePid);
	}
	if (DbgkpProcessDebugPortMutex.Count != 0)
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
}

BOOLEAN DebugSystem::StartDebug(UINT64 DebuggerPid, UINT64 DebugeePid)
{
	//如果我们在链表中找到State，说明这调试器调试过其他进程，这个时候需要更新被调试进程的Pid
	if (GetStateByDebuggerPid(DebuggerPid, NULL))
	{
		SetStateByDebuggerPid(DebuggerPid, DebugeePid);
		return TRUE;
	}

	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);

	PDEBUG_STATE PDebugState = (PDEBUG_STATE)ExAllocatePoolWithTag(PagedPool, sizeof(DEBUG_STATE), POOLTAG);
	if (!PDebugState)
	{
		KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
		return FALSE;
	}
	RtlZeroMemory(PDebugState, sizeof(DEBUG_STATE));

	PDebugState->DebuggerPid = DebuggerPid;
	PDebugState->DebugeePid = DebugeePid;
	PDebugState->DebugObject = NULL;
	InsertHeadList(&DebugStateListHead, &PDebugState->DebugStateList);
	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return TRUE;
}

VOID DebugSystem::InitDebugObjectType()
{
	NTSTATUS Status;
	UNICODE_STRING ObjectTypeName;
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer = { 0 };

	RtlInitUnicodeString(&ObjectTypeName, L"Simplehver");
	POBJECT_TYPE* tempDbgkDebugObjectType = (POBJECT_TYPE*)GlobalConfig::Instance().DbgkDebugObjectType;
	FnObCreateObjectType ObCreateObjectType = (FnObCreateObjectType)GlobalConfig::Instance().ObCreateObjectType;

	RtlCopyMemory(&ObjectTypeInitializer, &(*tempDbgkDebugObjectType)->TypeInfo, sizeof(OBJECT_TYPE_INITIALIZER));
	ObjectTypeInitializer.ValidAccessMask = 0x001F000F;
	ObjectTypeInitializer.GenericMapping.GenericRead = 0x00020001;
	ObjectTypeInitializer.GenericMapping.GenericWrite = 0x00020002;
	ObjectTypeInitializer.GenericMapping.GenericExecute = 0x00120000;
	ObjectTypeInitializer.GenericMapping.GenericAll = 0x001f000f;
	ObjectTypeInitializer.DeleteProcedure = NewDbgkpDeleteProcedure;
	ObjectTypeInitializer.CloseProcedure = (FUNCT_011D_2836_CloseProcedure*)DebugSystem::NewDbgkpCloseObject;

	Status = ObCreateObjectType(&ObjectTypeName, &ObjectTypeInitializer, NULL, &DebugSystem::DbgkDebugObjectType);
	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_OBJECT_NAME_COLLISION)
		{
			POBJECT_TYPE* ObTypeIndexTable = (POBJECT_TYPE*)GlobalConfig::Instance().ObTypeIndexTable;
			if (!ObTypeIndexTable)
				return;

			ULONG Index = 2;
			while (ObTypeIndexTable[Index])
			{
				if (&ObTypeIndexTable[Index]->Name)
				{
					if (ObTypeIndexTable[Index]->Name.Buffer)
					{
						if (RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &ObjectTypeName, FALSE) == 0)
						{
							DebugSystem::DbgkDebugObjectType = ObTypeIndexTable[Index];
							DebugSystem::DbgkDebugObjectType->TypeInfo.DeleteProcedure = NewDbgkpDeleteProcedure;
							DebugSystem::DbgkDebugObjectType->TypeInfo.CloseProcedure = (FUNCT_011D_2836_CloseProcedure*)NewDbgkpCloseObject;
							return;
						}
					}
				}
				Index++;
			}
		}
	}
}

BOOLEAN DebugSystem::HookDebugFunctions()
{

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtCreateDebugObject, (PVOID)&NewNtCreateDebugObject, (PVOID*)&OriginalNtCreateDebugObject) == FALSE)
	//{
	//	ShvOsDebugPrint("NtCreateDebugObject hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtDebugActiveProcess, (PVOID)&NewNtDebugActiveProcess, (PVOID*)&OriginalNtDebugActiveProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("NtDebugActiveProcess hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkCreateThread, (PVOID)&NewDbgkCreateThread, (PVOID*)&OriginalDbgkCreateThread) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkCreateThread hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkExitThread, (PVOID)&NewDbgkExitThread, (PVOID*)&OriginalDbgkExitThread) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkExitThread hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkExitProcess, (PVOID)&NewDbgkExitProcess, (PVOID*)&OriginalDbgkExitProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkExitProcess hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkMapViewOfSection, (PVOID)&NewDbgkMapViewOfSection, (PVOID*)&OriginalDbgkMapViewOfSection) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkMapViewOfSection hook failed\n");
	//	return FALSE;
	//}


	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkUnMapViewOfSection, (PVOID)&NewDbgkUnMapViewOfSection, (PVOID*)&OriginalDbgkUnMapViewOfSection) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkUnMapViewOfSection hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().KiDispatchException, (PVOID)&NewKiDispatchException, (PVOID*)&OriginalKiDispatchException) == FALSE)
	//{
	//	ShvOsDebugPrint("KiDispatchException hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtWaitForDebugEvent, (PVOID)&NewNtWaitForDebugEvent, (PVOID*)&OriginalNtWaitForDebugEvent) == FALSE)
	//{
	//	ShvOsDebugPrint("NtWaitForDebugEvent hook failed\n");
	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkpCloseObject, (PVOID)&NewDbgkpCloseObject, (PVOID*)&OriginalDbgkpCloseObject) == FALSE)
	//{
	//	ShvOsDebugPrint("NtDebugActiveProcess hook failed\n");
	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtDebugContinue, (PVOID)&NewNtDebugContinue, (PVOID*)&OriginalNtDebugContinue) == FALSE)
	//{
	//	ShvOsDebugPrint("NtDebugContinue hook failed\n");
	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkpMarkProcessPeb, (PVOID)&NewDbgkpMarkProcessPeb, (PVOID*)&OriginalDbgkpMarkProcessPeb) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkpMarkProcessPeb hook failed\n");
	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().DbgkForwardException, (PVOID)&NewDbgkForwardException, (PVOID*)&OriginalDbgkForwardException) == FALSE)
	//{
	//	ShvOsDebugPrint("DbgkForwardException hook failed\n");
	//	return FALSE;
	//}

	if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtTerminateProcess, (PVOID)&NewNtTerminateProcess, (PVOID*)&OriginalNtTerminateProcess) == FALSE)
	{
		ShvOsDebugPrint("NtTerminateProcess hook failed\n");
		return FALSE;
	}
	if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().ObpReferenceObjectByHandleWithTag, (PVOID)&NewObpReferenceObjectByHandleWithTag, (PVOID*)&OriginalObpReferenceObjectByHandleWithTag) == FALSE)
	{
		ShvOsDebugPrint("ObpReferenceObjectByHandleWithTag hook failed\n");
		return FALSE;
	}
	if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtTerminateThread, (PVOID)&NewNtTerminateThread, (PVOID*)&OriginalNtTerminateThread) == FALSE)
	{
		ShvOsDebugPrint("NtTerminateThread hook failed\n");
		return FALSE;
	}
	if (HookSsdtTwoTrampoline((PVOID)ObfDereferenceObjectWithTag, (PVOID)&NewObfDereferenceObjectWithTag, (PVOID*)&OriginalObfDereferenceObjectWithTag) == FALSE)
	{
		ShvOsDebugPrint("ObfDereferenceObjectWithTag hook failed\n");
		return FALSE;
	}
	return TRUE;

}

VOID DebugSystem::UnHookDebugFunctions()
{
	//UnHookSsdt(GlobalConfig::Instance().NtCreateDebugObject);
	//UnHookSsdt(GlobalConfig::Instance().NtDebugActiveProcess);
	//UnHookSsdt(GlobalConfig::Instance().DbgkCreateThread);
	//UnHookSsdt(GlobalConfig::Instance().DbgkExitThread);
	//UnHookSsdt(GlobalConfig::Instance().DbgkExitProcess);
	//UnHookSsdt(GlobalConfig::Instance().DbgkMapViewOfSection);
	//UnHookSsdt(GlobalConfig::Instance().DbgkUnMapViewOfSection);
	//UnHookSsdt(GlobalConfig::Instance().KiDispatchException);
	//UnHookSsdt(GlobalConfig::Instance().NtWaitForDebugEvent);
	//UnHookSsdt(GlobalConfig::Instance().DbgkpCloseObject);
	//UnHookSsdt(GlobalConfig::Instance().NtDebugContinue);
	//UnHookSsdt(GlobalConfig::Instance().DbgkpMarkProcessPeb);
	//UnHookSsdt(GlobalConfig::Instance().DbgkForwardException);
	UnHookSsdt(GlobalConfig::Instance().NtTerminateProcess);
	UnHookSsdt(GlobalConfig::Instance().NtTerminateThread);
	UnHookSsdt(GlobalConfig::Instance().ObpReferenceObjectByHandleWithTag);
	UnHookSsdt((UINT64)ObfDereferenceObjectWithTag);
}

BOOLEAN DebugSystem::GetStateByDebuggerPid(UINT64 DebuggerPid, PDEBUG_STATE PDebugState)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);

	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;

	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebuggerPid == DebuggerPid)
		{
			if (PDebugState)
			{
				PDebugState->DebugeePid = PDebugStateVar->DebugeePid;
				PDebugState->DebuggerPid = PDebugStateVar->DebuggerPid;
				PDebugState->DebugObject = PDebugStateVar->DebugObject;
			}
			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			return TRUE;
		}
	}

	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return FALSE;
}

BOOLEAN DebugSystem::SetStateByDebuggerPid(UINT64 DebuggerPid, UINT64 DebugeePid)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);

	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;

	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebuggerPid == DebuggerPid)
		{

			PDebugStateVar->DebugeePid = DebugeePid;
			PDebugStateVar->DebuggerPid = DebuggerPid;
			//PDebugStateVar->DebugObject = NULL;
			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			ShvOsDebugPrint("SetStateByDebuggerPid Update Success! DebugeePid [%d]\n", DebugeePid);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return FALSE;
}

BOOLEAN DebugSystem::RemoveStateByDebuggerPid(UINT64 DebuggerPid)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);

	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;

	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebuggerPid == DebuggerPid)
		{
			RemoveEntryList(&PDebugStateVar->DebugStateList);
			ExFreePool(PDebugStateVar);
			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			return TRUE;
		}
	}

	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return FALSE;
}

BOOLEAN DebugSystem::GetStateByDebugeePid(UINT64 DebugeePid, PDEBUG_STATE PDebugState)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);
	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;

	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebugeePid == DebugeePid)
		{
			if (PDebugState)
			{
				PDebugState->DebugeePid = PDebugStateVar->DebugeePid;
				PDebugState->DebuggerPid = PDebugStateVar->DebuggerPid;
				PDebugState->DebugObject = PDebugStateVar->DebugObject;
			}
			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return FALSE;
}

BOOLEAN DebugSystem::RemoveStateByDebugeePid(UINT64 DebugeePid)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);
	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;

	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebugeePid == DebugeePid)
		{
			RemoveEntryList(&PDebugStateVar->DebugStateList);
			ExFreePool(PDebugStateVar);
			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			//ShvOsDebugPrint("RemoveStateByDebugeePid DebugeePid：[%d]\n", DebugeePid);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return FALSE;
}

BOOLEAN DebugSystem::GetDebugeePid(UINT64* DebugeePid)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);
	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;

	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebugeePid)
		{
			if (DebugeePid)
				*DebugeePid = PDebugStateVar->DebugeePid;

			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			return TRUE;
		}
	}
	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return FALSE;
}

PDEBUG_OBJECT DebugSystem::GetDebugObject(PEPROCESS PEprocess)
{
	DEBUG_STATE DebugState = { 0 };
	UINT64* UniqueProcessIdAddress = GetUniqueProcessIdAddress(PEprocess);

	if (GetStateByDebugeePid(*UniqueProcessIdAddress, &DebugState))
	{
		return DebugState.DebugObject;
	}

	return NULL;
}

VOID DebugSystem::SetDebugObject(PEPROCESS PEprocess, PDEBUG_OBJECT DebugObject)
{
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&DebugSystem::DebugStateListLock, &OldIrql);
	UINT64* UniqueProcessIdAddress = GetUniqueProcessIdAddress(PEprocess);
	UINT64 Pid = *UniqueProcessIdAddress;

	PLIST_ENTRY Current = &DebugSystem::DebugStateListHead;
	while (&DebugSystem::DebugStateListHead != Current->Flink)
	{
		Current = Current->Flink;
		PDEBUG_STATE PDebugStateVar = CONTAINING_RECORD(Current, DEBUG_STATE, DebugStateList);
		if (PDebugStateVar->DebugeePid == Pid)
		{
			PDebugStateVar->DebugObject = DebugObject;
			KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
			return;
		}
	}
	KeReleaseSpinLock(&DebugSystem::DebugStateListLock, OldIrql);
	return;
}

UINT64* DebugSystem::GetPcbSecureStateAddress(PEPROCESS PEprocess)
{
	UINT64* PcbSecureStateAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().PcbSecureStateOffset);
	return PcbSecureStateAddress;
}

UINT64* DebugSystem::GetRundownProtectAddress(PEPROCESS PEprocess)
{
	UINT64* RundownProtectAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().RundownProtectOffset);
	return RundownProtectAddress;
}

UINT64* DebugSystem::GetSectionObjectAddress(PEPROCESS PEprocess)
{
	UINT64* SectionObjectAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().SectionObjectOffset);
	return SectionObjectAddress;
}

UINT64* DebugSystem::GetSectionBaseAddressAddress(PEPROCESS PEprocess)
{
	UINT64* SectionBaseAddressAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().SectionBaseAddressOffset);
	return SectionBaseAddressAddress;
}
UINT64* DebugSystem::GetPebAddress(PEPROCESS PEprocess)
{
	UINT64* PebAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().PebOffset);
	return PebAddress;
}
UINT64* DebugSystem::GetFlagsAddress(PEPROCESS PEprocess)
{
	UINT64* FlagsAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().FlagsOffset);
	return FlagsAddress;
}
UINT64* DebugSystem::GetExitTimeAddress(PEPROCESS PEprocess)
{
	UINT64* ExitTimeAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().ExitTimeOffset);
	return ExitTimeAddress;
}
UINT64* DebugSystem::GetMachineAddress(PEPROCESS PEprocess)
{
	UINT64* MachineAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().MachineOffset);
	return MachineAddress;
}
UINT64* DebugSystem::GetSeAuditProcessCreationInfoImageFileNameNameAddress(PEPROCESS PEprocess)
{
	UINT64* SeAuditProcessCreationInfoAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().SeAuditProcessCreationInfoOffset);
	UINT64* ImageFileNameAddress = (UINT64*)*SeAuditProcessCreationInfoAddress;
	UINT64* NameAddress = (UINT64*)*ImageFileNameAddress;
	return NameAddress;
}
UINT64* DebugSystem::GetWoW64ProcessAddress(PEPROCESS PEprocess)
{
	UINT64* WoW64ProcessAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().WoW64ProcessOffset);
	return WoW64ProcessAddress;
}

UINT64* DebugSystem::GetUniqueProcessIdAddress(PEPROCESS PEprocess)
{
	UINT64* UniqueProcessIdAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().UniqueProcessIdOffset);
	return UniqueProcessIdAddress;
}

UINT64* DebugSystem::GetProtectionAddress(PEPROCESS PEprocess)
{
	UINT64* ProtectionAddress = (UINT64*)((UINT8*)PEprocess + GlobalConfig::Instance().ProtectionOffset);
	return ProtectionAddress;
}

UINT64* DebugSystem::GetThreadRundownProtectAddress(PETHREAD PEthread)
{
	UINT64* RundownProtectAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().ThreadRundownProtectOffset);
	return RundownProtectAddress;
}

UINT64* DebugSystem::GetMiscFlagsAddress(PETHREAD PEthread)
{
	UINT64* MiscFlagsAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().MiscFlagsOffset);
	return MiscFlagsAddress;
}

UINT64* DebugSystem::GetCrossThreadFlagsAddress(PETHREAD PEthread)
{
	UINT64* CrossThreadFlagsAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().CrossThreadFlagsOffset);
	return CrossThreadFlagsAddress;
}

UINT64* DebugSystem::GetWin32StartAddressAddress(PETHREAD PEthread)
{
	UINT64* Win32StartAddressAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().Win32StartAddressOffset);
	return Win32StartAddressAddress;
}

UINT64* DebugSystem::GetCidAddress(PETHREAD PEthread)
{
	UINT64* CidAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().CidOffset);
	return CidAddress;
}

UINT64* DebugSystem::GetApcStateAddress(PETHREAD PEthread)
{
	UINT64* ApcStateAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().ApcStateOffset);
	return ApcStateAddress;
}

UINT64* DebugSystem::GetApcStateProcessAddress(PETHREAD PEthread)
{
	UINT64* ApcStateProcessAddress = (UINT64*)((UINT8*)GetApcStateAddress(PEthread) + GlobalConfig::Instance().ApcStateProcessOffset);
	return ApcStateProcessAddress;
}

UINT64* DebugSystem::GetTebAddress(PETHREAD PEthread)
{
	UINT64* TebAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().TebOffset);
	return TebAddress;
}

UINT64* DebugSystem::GetSameThreadPassiveFlagsAddress(PETHREAD PEthread)
{
	UINT64* SameThreadPassiveFlagsAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().SameThreadPassiveFlagsOffset);
	return SameThreadPassiveFlagsAddress;
}

UINT64* DebugSystem::GetTcbPreviousModeAddress(PETHREAD PEthread)
{
	UINT64* SameThreadPassiveFlagsAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().TcbPreviousModeOffset);
	return SameThreadPassiveFlagsAddress;
}

UINT64* DebugSystem::GetTcbProcessAddress(PETHREAD PEthread)
{
	UINT64* TcbProcessAddress = (UINT64*)((UINT8*)PEthread + GlobalConfig::Instance().TcbProcessOffset);
	return TcbProcessAddress;
}

UINT64* DebugSystem::GetTebStaticUnicodeBufferAddress(PVOID PTEB)
{
	UINT64* TebStaticUnicodeBufferAddress = (UINT64*)((UINT8*)PTEB + GlobalConfig::Instance().StaticUnicodeBufferOffset);
	return TebStaticUnicodeBufferAddress;
}

UINT64* DebugSystem::GetNtTibArbitraryUserPointerAddress(PVOID PTEB)
{
	UINT64* NtTibArbitraryUserPointerAddress = (UINT64*)((UINT8*)PTEB + GlobalConfig::Instance().NtTibArbitraryUserPointerOffset);
	return NtTibArbitraryUserPointerAddress;
}

UINT64* DebugSystem::GetSameTebFlagsAddress(PVOID PTEB)
{
	UINT64* SameTebFlagsAddress = (UINT64*)((UINT8*)PTEB + GlobalConfig::Instance().SameTebFlagsOffset);
	return SameTebFlagsAddress;
}

UINT64* DebugSystem::GetWoW64ProcessPebAddress(PEWOW64PROCESS PWoW64Process)
{
	UINT64* WoW64ProcessPebAddress = (UINT64*)((UINT8*)PWoW64Process + 0);
	return WoW64ProcessPebAddress;
}

