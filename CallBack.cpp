#include "CallBack.h"
#include "Hide.h"
#include "UserHook.h"
#include "EptHook.h"
#include "Protect.h"


EXTERN_C NTKERNELAPI UCHAR* NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);
PLOAD_IMAGE_NOTIFY_ROUTINE CallBack::OriginalLoadImageCallBack = NULL;
PVOID CallBack::HookedLoadImageCallBackAddress = NULL;
PVOID CallBack::RgistrationCallBackHandle = NULL;
BOOLEAN CallBack::IsHook = FALSE;
BOOLEAN CallBack::IsCreateThread = FALSE;

PVOID CallBack::HookedObPreProcessCallBackAddress = NULL;
PVOID CallBack::HookedObPostProcessCallBackAddress = NULL;
PVOID CallBack::HookedObPreThreadCallBackAddress = NULL;
PVOID CallBack::HookedObPostThreadCallBackAddress = NULL;

POB_PRE_OPERATION_CALLBACK CallBack::OriginalPreProcessCallBack = NULL;
POB_PRE_OPERATION_CALLBACK CallBack::OriginalPostProcessCallBack = NULL;

POB_PRE_OPERATION_CALLBACK CallBack::OriginalPreThreadCallBack = NULL;
POB_PRE_OPERATION_CALLBACK CallBack::OriginalPostThreadCallBack = NULL;


INT64(NTAPI* CallBack::OriginalObpCallPreOperationCallbacks)(
	POBJECT_TYPE PObjectType,
	POB_PRE_OPERATION_INFORMATION OperationInformation,
	PVOID a3) = NULL;

INT64(NTAPI* CallBack::OriginalObpCallPostOperationCallbacks)(
	POBJECT_TYPE PObjectType,
	POB_POST_OPERATION_INFORMATION OperationInformation) = NULL;

INT64(NTAPI* CallBack::OriginalObpPreInterceptHandleCreate)(
	INT64 a1,
	CHAR a2,
	PVOID a3,
	PVOID a4) = NULL;
INT64(NTAPI* CallBack::OriginalObpPreInterceptHandleDuplicate)(
	INT64 a1,
	CHAR a2,
	PVOID a3,
	INT64 a4,
	INT64 a5,
	PVOID a6) = NULL;

typedef struct _LDR_DATA
{
	struct _LIST_ENTRY InLoadOrderLinks;
	struct _LIST_ENTRY InMemoryOrderLinks;
	struct _LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	struct _UNICODE_STRING FullDllName;
	struct _UNICODE_STRING BaseDllName;
	ULONG32      Flags;
}LDR_DATA, * PLDR_DATA;

typedef struct _OB_CALLBACK
{
	LIST_ENTRY ListEntry;
	ULONGLONG Unknown;
	HANDLE ObHandle;
	PVOID ObTypeAddr;
	PVOID PreCall;
	PVOID PostCall;
}OB_CALLBACK, * POB_CALLBACK;
#pragma pack()
typedef struct _OBJECT_TYPE_INITIALIZER
{
	USHORT Length; // Uint2B
	UCHAR ObjectTypeFlags; // UChar
	ULONG ObjectTypeCode; // Uint4B
	ULONG InvalidAttributes; // Uint4B
	GENERIC_MAPPING GenericMapping; // _GENERIC_MAPPING
	ULONG ValidAccessMask; // Uint4B
	ULONG RetainAccess; // Uint4B
	POOL_TYPE PoolType; // _POOL_TYPE
	ULONG DefaultPagedPoolCharge; // Uint4B
	ULONG DefaultNonPagedPoolCharge; // Uint4B
	PVOID DumpProcedure; // Ptr64 void
	PVOID OpenProcedure; // Ptr64 long
	PVOID CloseProcedure; // Ptr64 void
	PVOID DeleteProcedure; // Ptr64 void
	PVOID ParseProcedure; // Ptr64 long
	PVOID SecurityProcedure; // Ptr64 long
	PVOID QueryNameProcedure; // Ptr64 long
	PVOID OkayToCloseProcedure; // Ptr64 unsigned char
	ULONG WaitObjectFlagMask; // Uint4B
	USHORT WaitObjectFlagOffset; // Uint2B
	USHORT WaitObjectPointerOffset; // Uint2B
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;
typedef struct _OBJECT_TYPE
{
	LIST_ENTRY TypeList; // _LIST_ENTRY
	UNICODE_STRING Name; // _UNICODE_STRING
	PVOID DefaultObject; // Ptr64 Void
	UCHAR Index; // UChar
	ULONG TotalNumberOfObjects; // Uint4B
	ULONG TotalNumberOfHandles; // Uint4B
	ULONG HighWaterNumberOfObjects; // Uint4B
	ULONG HighWaterNumberOfHandles; // Uint4B
	OBJECT_TYPE_INITIALIZER TypeInfo; // _OBJECT_TYPE_INITIALIZER
	EX_PUSH_LOCK TypeLock; // _EX_PUSH_LOCK
	ULONG Key; // Uint4B
	LIST_ENTRY CallbackList; // _LIST_ENTRY
}OBJECT_TYPE, * POBJECT_TYPE;

BOOLEAN CallBack::EptHookDriverCreateThreadCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize)
{
	if (!TargetDriverAddress || !TargetDriverSize)
		return FALSE;

	INT32 i = 0;

	while (((PUINT64)(GlobalConfig::Instance().PspCreateThreadNotifyRoutine))[i])
	{
		PUINT64 PThreadNotifyRoutine = NULL;
		PThreadNotifyRoutine = (PUINT64)(((PUINT64)(GlobalConfig::Instance().PspCreateThreadNotifyRoutine))[i] & 0xFFFFFFFFFFFFFFF0);

		if (PThreadNotifyRoutine && MmIsAddressValid(PThreadNotifyRoutine))
			if (PThreadNotifyRoutine[1] > TargetDriverAddress && PThreadNotifyRoutine[1] < ((UINT64)TargetDriverAddress + TargetDriverSize))
			{
				ShvOsDebugPrint("TargetDriver CreateThreadCallback:[%p]\n", PThreadNotifyRoutine[1]);
			}
		i++;
	}

	return TRUE;
}

BOOLEAN CallBack::EptHookDriverObProcessCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize)
{
	POB_CALLBACK pObCallbackProcess = NULL;
	LIST_ENTRY CallbackListProcess = ((POBJECT_TYPE)(*PsProcessType))->CallbackList;
	pObCallbackProcess = (POB_CALLBACK)CallbackListProcess.Flink;
	do
	{
		if (FALSE == MmIsAddressValid(pObCallbackProcess))
		{
			break;
		}
		if (NULL != pObCallbackProcess->ObHandle)
		{
			if ((UINT64)pObCallbackProcess->PreCall > TargetDriverAddress && (UINT64)pObCallbackProcess->PreCall < ((UINT64)TargetDriverAddress + TargetDriverSize))
			{
				if (MmIsAddressValid(pObCallbackProcess->PreCall) && *(UINT8*)pObCallbackProcess->PreCall == 0xE9)
				{
					HookedObPreProcessCallBackAddress = (PVOID)RELATIVE_ADDRESS(pObCallbackProcess->PreCall, 5);
				}
				else
				{
					if (MmIsAddressValid(pObCallbackProcess->PreCall))
					{
						HookedObPreProcessCallBackAddress = pObCallbackProcess->PreCall;
					}
					else
					{
						HookedObPreProcessCallBackAddress = NULL;
					}
				}

				if (MmIsAddressValid(pObCallbackProcess->PostCall) && *(UINT8*)pObCallbackProcess->PostCall == 0xE9)
				{
					HookedObPostProcessCallBackAddress = (PVOID)RELATIVE_ADDRESS(pObCallbackProcess->PostCall, 5);
				}
				else
				{
					if (MmIsAddressValid(pObCallbackProcess->PostCall))
					{
						HookedObPostProcessCallBackAddress = pObCallbackProcess->PostCall;
					}
					else
					{
						HookedObPostProcessCallBackAddress = NULL;
					}
				}

				ShvOsDebugPrint("EptHookDriverObProcessCallback Pre:[%p] Post:[%p]\n", HookedObPreProcessCallBackAddress, HookedObPostProcessCallBackAddress);
				//KeSleep(60000);
				//ShvOsDebugPrint("Process PreCall = %p | PostCall = %p\n", HookedObPreProcessCallBackAddress, HookedObPostProcessCallBackAddress);
				//在这里开始Ept hook
				if (HookedObPreProcessCallBackAddress && HookSsdtTwoTrampoline(HookedObPreProcessCallBackAddress, (PVOID)&ProxProcessPreCallBack, (PVOID*)&OriginalPreProcessCallBack) == FALSE)
				{
					ShvOsDebugPrint("HookedObPreProcessCallBackAddress hook failed\n");
					return FALSE;
				}
				//KeSleep(60000);
				//if (HookedObPostProcessCallBackAddress && HookSsdtTwoTrampoline(HookedObPostProcessCallBackAddress, (PVOID)&ProxProcessPostCallBack, (PVOID*)&OriginalPostProcessCallBack) == FALSE)
				//{
				//	ShvOsDebugPrint("HookedObPostProcessCallBackAddress hook failed\n");
				//	return FALSE;
				//}
			}
		}
		// 获取下一链表信息
		pObCallbackProcess = (POB_CALLBACK)pObCallbackProcess->ListEntry.Flink;
	} while (CallbackListProcess.Flink != (PLIST_ENTRY)pObCallbackProcess);
	return TRUE;
}

BOOLEAN CallBack::EptHookDriverObThreadCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize)
{
	POB_CALLBACK pObCallbackThread = NULL;
	LIST_ENTRY CallbackListThread = ((POBJECT_TYPE)(*PsThreadType))->CallbackList;
	pObCallbackThread = (POB_CALLBACK)CallbackListThread.Flink;
	ShvOsDebugPrint("13\n");
	do
	{
		if (FALSE == MmIsAddressValid(pObCallbackThread))
		{
			ShvOsDebugPrint("14\n");
			break;
		}
		if (NULL != pObCallbackThread->ObHandle)
		{
			ShvOsDebugPrint("15\n");
			if ((UINT64)pObCallbackThread->PreCall > TargetDriverAddress && (UINT64)pObCallbackThread->PreCall < ((UINT64)TargetDriverAddress + TargetDriverSize))
			{
				//ShvOsDebugPrint("Thread PreCall = %p | PostCall = %p\n", pObCallbackThread->PreCall, pObCallbackThread->PostCall);
				ShvOsDebugPrint("16\n");
				if (MmIsAddressValid(pObCallbackThread->PreCall) && *(UINT8*)pObCallbackThread->PreCall == 0xE9)
				{
					ShvOsDebugPrint("17\n");
					HookedObPreThreadCallBackAddress = (PVOID)RELATIVE_ADDRESS(pObCallbackThread->PreCall, 5);
				}
				else
				{
					if (MmIsAddressValid(pObCallbackThread->PreCall))
					{
						ShvOsDebugPrint("18\n");
						HookedObPreThreadCallBackAddress = pObCallbackThread->PreCall;
					}
					else
					{
						ShvOsDebugPrint("19\n");
						HookedObPreThreadCallBackAddress = NULL;
					}

				}




				if (MmIsAddressValid(pObCallbackThread->PostCall) && *(UINT8*)pObCallbackThread->PostCall == 0xE9)
				{
					ShvOsDebugPrint("20\n");
					HookedObPostThreadCallBackAddress = (PVOID)RELATIVE_ADDRESS(pObCallbackThread->PostCall, 5);
				}
				else
				{
					if (MmIsAddressValid(pObCallbackThread->PostCall))
					{
						ShvOsDebugPrint("21\n");
						HookedObPostThreadCallBackAddress = pObCallbackThread->PostCall;
					}
					else
					{
						ShvOsDebugPrint("22\n");
						HookedObPostThreadCallBackAddress = NULL;
					}
				}


				ShvOsDebugPrint("EptHookDriverObThreadCallback Pre:[%p] Post:[%p]\n", HookedObPreThreadCallBackAddress, HookedObPostThreadCallBackAddress);
				KeSleep(60000);
				//在这里开始Ept hook
				if (HookedObPreThreadCallBackAddress && HookSsdtTwoTrampoline(HookedObPreThreadCallBackAddress, (PVOID)&ProxThreadPreCallBack, (PVOID*)&OriginalPreThreadCallBack) == FALSE)
				{
					ShvOsDebugPrint("HookedObPreThreadCallBackAddress hook failed\n");
					return FALSE;
				}
				ShvOsDebugPrint("23\n");
				KeSleep(60000);
				if (HookedObPostThreadCallBackAddress && HookSsdtTwoTrampoline(HookedObPostThreadCallBackAddress, (PVOID)&ProxThreadPostCallBack, (PVOID*)&OriginalPostThreadCallBack) == FALSE)
				{
					ShvOsDebugPrint("HookedObPostThreadCallBackAddress hook failed\n");
					return FALSE;
				}
				ShvOsDebugPrint("24\n");
			}
		}
		// 获取下一链表信息
		pObCallbackThread = (POB_CALLBACK)pObCallbackThread->ListEntry.Flink;
	} while (CallbackListThread.Flink != (PLIST_ENTRY)pObCallbackThread);
	return TRUE;
}

BOOLEAN CallBack::Register()
{
	OB_CALLBACK_REGISTRATION obRegistration = { 0, };
	OB_OPERATION_REGISTRATION opRegistration[2] = { 0 };

	obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obRegistration.OperationRegistrationCount = 2;
	RtlInitUnicodeString(&obRegistration.Altitude, L"600000");
	obRegistration.RegistrationContext = NULL;

	opRegistration[0].ObjectType = PsProcessType;
	opRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE;
	opRegistration[0].PreOperation = ProcessPreCallBack;
	opRegistration[0].PostOperation = ProcessPostCallBack;

	opRegistration[1].ObjectType = PsThreadType;
	opRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE;
	opRegistration[1].PreOperation = ProcessPreCallBack;
	opRegistration[1].PostOperation = ProcessPostCallBack;
	obRegistration.OperationRegistration = opRegistration;

	if (NT_SUCCESS(ObRegisterCallbacks(&obRegistration, &RgistrationCallBackHandle)))
		return TRUE;
	else
		return FALSE;
}

NTSTATUS CallBack::MonitorAceHandHookCallBack(PVOID PContext)
{
	UNREFERENCED_PARAMETER(PContext);
	IsCreateThread = TRUE;

	ShvOsDebugPrint("Monitor Thread Scanning !\n");

	if (!IsHook)
	{//C:\Windows\system32\DRIVERS\sysdiag_win10.sys
		while (!GetProcessInfo("ACE-BASE.sys", &GlobalConfig::Instance().ACEBASEDriverSize, (PVOID*)&GlobalConfig::Instance().ACEBASEDriverAddress))
		{
			ShvOsDebugPrint("Monitor Thread Findding Target Driver!\n");
			KeSleep(3000);
			//开始枚举并Hook ACE-BASE的ObCallBack

		}
		ShvOsDebugPrint("ACE-BASE.sys:[%p] [%p]\n", GlobalConfig::Instance().ACEBASEDriverAddress, GlobalConfig::Instance().ACEBASEDriverSize);
		KeSleep(10000);

		if (EptHookDriverObProcessCallback(GlobalConfig::Instance().ACEBASEDriverAddress, GlobalConfig::Instance().ACEBASEDriverSize))
		{
			IsHook = TRUE;
		}
		//if (EptHookDriverObProcessCallback(GlobalConfig::Instance().ACEBASEDriverAddress, GlobalConfig::Instance().ACEBASEDriverSize) &&
		//	EptHookDriverObThreadCallback(GlobalConfig::Instance().ACEBASEDriverAddress, GlobalConfig::Instance().ACEBASEDriverSize))

	}
	else
	{
		ShvOsDebugPrint("Has been done!\n");
	}

	ShvOsDebugPrint("Monitor Thread Over!\n");
	IsCreateThread = FALSE;
	return PsTerminateSystemThread(STATUS_SUCCESS);
}

BOOLEAN CallBack::EptHookDriverCmpCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize)
{
	if (!TargetDriverAddress || !TargetDriverSize)
		return FALSE;

	PLIST_ENTRY pCallbackListHead = (PLIST_ENTRY)GlobalConfig::Instance().CallbackListHead;
	PLIST_ENTRY pCallbackList = pCallbackListHead->Blink;
	do
	{
		if (((PUINT64)pCallbackList)[5] > TargetDriverAddress && ((PUINT64)pCallbackList)[5] < ((UINT64)TargetDriverAddress + TargetDriverSize))
		{
			ShvOsDebugPrint("TargetDriver CmpCallback:[%p]\n", ((PUINT64)pCallbackList)[5]);
		}

		pCallbackList = pCallbackList->Blink;
	} while (pCallbackList != pCallbackListHead);

	return TRUE;
}





VOID
CallBack::ProxLoadImageCallBack(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	if (FullImageName && wcsstr(FullImageName->Buffer, L"Client-Win64-ShippingBase.dll") != NULL)
	{
		PEPROCESS Process = NULL;
		NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
		if (NT_SUCCESS(Status))
		{
			UNICODE_STRING TruncatedFullImageName = PsQueryFullProcessImageName(Process);
			//ShvOsDebugPrint("ProxLoadImageCallBack Begin Hook FullImageName:[%wZ]  ProcessName:[%wZ]\n", FullImageName, &TruncatedFullImageName);

			//后续将在这里监控谁hook的注入进程的函数
			ObDereferenceObject(Process);

			if (GlobalConfig::Instance().LdrLoadDll)
			{
				UserHook::AntiHookAndMonitorUserPageAccessFreely((UINT64)ProcessId, (PVOID)GlobalConfig::Instance().LdrLoadDll);
			}
		}

	}

	return OriginalLoadImageCallBack(FullImageName, ProcessId, ImageInfo);
}

OB_PREOP_CALLBACK_STATUS CallBack::ProxProcessPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation)
{
	static UINT64 Times = 0;

	PEPROCESS Process = (PEPROCESS)POperationInformation->Object;
	if (POperationInformation->ObjectType == *PsProcessType && Process)
	{
		//UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(Process);
		//UNICODE_STRING TargetImageName = { 0 };
		//RtlInitUnicodeString(&TargetImageName, L"Scann Toolss.exe");
		//if (RtlUnicodeStringContains(&ProcessImageName, &TargetImageName, TRUE))//不区分大小写，只关注特定进程
		//{
		//	//if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		//	//{
		//	//	//ShvOsDebugPrint("ProxProcessPreCallBack Scann Toolss want to open handle:[%d]\n", Times++);
		//	//}
		//	//else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		//	//{
		//	//	//ShvOsDebugPrint("ProxProcessPreCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d]\n", Times++);
		//	//}
		//	return OB_PREOP_SUCCESS;
		//}

	}
	return OriginalPreProcessCallBack(RegistrationContext, POperationInformation);
}

OB_PREOP_CALLBACK_STATUS CallBack::ProxProcessPostCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation)
{
	static UINT64 Times = 0;


	PEPROCESS Process = (PEPROCESS)POperationInformation->Object;
	if (POperationInformation->ObjectType == *PsProcessType && Process)
	{
		UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(Process);
		UNICODE_STRING TargetImageName = { 0 };
		RtlInitUnicodeString(&TargetImageName, L"Scann Toolss.exe");
		if (RtlUnicodeStringContains(&ProcessImageName, &TargetImageName, TRUE))//不区分大小写,只关注特定进程
		{
			if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				ShvOsDebugPrint("ProxProcessPostCallBack Scann Toolss want to open handle:[%d]\n", Times++);
			}
			else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				ShvOsDebugPrint("ProxProcessPostCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d]\n", Times++);
			}
			return OB_PREOP_SUCCESS;
		}
	}
	return OriginalPostProcessCallBack(RegistrationContext, POperationInformation);
}


OB_PREOP_CALLBACK_STATUS CallBack::ProxThreadPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation)
{
	static UINT64 Times = 0;

	PETHREAD Thread = (PETHREAD)POperationInformation->Object;
	if (POperationInformation->ObjectType == *PsThreadType && Thread)
	{
		PEPROCESS Process = PsGetThreadProcess(Thread);
		UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(Process);
		UNICODE_STRING TargetImageName = { 0 };
		RtlInitUnicodeString(&TargetImageName, L"Scann Toolss.exe");
		if (RtlUnicodeStringContains(&ProcessImageName, &TargetImageName, TRUE))//不区分大小写，只关注特定进程
		{
			if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				ShvOsDebugPrint("ProxThreadPreCallBack Scann Toolss want to open handle:[%d]\n", Times++);
			}
			else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				ShvOsDebugPrint("ProxThreadPreCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d]\n", Times++);
			}
			return OB_PREOP_SUCCESS;
		}

	}
	return OriginalPreThreadCallBack(RegistrationContext, POperationInformation);
}

OB_PREOP_CALLBACK_STATUS CallBack::ProxThreadPostCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation)
{
	static UINT64 Times = 0;

	PETHREAD Thread = (PETHREAD)POperationInformation->Object;
	if (POperationInformation->ObjectType == *PsThreadType && Thread)
	{
		PEPROCESS Process = PsGetThreadProcess(Thread);
		UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(Process);
		UNICODE_STRING TargetImageName = { 0 };
		RtlInitUnicodeString(&TargetImageName, L"Scann Toolss.exe");
		if (RtlUnicodeStringContains(&ProcessImageName, &TargetImageName, TRUE))//不区分大小写,只关注特定进程
		{
			if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				ShvOsDebugPrint("ProxThreadPostCallBack Scann Toolss want to open handle:[%d]\n", Times++);
			}
			else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				ShvOsDebugPrint("ProxThreadPostCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d]\n", Times++);
			}
			return OB_PREOP_SUCCESS;
		}
	}
	return OriginalPostThreadCallBack(RegistrationContext, POperationInformation);
}

INT64 CallBack::ProxObpCallPreOperationCallbacks(POBJECT_TYPE PObjectType, POB_PRE_OPERATION_INFORMATION OperationInformation, PVOID a3)
{
	if (PObjectType != *PsProcessType && PObjectType != *PsThreadType)
	{
		return OriginalObpCallPreOperationCallbacks(PObjectType, OperationInformation, a3);
	}

	if (strstr((char*)PsGetProcessImageFileName(PsGetCurrentProcess()), "Scann")) {
		return STATUS_SUCCESS;
	}

	if (PObjectType == *PsProcessType)
	{
		PEPROCESS Process = (PEPROCESS)OperationInformation->Object;
		if (strstr((char*)PsGetProcessImageFileName(Process), "Scann")) {
			return STATUS_SUCCESS;
		}
	}

	if (PObjectType == *PsThreadType)
	{
		PETHREAD Thread = (PETHREAD)OperationInformation->Object;
		if (Thread)
		{
			PEPROCESS Process = PsGetThreadProcess(Thread);
			if (strstr((char*)PsGetProcessImageFileName(Process), "Scann")) {
				return STATUS_SUCCESS;
			}
		}

	}
	return OriginalObpCallPreOperationCallbacks(PObjectType, OperationInformation, a3);
}

INT64 CallBack::ProxObpCallPostOperationCallbacks(POBJECT_TYPE PObjectType, POB_POST_OPERATION_INFORMATION OperationInformation)
{

	return OriginalObpCallPostOperationCallbacks(PObjectType, OperationInformation);
}

INT64 CallBack::ProxObpPreInterceptHandleCreate(INT64 a1, CHAR a2, PVOID a3, PVOID a4)
{
	return OriginalObpPreInterceptHandleCreate(a1, a2, a3, a4);
}

INT64 CallBack::ProxObpPreInterceptHandleDuplicate(INT64 a1, CHAR a2, PVOID a3, INT64 a4, INT64 a5, PVOID a6)
{
	return OriginalObpPreInterceptHandleDuplicate(
		a1,
		a2,
		a3,
		a4,
		a5,
		a6);
}


BOOLEAN CallBack::Initialize(PDRIVER_OBJECT PDriverObject)
{
	BypassCheckSign(PDriverObject);

	//if (!EptHookDriverLoadImageCallback(GlobalConfig::Instance().SysdiagDriverAddress, GlobalConfig::Instance().SysdiagDriverSize))
	//{
	//	ShvOsDebugPrint("EptHookDriverLoadImageCallback Faild!\n");
	//	return FALSE;
	//}

	//EptHookDriverCmpCallback(GlobalConfig::Instance().SysdiagDriverAddress, GlobalConfig::Instance().SysdiagDriverSize);
	//EptHookDriverCreateProcessCallback(GlobalConfig::Instance().SysdiagDriverAddress, GlobalConfig::Instance().SysdiagDriverSize);
	//EptHookDriverCreateThreadCallback(GlobalConfig::Instance().SysdiagDriverAddress, GlobalConfig::Instance().SysdiagDriverSize);
	//EptHookDriverObProcessCallback(GlobalConfig::Instance().SysdiagDriverAddress, GlobalConfig::Instance().SysdiagDriverSize);
	//EptHookDriverObThreadCallback(GlobalConfig::Instance().SysdiagDriverAddress, GlobalConfig::Instance().SysdiagDriverSize);

	if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().ObpCallPreOperationCallbacks, (PVOID)&ProxObpCallPreOperationCallbacks, (PVOID*)&OriginalObpCallPreOperationCallbacks) == FALSE)
	{
		ShvOsDebugPrint("ObpCallPreOperationCallbacks hook failed\n");
		return FALSE;
	}


	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().ObpCallPreOperationCallbacks, (PVOID)&ProxObpCallPreOperationCallbacks, (PVOID*)&OriginalObpCallPreOperationCallbacks) == FALSE)
	//{
	//	ShvOsDebugPrint("ObpCallPreOperationCallbacks hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().ObpCallPostOperationCallbacks, (PVOID)&ProxObpCallPostOperationCallbacks, (PVOID*)&OriginalObpCallPostOperationCallbacks) == FALSE)
	//{
	//	ShvOsDebugPrint("ObpCallPostOperationCallbacks hook failed\n");
	//	return FALSE;
	//}
	return TRUE;
}

BOOLEAN CallBack::AntiAce()
{

	//if (IsCreateThread == FALSE)
	//{
	//	NTSTATUS Status = CreateThread(MonitorAceHandHookCallBack);
	//	if (NT_SUCCESS(Status))
	//		return TRUE;
	//	else
	//		return FALSE;
	//}

	return FALSE;
}

// 绕过签名检测
VOID CallBack::BypassCheckSign(PDRIVER_OBJECT PDriverObj)
{
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)(PDriverObj->DriverSection);
	ldr->Flags |= 0x20;
}

BOOLEAN CallBack::Destory()
{
	//ObUnRegisterCallbacks(RgistrationCallBackHandle);

	if (HookedLoadImageCallBackAddress)
	{
		UnHookSsdt((UINT64)HookedLoadImageCallBackAddress);
	}
	if (HookedObPreProcessCallBackAddress)
	{
		UnHookSsdt((UINT64)HookedObPreProcessCallBackAddress);
	}
	if (HookedObPostProcessCallBackAddress)
	{
		UnHookSsdt((UINT64)HookedObPostProcessCallBackAddress);
	}

	if (HookedObPreThreadCallBackAddress)
	{
		UnHookSsdt((UINT64)HookedObPreThreadCallBackAddress);
	}
	if (HookedObPostThreadCallBackAddress)
	{
		UnHookSsdt((UINT64)HookedObPostThreadCallBackAddress);
	}
	//UnHookSsdt(GlobalConfig::Instance().ObpCallPostOperationCallbacks);
	UnHookSsdt(GlobalConfig::Instance().ObpCallPreOperationCallbacks);
	return TRUE;
}

BOOLEAN CallBack::EptHookDriverLoadImageCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize)
{
	if (!TargetDriverAddress || !TargetDriverSize)
		return FALSE;

	INT i = 0;

	while (((PUINT64)(GlobalConfig::Instance().PspLoadImageNotifyRoutine))[i])
	{
		PUINT64 PLoadImageNotifyRoutine = NULL;
		PLoadImageNotifyRoutine = (PUINT64)(((PUINT64)(GlobalConfig::Instance().PspLoadImageNotifyRoutine))[i] & 0xFFFFFFFFFFFFFFF0);

		if (PLoadImageNotifyRoutine && MmIsAddressValid(PLoadImageNotifyRoutine))
			if (PLoadImageNotifyRoutine[1] > TargetDriverAddress && PLoadImageNotifyRoutine[1] < (TargetDriverAddress + TargetDriverSize))
			{

				ShvOsDebugPrint("TargetDriver LoadImageCallback:[%p]\n", PLoadImageNotifyRoutine[1]);
				HookedLoadImageCallBackAddress = (PVOID)PLoadImageNotifyRoutine[1];
				return TRUE;
				//if (HookSsdtTwoTrampoline(HookedLoadImageCallBackAddress, (PVOID)&ProxLoadImageCallBack, (PVOID*)&OriginalLoadImageCallBack) == FALSE)
				//{
				//	ShvOsDebugPrint("LoadImageNotifyRoutine hook failed\n");
				//	return FALSE;
				//}
				//else
				//{
				//	return TRUE;
				//}

			}
		i++;
	}
	return FALSE;
}

BOOLEAN CallBack::EptHookDriverCreateProcessCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize)
{
	if (!TargetDriverAddress || !TargetDriverSize)
		return FALSE;

	INT32 i = 0;

	while (((PUINT64)(GlobalConfig::Instance().PspCreateProcessNotifyRoutine))[i])
	{
		PUINT64 PProcessNotifyRoutine = NULL;
		PProcessNotifyRoutine = (PUINT64)(((PUINT64)(GlobalConfig::Instance().PspCreateProcessNotifyRoutine))[i] & 0xFFFFFFFFFFFFFFF0);

		if (PProcessNotifyRoutine && MmIsAddressValid(PProcessNotifyRoutine))
			if (PProcessNotifyRoutine[1] > TargetDriverAddress && PProcessNotifyRoutine[1] < ((UINT64)TargetDriverAddress + TargetDriverSize))
			{
				ShvOsDebugPrint("TargetDriver CreateProcessNotifyRoutine:[%p]\n", PProcessNotifyRoutine[1]);
			}
		i++;
	}

	return TRUE;
}


// 自定义回调
OB_PREOP_CALLBACK_STATUS CallBack::ProcessPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation)
{
	static UINT64 Times = 0;


	// 只取出进程回调
	if (POperationInformation->ObjectType != *PsProcessType && POperationInformation->ObjectType != *PsThreadType)
	{
		return OB_PREOP_SUCCESS;
	}

	UNREFERENCED_PARAMETER(RegistrationContext);

	if (POperationInformation->ObjectType == *PsProcessType)
	{
		PEPROCESS Process = (PEPROCESS)POperationInformation->Object;
		if (Process)
		{
			if (strstr((PCHAR)PsGetProcessImageFileName(PsGetCurrentProcess()), (PCHAR)"Scann") ||
				strstr((PCHAR)PsGetProcessImageFileName(Process), (PCHAR)"Scann"))
			{
	
				if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					ShvOsDebugPrint("ProcessPreCallBack Scann Toolss want to open handle:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
				}
				else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				{
					ShvOsDebugPrint("ProcessPreCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
				}

			}

		}

	}

	if (POperationInformation->ObjectType == *PsThreadType)
	{
		// 得到所有进程的ID
		PETHREAD Thread = (PETHREAD)POperationInformation->Object;

		if (Thread)
		{
			PEPROCESS Process = PsGetThreadProcess(Thread);
			if (Process)
				if (strstr((PCHAR)PsGetProcessImageFileName(PsGetCurrentProcess()), (PCHAR)"Scann") ||
					strstr((PCHAR)PsGetProcessImageFileName(Process), (PCHAR)"Scann"))//不区分大小写
				{

					if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
					{
						//DbgBreakPoint();

						ShvOsDebugPrint("ThreadPreCallBack Scann Toolss want to open handle:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
					}
					else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
					{
						ShvOsDebugPrint("ThreadPreCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
					}

				}

		}

	}



	return OB_PREOP_SUCCESS;
}



// 自定义回调
VOID CallBack::ProcessPostCallBack(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION POperationInformation)
{
	static UINT64 Times = 0;


	// 只取出进程回调
	if (POperationInformation->ObjectType != *PsProcessType && POperationInformation->ObjectType != *PsThreadType)
	{
		return;
	}


	UNREFERENCED_PARAMETER(RegistrationContext);

	if (POperationInformation->ObjectType == *PsProcessType)
	{
		// 得到所有进程的ID
		PEPROCESS Process = (PEPROCESS)POperationInformation->Object;
		if (Process)
		{
			if (strstr((PCHAR)PsGetProcessImageFileName(PsGetCurrentProcess()), (PCHAR)"Scann") ||
				strstr((PCHAR)PsGetProcessImageFileName(Process), (PCHAR)"Scann"))
			{
				if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					ShvOsDebugPrint("ProcessPreCallBack Scann Toolss want to open handle:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
				}
				else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				{
					ShvOsDebugPrint("ProcessPreCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
				}
			}

		}

	}


	if (POperationInformation->ObjectType == *PsThreadType)
	{
		// 得到所有进程的ID
		PETHREAD Thread = (PETHREAD)POperationInformation->Object;
		if (Thread)
		{
			PEPROCESS Process = PsGetThreadProcess(Thread);
			if (strstr((PCHAR)PsGetProcessImageFileName(PsGetCurrentProcess()), (PCHAR)"Scann") ||
				strstr((PCHAR)PsGetProcessImageFileName(Process), (PCHAR)"Scann"))
			{
				if (POperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					//DbgBreakPoint();

					ShvOsDebugPrint("ThreadPostCallBack Scann Toolss want to open handle:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
				}
				else if (POperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				{
					ShvOsDebugPrint("ThreadPostCallBack Scann Toolss want OB_OPERATION_HANDLE_DUPLICATE:[%d] [%s] [%s]\n", Times++, PsGetProcessImageFileName(PsGetCurrentProcess()), PsGetProcessImageFileName(Process));
				}



			}

		}



	}

}
