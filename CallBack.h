#pragma once
#include "GlobalConfig.h"

class CallBack
{
public:
	static BOOLEAN Initialize(PDRIVER_OBJECT PDriverObject);
	static BOOLEAN AntiAce();
	static BOOLEAN Destory();
	static BOOLEAN EptHookDriverLoadImageCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize);
	static BOOLEAN EptHookDriverCmpCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize);
	static BOOLEAN EptHookDriverCreateProcessCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize);
	static BOOLEAN EptHookDriverCreateThreadCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize);
	static BOOLEAN EptHookDriverObProcessCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize);
	static BOOLEAN EptHookDriverObThreadCallback(UINT64 TargetDriverAddress, UINT64 TargetDriverSize);



	static BOOLEAN Register();
	static NTSTATUS MonitorAceHandHookCallBack(PVOID PContext);
	static BOOLEAN IsHook;
	static BOOLEAN IsCreateThread;

private:
	static OB_PREOP_CALLBACK_STATUS ProcessPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation);
	static VOID ProcessPostCallBack(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION POperationInformation);
	static VOID BypassCheckSign(PDRIVER_OBJECT PDriverObj);
	static VOID ProxLoadImageCallBack(
		_In_opt_ PUNICODE_STRING FullImageName,
		_In_ HANDLE ProcessId,
		_In_ PIMAGE_INFO ImageInfo
	);

	static OB_PREOP_CALLBACK_STATUS ProxProcessPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation);
	static OB_PREOP_CALLBACK_STATUS ProxProcessPostCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation);
	static POB_PRE_OPERATION_CALLBACK OriginalPreProcessCallBack;
	static POB_PRE_OPERATION_CALLBACK OriginalPostProcessCallBack;
	static OB_PREOP_CALLBACK_STATUS ProxThreadPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation);
	static OB_PREOP_CALLBACK_STATUS ProxThreadPostCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION POperationInformation);
	static POB_PRE_OPERATION_CALLBACK OriginalPreThreadCallBack;
	static POB_PRE_OPERATION_CALLBACK OriginalPostThreadCallBack;

	static PLOAD_IMAGE_NOTIFY_ROUTINE OriginalLoadImageCallBack;
	static PVOID HookedLoadImageCallBackAddress;
	static PVOID RgistrationCallBackHandle;
	static PVOID HookedObPreProcessCallBackAddress;
	static PVOID HookedObPostProcessCallBackAddress;
	static PVOID HookedObPreThreadCallBackAddress;
	static PVOID HookedObPostThreadCallBackAddress;


//	static NTSTATUS(NTAPI* OriginalObpReferenceObjectByHandleWithTag)(
//		HANDLE                     Handle,
//		ACCESS_MASK                DesiredAccess,
//		POBJECT_TYPE               ObjectType,
//		KPROCESSOR_MODE            AccessMode,
//		ULONG                      Tag,
//		PVOID* Object,
//		POBJECT_HANDLE_INFORMATION HandleInformation,
//		PVOID					   UnKnown
//		);
//
//private:
//	static NTSTATUS NewNtTerminateThread(
//		HANDLE ThreadHandle,
//		NTSTATUS ExitStatus);

	static INT64(NTAPI* OriginalObpCallPreOperationCallbacks)(
		POBJECT_TYPE PObjectType,
		POB_PRE_OPERATION_INFORMATION OperationInformation,
		PVOID a3);

	static INT64 ProxObpCallPreOperationCallbacks(
		POBJECT_TYPE PObjectType,
		POB_PRE_OPERATION_INFORMATION OperationInformation,
		PVOID a3);

	static INT64(NTAPI* OriginalObpCallPostOperationCallbacks)(
		POBJECT_TYPE PObjectType,
		POB_POST_OPERATION_INFORMATION OperationInformation);

	static INT64 ProxObpCallPostOperationCallbacks(
		POBJECT_TYPE PObjectType,
		POB_POST_OPERATION_INFORMATION OperationInformation);




	static INT64 ProxObpPreInterceptHandleCreate(
		INT64 a1,
		CHAR a2,
		PVOID a3,
		PVOID a4);

	static INT64 ProxObpPreInterceptHandleDuplicate(
		INT64 a1,
		CHAR a2,
		PVOID a3,
		INT64 a4,
		INT64 a5,
		PVOID a6);
	static INT64(NTAPI* OriginalObpPreInterceptHandleCreate)(
		INT64 a1,
		CHAR a2,
		PVOID a3,
		PVOID a4);
	static INT64(NTAPI* OriginalObpPreInterceptHandleDuplicate)(
		INT64 a1,
		CHAR a2,
		PVOID a3,
		INT64 a4,
		INT64 a5,
		PVOID a6);



};




