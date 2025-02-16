#include <ntifs.h>
#include <ntdef.h>
#include "EptHook.h"
#include "Hide.h"
#include "oxygenPdb/oxygenPdb.h"
#include "UserHook.h"
#include "DebugSystem.h"
#include "CallBack.h"
#include "File.h"
#include "Handle.h"
#include "Protect.h"
#include "PhysicalMemory.h"
#include "PuppetMemory.h"
#include "MdlLock.h"

EXTERN_C POBJECT_TYPE* IoDriverObjectType;
EXTERN_C NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);

NTSTATUS(NTAPI* OriginalIoctlFuntion)(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS ProxIoctlFuntion(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PIO_STACK_LOCATION pIrpStack;
	ULONG Code;
	NTSTATUS Status;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	Code = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	switch (Code)
	{
	case CommandMemoryRead:
	{
		PMEMORY_RW_DESC mrd = (PMEMORY_RW_DESC)pIrp->AssociatedIrp.SystemBuffer;
		switch (mrd->Method)
		{
		case ReadProcessMemoryByHostMmCopyMemoryMethod:
		{
			Status = ReadProcessMemoryByVtHostMmCopyMemory(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize, mrd->NumberOfBytes);
			break;
		}
		case ReadProcessMemoryByMdlMethod:
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		case ReadProcessMemoryByMmCopyVirtualMemoryMethod:
		{
			Status = ReadProcessMemoryByMmCopyVirtualMemory(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize, mrd->NumberOfBytes);
			break;
		}
		case ReadProcessMemoryByHostCr3Method:
		{
			Status = ReadProcessMemoryByVtCr3(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize, mrd->NumberOfBytes);
			break;
		}
		case ReadProcessMemoryByMmMapIoSpaceMethod:
		{
			Status = PhysicalMemory::ReadProcessMemoryPhysicalByMmMapIoSpace((HANDLE)mrd->Pid, (ULONG64)mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize);
			if (NT_SUCCESS(Status) && mrd->NumberOfBytes)
			{
				RtlCopyMemory(mrd->NumberOfBytes, &mrd->BufferSize, sizeof(size_t));
			}

			break;
		}
		case ReadProcessMemoryByInvlpgMethod:
		{
			Status = ReadProcessMemoryByInvlpg(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize);
			if (NT_SUCCESS(Status) && mrd->NumberOfBytes)
			{
				RtlCopyMemory(mrd->NumberOfBytes, &mrd->BufferSize, sizeof(size_t));
			}
			break;
		}
		default:
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		}

		if (NT_SUCCESS(Status))
		{
			mrd->Status = TRUE;
		}
		else
		{
			//ShvOsDebugPrint("VtReadProcessMemoryHostMmCopyMemory mrd->Pid:[%p] mrd->VirtualAddress:[%p] mrd->Buffer:[%p] mrd->BufferSize:[%p]\n", mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize);
			mrd->Status = FALSE;
		}
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(MEMORY_RW_DESC);
		break;
	}
	case CommandMemoryWrite:
	{

		PMEMORY_RW_DESC mrd = (PMEMORY_RW_DESC)pIrp->AssociatedIrp.SystemBuffer;

		switch (mrd->Method)
		{
		case WriteProcessMemoryByHostMmMapIoSpaceMethod:
		{
			Status = WriteProcessMemoryByVtHostMmMapIoSpace(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize, mrd->NumberOfBytes);
			break;
		}
		case WriteProcessMemoryByMdlMethod:
		{
			Status = WriteProcessMemoryByMdl(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize, mrd->NumberOfBytes);
			break;
		}
		case WriteProcessMemoryByMmCopyVirtualMemoryMethod:
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		case WriteProcessMemoryByHostCr3Method:
		{
			Status = WriteProcessMemoryByVtCr3(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize, mrd->NumberOfBytes);
			break;
		}
		case WriteProcessMemoryByMmMapIoSpaceMethod:
		{
			Status = PhysicalMemory::WriteProcessMemoryPhysicalByMmMapIoSpace((HANDLE)mrd->Pid, (ULONG64)mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize);
			if (NT_SUCCESS(Status) && mrd->NumberOfBytes)
			{
				RtlCopyMemory(mrd->NumberOfBytes, &mrd->BufferSize, sizeof(size_t));
			}
			break;
		}
		case WriteProcessMemoryByInvlpgMethod:
		{
			Status = WriteProcessMemoryByInvlpg(mrd->Pid, mrd->VirtualAddress, mrd->Buffer, mrd->BufferSize);
			if (NT_SUCCESS(Status) && mrd->NumberOfBytes)
			{
				RtlCopyMemory(mrd->NumberOfBytes, &mrd->BufferSize, sizeof(size_t));
			}
			break;
		}
		default:
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
		}


		if (NT_SUCCESS(Status))
		{
			mrd->Status = TRUE;
		}
		else
		{
			mrd->Status = FALSE;
		}
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(MEMORY_RW_DESC);
		break;
	}
	case CommandAntiAceCallBack:
	{
		CallBack::AntiAce();
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = 0;
		break;
	}
	case CommandUnHideFromSyscall:
	{

		//DebugSystem::Destory();
		//第一步，移除隐藏的pid
		//UINT32* pid = (UINT32*)pIrp->AssociatedIrp.SystemBuffer;
		//ShvOsDebugPrint(" CommandRemoveHiderEntry pid:[%d]\n", *pid);
		//if (RemoveEntry(PidToProcess((HANDLE)*pid)) == FALSE)
		//{
		//	pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		//	pIrp->IoStatus.Information = 0;
		//	break;
		//}
		//else
		//{
		//	pIrp->IoStatus.Status = STATUS_SUCCESS;
		//	pIrp->IoStatus.Information = 0;
		//	GlobalConfig::Instance().NumberOfActiveDebuggers--;
		//}
		////第二步，卸载hook
		//UnHookSyscalls();

		break;
	}
	case CommandUserEptHook:
	{
		PEPT_USER_PAGE_MONITOR PUserPageMonitor = (PEPT_USER_PAGE_MONITOR)pIrp->AssociatedIrp.SystemBuffer;
		ShvOsDebugPrint("Pid:[%p] VirtualAddress:[%p]\n", PUserPageMonitor->Pid, PUserPageMonitor->VirtualAddress);
		if (UserHook::HookUser(PUserPageMonitor->Pid, (PVOID)PUserPageMonitor->VirtualAddress))
			PUserPageMonitor->Status = TRUE;
		else
			PUserPageMonitor->Status = FALSE;
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(EPT_USER_PAGE_MONITOR);
		break;
	}
	case CommandUserEptHookFreely:
	{
		PEPT_USER_PAGE_MONITOR PUserPageMonitor = (PEPT_USER_PAGE_MONITOR)pIrp->AssociatedIrp.SystemBuffer;
		if (PUserPageMonitor->BufferSize == PAGE_SIZE)
		{
			ShvOsDebugPrint("Pid:[%p] VirtualAddress:[%p]\n", PUserPageMonitor->Pid, PUserPageMonitor->VirtualAddress);
			if (UserHook::HookUserFreely(PUserPageMonitor->Pid, (PVOID)PUserPageMonitor->VirtualAddress, (PVOID)PUserPageMonitor->Buffer))
				PUserPageMonitor->Status = TRUE;
			else
				PUserPageMonitor->Status = FALSE;
		}
		else
			ShvOsDebugPrint("HookUserFreely BufferSize Must Be PAGE_SIZE\n");

		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(EPT_USER_PAGE_MONITOR);
		break;
	}
	case CommandUserEptUnHook:
	{
		PEPT_USER_PAGE_MONITOR PUserPageMonitor = (PEPT_USER_PAGE_MONITOR)pIrp->AssociatedIrp.SystemBuffer;
		ShvOsDebugPrint("Pid:[%p] VirtualAddress:[%p]\n", PUserPageMonitor->Pid, PUserPageMonitor->VirtualAddress);
		if (UserHook::UnHookUser(PUserPageMonitor->Pid, (PVOID)PUserPageMonitor->VirtualAddress))
			PUserPageMonitor->Status = TRUE;
		else
			PUserPageMonitor->Status = FALSE;
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(EPT_USER_PAGE_MONITOR);
		break;
	}
	case CommandAddDebugger:
	{
		PADD_DEBUGGER PAddDebugger = (PADD_DEBUGGER)pIrp->AssociatedIrp.SystemBuffer;
		ShvOsDebugPrint("DebuggerPid:[%d] DebugeePid:[%d]\n", PAddDebugger->DebuggerPid, PAddDebugger->DebugeePid);
		if (DebugSystem::StartDebug(PAddDebugger->DebuggerPid, PAddDebugger->DebugeePid))
			PAddDebugger->Status = TRUE;
		else
			PAddDebugger->Status = FALSE;

		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(ADD_DEBUGGER);
		break;
	}
	case CommandUpdateHanldeAccess:
	{
		PHANDLE_INFORMATION Info = (PHANDLE_INFORMATION)pIrp->AssociatedIrp.SystemBuffer;
		if (Info)
		{
			if (Info->Method == HandleMethodOne)
			{
				Handle::HandleGrantAccess(*Info);
				pIrp->IoStatus.Status = STATUS_SUCCESS;
			}
			else if (Info->Method == HandleMethodTwo)
			{
				if (Info->IsAdd)
				{	//防止重复添加
					//if (Info->IsProcessId)
					//{
					//	ShvOsDebugPrint("UniqueProcess:[%d]\n", Info->ClientId.UniqueProcess);
					//	if (Handle::IsExistProcessId((UINT64)Info->ClientId.UniqueProcess))
					//	{
					//		Info->Status = TRUE;
					//		pIrp->IoStatus.Status = STATUS_SUCCESS;
					//		pIrp->IoStatus.Information = sizeof(HANDLE_INFORMATION);
					//		break;
					//	}
					//}
					//else
					//{
					//	ShvOsDebugPrint("UniqueThread:[%d]\n", Info->ClientId.UniqueThread);
					//	if (Handle::IsExistThreadId((UINT64)Info->ClientId.UniqueThread))
					//	{
					//		Info->Status = TRUE;
					//		pIrp->IoStatus.Status = STATUS_SUCCESS;
					//		pIrp->IoStatus.Information = sizeof(HANDLE_INFORMATION);
					//		break;
					//	}
					//}
					//ShvOsDebugPrint("AddProcessIdAndThreadId UniqueProcess:[%p] UniqueThread:[%p]\n", Info->ClientId.UniqueProcess, Info->ClientId.UniqueThread);

					if (Handle::AddProcessIdAndThreadId(Info->ClientId))
						Info->Status = TRUE;
					else
						Info->Status = FALSE;
				}
				else
				{
					if (Handle::RemoveProcessIdAndThreadId(Info->ClientId))
						Info->Status = TRUE;
					else
						Info->Status = FALSE;
				}

			}
		}
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(HANDLE_INFORMATION);
		break;
	}
	case CommandUserEptBreakPoint:
	{
		PUSER_EPT_BREAKPOINT Info = (PUSER_EPT_BREAKPOINT)pIrp->AssociatedIrp.SystemBuffer;
		ShvOsDebugPrint("IsAddBreakPoint:[%d] ProcessId:[%d] VirtualAddress:[%p]\n", Info->IsAddBreakPoint, Info->ProcessId, Info->VirtualAddress);
		if (Info->IsAddBreakPoint)
		{
			if (UserHook::UserEptBreakPoint(Info->ProcessId, (PVOID)Info->VirtualAddress, Info->TargetVirtualAddressInstructionLength, Info->RegisterIndex, &Info->FilterData))
				Info->Status = TRUE;
			else
				Info->Status = FALSE;
		}
		else
		{
			if (UserHook::UserEptUnBreakPoint(Info->ProcessId, (PVOID)Info->VirtualAddress, Info->OldValue))
				Info->Status = TRUE;
			else
				Info->Status = FALSE;
		}

		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(USER_EPT_BREAKPOINT);
		break;
	}
	case CommandProtect:
	{
		PPROTECT_INFO Info = (PPROTECT_INFO)pIrp->AssociatedIrp.SystemBuffer;
		//ShvOsDebugPrint("CommandProtect IsAdd:[%d] ProcessId:[%d] ThreadId:[%p]\n", Info->IsAdd, Info->ClientId.UniqueProcess, Info->ClientId.UniqueThread);
		if (Info->IsAdd)
		{
			if (Protect::AddProcessIdAndThreadId(Info->ClientId))
				Info->Status = TRUE;
			else
				Info->Status = FALSE;
		}
		else
		{
			if (Protect::RemoveProcessIdAndThreadId(Info->ClientId))
				Info->Status = TRUE;
			else
				Info->Status = FALSE;
		}
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = sizeof(PROTECT_INFO);
		break;
	}

	default:
	{
		return OriginalIoctlFuntion(pDevObj, pIrp);
		break;
	}
	}

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

BOOLEAN InitOffsets()
{

	UINT64 imageSize;
	GetProcessInfo("ntoskrnl.exe", &imageSize, (PVOID*)&GlobalConfig::Instance().NtoskrnlAddress);
	GetProcessInfo("win32kfull.sys", &imageSize, (PVOID*)&GlobalConfig::Instance().Win32kAddress);
	GetProcessInfo("volmgr.sys", &imageSize, (PVOID*)&GlobalConfig::Instance().volmgrAddress);
	//if (!GetProcessInfo("sysdiag_win10.sys", &GlobalConfig::Instance().SysdiagDriverSize, (PVOID*)&GlobalConfig::Instance().SysdiagDriverAddress))
	//{
	//	GetProcessInfo("sysdiag.sys", &GlobalConfig::Instance().SysdiagDriverSize, (PVOID*)&GlobalConfig::Instance().SysdiagDriverAddress);
	//}

	PEPROCESS        CsrssProcess = GetCsrssProcess();
	PVOID            NtDllAddress = GetUserModeModule(CsrssProcess, L"ntdll.dll", FALSE);
	GlobalConfig::Instance().KiUserExceptionDispatcherAddress = (UINT64)GetExportedFunctionAddress(CsrssProcess, NtDllAddress, "KiUserExceptionDispatcher");


	HANDLE ProcessId = PsGetProcessId(CsrssProcess);
	NTSTATUS Status = GetProcessModule(ProcessId, (CHAR*)"ntdll.dll", (PVOID) & (GlobalConfig::Instance().NtdllAddress));
	if (NT_SUCCESS(Status))
	{
		GetProcessModuleFunc(ProcessId, (PVOID)(GlobalConfig::Instance().NtdllAddress), (CHAR*)"LdrLoadDll", (PVOID) & (GlobalConfig::Instance().LdrLoadDll));
		ShvOsDebugPrint("ntdll.dll:[%p] LdrLoadDll:[%p]\n", GlobalConfig::Instance().NtdllAddress, GlobalConfig::Instance().LdrLoadDll);
	}


	KAPC_STATE State;
	KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);
	oxygenPdb::Pdber win32kbase(L"win32kbase.sys");
	oxygenPdb::Pdber win32kfull(L"win32kfull.sys");


	if (win32kbase.init())
	{
		GlobalConfig::Instance().NtUserEnumDisplayDevices = (UINT64)win32kbase.GetPointer("NtUserEnumDisplayDevices");
	}

	if (win32kfull.init())
	{
		GlobalConfig::Instance().NtUserGetThreadState = (HANDLE(NTAPI*)(ULONG Routine))win32kfull.GetPointer("NtUserGetThreadState");
		GlobalConfig::Instance().NtUserFindWindowEx = (UINT64)win32kfull.GetPointer("NtUserFindWindowEx");
		GlobalConfig::Instance().NtUserBuildHwndList = (UINT64)win32kfull.GetPointer("NtUserBuildHwndList");
		GlobalConfig::Instance().NtUserQueryWindow = (UINT64)win32kfull.GetPointer("NtUserQueryWindow");
		GlobalConfig::Instance().NtUserGetForegroundWindow = (UINT64)win32kfull.GetPointer("NtUserGetForegroundWindow");
		GlobalConfig::Instance().NtUserGetClassName = (UINT64)win32kfull.GetPointer("NtUserGetClassName");
		GlobalConfig::Instance().NtUserInternalGetWindowText = (UINT64)win32kfull.GetPointer("NtUserInternalGetWindowText");
		GlobalConfig::Instance().NtGdiExtTextOutW = (UINT64)win32kfull.GetPointer("NtGdiExtTextOutW");
	}


	KeUnstackDetachProcess(&State);


	oxygenPdb::Pdber ntos(L"ntoskrnl.exe");
	if (ntos.init())
	{
		GlobalConfig::Instance().NtSetInformationThread = ntos.GetPointer("NtSetInformationThread");
		GlobalConfig::Instance().NtQueryInformationProcess = ntos.GetPointer("NtQueryInformationProcess");
		GlobalConfig::Instance().NtQueryObject = ntos.GetPointer("NtQueryObject");
		GlobalConfig::Instance().NtSystemDebugControl = ntos.GetPointer("NtSystemDebugControl");
		GlobalConfig::Instance().NtSetContextThread = ntos.GetPointer("NtSetContextThread");
		GlobalConfig::Instance().NtQuerySystemInformation = ntos.GetPointer("NtQuerySystemInformation");
		GlobalConfig::Instance().NtGetContextThread = ntos.GetPointer("NtGetContextThread");
		GlobalConfig::Instance().NtClose = ntos.GetPointer("NtClose");
		GlobalConfig::Instance().NtQueryInformationThread = ntos.GetPointer("NtQueryInformationThread");
		GlobalConfig::Instance().NtCreateThreadEx = ntos.GetPointer("NtCreateThreadEx");
		GlobalConfig::Instance().NtCreateFile = ntos.GetPointer("NtCreateFile");
		GlobalConfig::Instance().NtCreateProcessEx = ntos.GetPointer("NtCreateProcessEx");
		GlobalConfig::Instance().NtYieldExecution = ntos.GetPointer("NtYieldExecution");
		GlobalConfig::Instance().NtQuerySystemTime = ntos.GetPointer("NtQuerySystemTime");
		GlobalConfig::Instance().NtQueryPerformanceCounter = ntos.GetPointer("NtQueryPerformanceCounter");
		GlobalConfig::Instance().NtContinue = ntos.GetPointer("NtContinue");
		GlobalConfig::Instance().NtContinueEx = ntos.GetPointer("NtContinueEx");
		GlobalConfig::Instance().NtQueryInformationJobObject = ntos.GetPointer("NtQueryInformationJobObject");
		GlobalConfig::Instance().NtCreateUserProcess = ntos.GetPointer("NtCreateUserProcess");
		GlobalConfig::Instance().NtGetNextProcess = ntos.GetPointer("NtGetNextProcess");
		GlobalConfig::Instance().NtOpenProcess = ntos.GetPointer("NtOpenProcess");
		GlobalConfig::Instance().NtOpenThread = ntos.GetPointer("NtOpenThread");
		GlobalConfig::Instance().NtSetInformationProcess = ntos.GetPointer("NtSetInformationProcess");
		GlobalConfig::Instance().NtDebugActiveProcess = ntos.GetPointer("NtDebugActiveProcess");
		GlobalConfig::Instance().NtCreateDebugObject = ntos.GetPointer("NtCreateDebugObject");
		GlobalConfig::Instance().NtRemoveProcessDebug = ntos.GetPointer("NtRemoveProcessDebug");
		GlobalConfig::Instance().NtWaitForDebugEvent = ntos.GetPointer("NtWaitForDebugEvent");
		GlobalConfig::Instance().NtDebugContinue = ntos.GetPointer("NtDebugContinue");
		GlobalConfig::Instance().NtReadVirtualMemory = ntos.GetPointer("NtReadVirtualMemory");
		GlobalConfig::Instance().NtWriteVirtualMemory = ntos.GetPointer("NtWriteVirtualMemory");
		GlobalConfig::Instance().NtTerminateProcess = ntos.GetPointer("NtTerminateProcess");
		GlobalConfig::Instance().NtTerminateThread = ntos.GetPointer("NtTerminateThread");
		GlobalConfig::Instance().ZwProtectVirtualMemory = ntos.GetPointer("ZwProtectVirtualMemory");

		GlobalConfig::Instance().ObpCallPostOperationCallbacks = ntos.GetPointer("ObpCallPostOperationCallbacks");
		GlobalConfig::Instance().ObpCallPreOperationCallbacks = ntos.GetPointer("ObpCallPreOperationCallbacks");

		//Debug Funtions
		GlobalConfig::Instance().NtCreateDebugObject = ntos.GetPointer("NtCreateDebugObject");
		GlobalConfig::Instance().NtDebugActiveProcess = ntos.GetPointer("NtDebugActiveProcess");
		GlobalConfig::Instance().DbgkCreateThread = ntos.GetPointer("DbgkCreateThread");
		GlobalConfig::Instance().DbgkExitThread = ntos.GetPointer("DbgkExitThread");
		GlobalConfig::Instance().DbgkExitProcess = ntos.GetPointer("DbgkExitProcess");
		GlobalConfig::Instance().DbgkMapViewOfSection = ntos.GetPointer("DbgkMapViewOfSection");
		GlobalConfig::Instance().DbgkUnMapViewOfSection = ntos.GetPointer("DbgkUnMapViewOfSection");
		GlobalConfig::Instance().KiDispatchException = ntos.GetPointer("KiDispatchException");
		GlobalConfig::Instance().NtWaitForDebugEvent = ntos.GetPointer("NtWaitForDebugEvent");
		GlobalConfig::Instance().DbgkpCloseObject = ntos.GetPointer("DbgkpCloseObject");
		GlobalConfig::Instance().NtDebugContinue = ntos.GetPointer("NtDebugContinue");
		GlobalConfig::Instance().DbgkpMarkProcessPeb = ntos.GetPointer("DbgkpMarkProcessPeb");
		GlobalConfig::Instance().DbgkForwardException = ntos.GetPointer("DbgkForwardException");
		GlobalConfig::Instance().ObCreateObjectType = ntos.GetPointer("ObCreateObjectType");
		GlobalConfig::Instance().DbgkDebugObjectType = ntos.GetPointer("DbgkDebugObjectType");


		GlobalConfig::Instance().ObTypeIndexTable = ntos.GetPointer("ObTypeIndexTable");
		GlobalConfig::Instance().PsTerminateProcess = ntos.GetPointer("PsTerminateProcess");
		GlobalConfig::Instance().DbgkpWakeTarget = ntos.GetPointer("DbgkpWakeTarget");
		GlobalConfig::Instance().PsGetNextProcess = ntos.GetPointer("PsGetNextProcess");
		GlobalConfig::Instance().PspCheckForInvalidAccessByProtection = ntos.GetPointer("PspCheckForInvalidAccessByProtection");
		GlobalConfig::Instance().PsGetNextProcessThread = ntos.GetPointer("PsGetNextProcessThread");
		GlobalConfig::Instance().PsSynchronizeWithThreadInsertion = ntos.GetPointer("PsSynchronizeWithThreadInsertion");
		GlobalConfig::Instance().PsSuspendThread = ntos.GetPointer("PsSuspendThread");
		GlobalConfig::Instance().PsResumeThread = ntos.GetPointer("PsResumeThread");
		GlobalConfig::Instance().DbgkpSectionToFileHandle = ntos.GetPointer("DbgkpSectionToFileHandle");
		GlobalConfig::Instance().PsQuerySystemDllInfo = ntos.GetPointer("PsQuerySystemDllInfo");
		GlobalConfig::Instance().DbgkpSuspendProcess = ntos.GetPointer("DbgkpSuspendProcess");
		GlobalConfig::Instance().PsThawMultiProcess = ntos.GetPointer("PsThawMultiProcess");
		GlobalConfig::Instance().MmGetFileNameForAddress = ntos.GetPointer("MmGetFileNameForAddress");
		GlobalConfig::Instance().PsCallImageNotifyRoutines = ntos.GetPointer("PsCallImageNotifyRoutines");
		GlobalConfig::Instance().PspReferenceSystemDll = ntos.GetPointer("PspReferenceSystemDll");
		GlobalConfig::Instance().MiSectionControlArea = ntos.GetPointer("MiSectionControlArea");
		GlobalConfig::Instance().MiReferenceControlAreaFile = ntos.GetPointer("MiReferenceControlAreaFile");
		GlobalConfig::Instance().ObFastDereferenceObject = ntos.GetPointer("ObFastDereferenceObject");
		GlobalConfig::Instance().DbgkpConvertKernelToUserStateChange = ntos.GetPointer("DbgkpConvertKernelToUserStateChange");
		GlobalConfig::Instance().DbgkpOpenHandles = ntos.GetPointer("DbgkpOpenHandles");
		GlobalConfig::Instance().DbgkpSendApiMessageLpc = ntos.GetPointer("DbgkpSendApiMessageLpc");
		GlobalConfig::Instance().DbgkpSendErrorMessage = ntos.GetPointer("DbgkpSendErrorMessage");
		GlobalConfig::Instance().PsCaptureExceptionPort = ntos.GetPointer("PsCaptureExceptionPort");
		GlobalConfig::Instance().ObpReferenceObjectByHandleWithTag = ntos.GetPointer("ObpReferenceObjectByHandleWithTag");
		GlobalConfig::Instance().MmPfnDatabaseAddress = ntos.GetPointer("MmPfnDatabase");
		GlobalConfig::Instance().PspLoadImageNotifyRoutine = ntos.GetPointer("PspLoadImageNotifyRoutine");
		GlobalConfig::Instance().CallbackListHead = ntos.GetPointer("CallbackListHead");
		GlobalConfig::Instance().PspCreateProcessNotifyRoutine = ntos.GetPointer("PspCreateProcessNotifyRoutine");
		GlobalConfig::Instance().PspCreateThreadNotifyRoutine = ntos.GetPointer("PspCreateThreadNotifyRoutine");
		GlobalConfig::Instance().MiGetPteAddress = (INT64(__fastcall*)(UINT64))ntos.GetPointer("MiGetPteAddress");



		GlobalConfig::Instance().ThreadHideFromDebuggerFlagOffset = (ULONG)ntos.GetOffset("_ETHREAD", "HideFromDebugger");
		GlobalConfig::Instance().BypassProcessFreezeFlagOffset = (ULONG)ntos.GetOffset("_KTHREAD", "BypassProcessFreeze");
		GlobalConfig::Instance().SeAuditProcessCreationInfoOffset = (ULONG)ntos.GetOffset("_EPROCESS", "SeAuditProcessCreationInfo");
		GlobalConfig::Instance().ActiveProcessLinksOffset = (ULONG)ntos.GetOffset("_EPROCESS", "ActiveProcessLinks");
		GlobalConfig::Instance().ObjectTable = (ULONG)ntos.GetOffset("_EPROCESS", "ObjectTable");
		GlobalConfig::Instance().ThreadBreakOnTerminationFlagOffset = (ULONG)ntos.GetOffset("_ETHREAD", "BreakOnTermination");
		GlobalConfig::Instance().PicoContextOffset = (ULONG)ntos.GetOffset("_ETHREAD", "PicoContext");
		GlobalConfig::Instance().RestrictSetThreadContextOffset = (ULONG)ntos.GetOffset("_EPROCESS", "RestrictSetThreadContext");
		GlobalConfig::Instance().DebugPortOffset = (ULONG)ntos.GetOffset("_EPROCESS", "DebugPort");
		GlobalConfig::Instance().WoW64ProcessOffset = (ULONG)ntos.GetOffset("_EPROCESS", "WoW64Process");
		GlobalConfig::Instance().ProtectionOffset = (ULONG)ntos.GetOffset("_EPROCESS", "Protection");
		GlobalConfig::Instance().PcbSecureStateOffset = (ULONG)ntos.GetOffset("_KPROCESS", "SecureState");
		GlobalConfig::Instance().DirectoryTableBaseOffset = (ULONG)ntos.GetOffset("_KPROCESS", "DirectoryTableBase");
		GlobalConfig::Instance().UserDirectoryTableBaseOffset = (ULONG)ntos.GetOffset("_KPROCESS", "UserDirectoryTableBase");
		GlobalConfig::Instance().RundownProtectOffset = (ULONG)ntos.GetOffset("_EPROCESS", "RundownProtect");
		GlobalConfig::Instance().UniqueProcessIdOffset = (ULONG)ntos.GetOffset("_EPROCESS", "UniqueProcessId");
		GlobalConfig::Instance().SectionObjectOffset = (ULONG)ntos.GetOffset("_EPROCESS", "SectionObject");
		GlobalConfig::Instance().SectionBaseAddressOffset = (ULONG)ntos.GetOffset("_EPROCESS", "SectionBaseAddress");
		GlobalConfig::Instance().PebOffset = (ULONG)ntos.GetOffset("_EPROCESS", "Peb");
		GlobalConfig::Instance().FlagsOffset = (ULONG)ntos.GetOffset("_EPROCESS", "Flags");
		GlobalConfig::Instance().ExitTimeOffset = (ULONG)ntos.GetOffset("_EPROCESS", "ExitTime");
		GlobalConfig::Instance().MachineOffset = (ULONG)ntos.GetOffset("_EPROCESS", "Machine");
		GlobalConfig::Instance().ThreadListHeadOffset = (ULONG)ntos.GetOffset("_EPROCESS", "ThreadListHead");
		GlobalConfig::Instance().ThreadListEntryOffset = (ULONG)ntos.GetOffset("_ETHREAD", "ThreadListEntry");
		GlobalConfig::Instance().MiscFlagsOffset = (ULONG)ntos.GetOffset("_KTHREAD", "MiscFlags");
		GlobalConfig::Instance().ApcStateOffset = (ULONG)ntos.GetOffset("_KTHREAD", "ApcState");
		GlobalConfig::Instance().CrossThreadFlagsOffset = (ULONG)ntos.GetOffset("_ETHREAD", "CrossThreadFlags");
		GlobalConfig::Instance().ThreadRundownProtectOffset = (ULONG)ntos.GetOffset("_ETHREAD", "RundownProtect");
		GlobalConfig::Instance().Win32StartAddressOffset = (ULONG)ntos.GetOffset("_ETHREAD", "Win32StartAddress");
		GlobalConfig::Instance().CidOffset = (ULONG)ntos.GetOffset("_ETHREAD", "Cid");
		GlobalConfig::Instance().SameThreadPassiveFlagsOffset = (ULONG)ntos.GetOffset("_ETHREAD", "SameThreadPassiveFlags");
		GlobalConfig::Instance().TebOffset = (ULONG)ntos.GetOffset("_KTHREAD", "Teb");
		GlobalConfig::Instance().TcbPreviousModeOffset = (ULONG)ntos.GetOffset("_KTHREAD", "PreviousMode");
		GlobalConfig::Instance().TcbProcessOffset = (ULONG)ntos.GetOffset("_KTHREAD", "Process");
		GlobalConfig::Instance().ApcStateProcessOffset = (ULONG)ntos.GetOffset("_KAPC_STATE", "Process");
		GlobalConfig::Instance().StaticUnicodeBufferOffset = (ULONG)ntos.GetOffset("_TEB", "StaticUnicodeBuffer");
		GlobalConfig::Instance().SameTebFlagsOffset = (ULONG)ntos.GetOffset("_TEB", "SameTebFlags");
		GlobalConfig::Instance().NtTibArbitraryUserPointerOffset = (ULONG)ntos.GetOffset("_NT_TIB", "ArbitraryUserPointer");


	}

	ShvOsDebugPrint("NtSetInformationThread:[%p]\n", GlobalConfig::Instance().NtSetInformationThread);
	ShvOsDebugPrint("NtQueryInformationProcess:[%p]\n", GlobalConfig::Instance().NtQueryInformationProcess);
	ShvOsDebugPrint("NtQueryObject:[%p]\n", GlobalConfig::Instance().NtQueryObject);
	ShvOsDebugPrint("NtSystemDebugControl:[%p]\n", GlobalConfig::Instance().NtSystemDebugControl);
	ShvOsDebugPrint("NtSetContextThread:[%p]\n", GlobalConfig::Instance().NtSetContextThread);
	ShvOsDebugPrint("NtQuerySystemInformation:[%p]\n", GlobalConfig::Instance().NtQuerySystemInformation);
	ShvOsDebugPrint("NtGetContextThread:[%p]\n", GlobalConfig::Instance().NtGetContextThread);
	ShvOsDebugPrint("NtClose:[%p]\n", GlobalConfig::Instance().NtClose);
	ShvOsDebugPrint("NtQueryInformationThread:[%p]\n", GlobalConfig::Instance().NtQueryInformationThread);
	ShvOsDebugPrint("NtCreateThreadEx:[%p]\n", GlobalConfig::Instance().NtCreateThreadEx);
	ShvOsDebugPrint("NtCreateFile:[%p]\n", GlobalConfig::Instance().NtCreateFile);
	ShvOsDebugPrint("NtCreateProcessEx:[%p]\n", GlobalConfig::Instance().NtCreateProcessEx);
	ShvOsDebugPrint("NtYieldExecution:[%p]\n", GlobalConfig::Instance().NtYieldExecution);
	ShvOsDebugPrint("NtQuerySystemTime:[%p]\n", GlobalConfig::Instance().NtQuerySystemTime);
	ShvOsDebugPrint("NtQueryPerformanceCounter:[%p]\n", GlobalConfig::Instance().NtQueryPerformanceCounter);
	ShvOsDebugPrint("NtContinue:[%p]\n", GlobalConfig::Instance().NtContinue);
	ShvOsDebugPrint("NtContinueEx:[%p]\n", GlobalConfig::Instance().NtContinueEx);
	ShvOsDebugPrint("NtQueryInformationJobObject:[%p]\n", GlobalConfig::Instance().NtQueryInformationJobObject);
	ShvOsDebugPrint("NtCreateUserProcess:[%p]\n", GlobalConfig::Instance().NtCreateUserProcess);
	ShvOsDebugPrint("NtGetNextProcess:[%p]\n", GlobalConfig::Instance().NtGetNextProcess);
	ShvOsDebugPrint("NtOpenProcess:[%p]\n", GlobalConfig::Instance().NtOpenProcess);
	ShvOsDebugPrint("NtOpenThread:[%p]\n", GlobalConfig::Instance().NtOpenThread);
	ShvOsDebugPrint("NtSetInformationProcess:[%p]\n", GlobalConfig::Instance().NtSetInformationProcess);
	ShvOsDebugPrint("NtRemoveProcessDebug:[%p]\n", GlobalConfig::Instance().NtRemoveProcessDebug);
	ShvOsDebugPrint("NtWaitForDebugEvent:[%p]\n", GlobalConfig::Instance().NtWaitForDebugEvent);
	ShvOsDebugPrint("NtReadVirtualMemory:[%p]\n", GlobalConfig::Instance().NtReadVirtualMemory);
	ShvOsDebugPrint("NtWriteVirtualMemory:[%p]\n", GlobalConfig::Instance().NtWriteVirtualMemory);
	ShvOsDebugPrint("NtTerminateProcess:[%p]\n", GlobalConfig::Instance().NtTerminateProcess);
	ShvOsDebugPrint("NtTerminateThread:[%p]\n", GlobalConfig::Instance().NtTerminateThread);

	ShvOsDebugPrint("MmPfnDatabase:[%p]\n", GlobalConfig::Instance().MmPfnDatabaseAddress);
	ShvOsDebugPrint("MiGetPteAddress:[%p]\n", GlobalConfig::Instance().MiGetPteAddress);
	ShvOsDebugPrint("ThreadHideFromDebuggerFlagOffset:[%p]\n", GlobalConfig::Instance().ThreadHideFromDebuggerFlagOffset);
	ShvOsDebugPrint("BypassProcessFreezeFlagOffset:[%p]\n", GlobalConfig::Instance().BypassProcessFreezeFlagOffset);
	ShvOsDebugPrint("SeAuditProcessCreationInfoOffset:[%p]\n", GlobalConfig::Instance().SeAuditProcessCreationInfoOffset);
	ShvOsDebugPrint("ThreadBreakOnTerminationFlagOffset:[%p]\n", GlobalConfig::Instance().ThreadBreakOnTerminationFlagOffset);
	ShvOsDebugPrint("PicoContextOffset:[%p]\n", GlobalConfig::Instance().PicoContextOffset);
	ShvOsDebugPrint("RestrictSetThreadContextOffset:[%p]\n", GlobalConfig::Instance().RestrictSetThreadContextOffset);
	ShvOsDebugPrint("NtUserGetThreadState:[%p]\n", GlobalConfig::Instance().NtUserGetThreadState);
	ShvOsDebugPrint("NtUserFindWindowEx:[%p]\n", GlobalConfig::Instance().NtUserFindWindowEx);
	ShvOsDebugPrint("NtUserBuildHwndList:[%p]\n", GlobalConfig::Instance().NtUserBuildHwndList);
	ShvOsDebugPrint("NtUserQueryWindow:[%p]\n", GlobalConfig::Instance().NtUserQueryWindow);
	ShvOsDebugPrint("NtUserGetForegroundWindow:[%p]\n", GlobalConfig::Instance().NtUserGetForegroundWindow);
	ShvOsDebugPrint("NtUserGetClassName:[%p]\n", GlobalConfig::Instance().NtUserGetClassName);
	ShvOsDebugPrint("NtUserInternalGetWindowText:[%p]\n", GlobalConfig::Instance().NtUserInternalGetWindowText);
	ShvOsDebugPrint("NtUserEnumDisplayDevices:[%p]\n", GlobalConfig::Instance().NtUserEnumDisplayDevices);
	ShvOsDebugPrint("NtGdiExtTextOutW:[%p]\n", GlobalConfig::Instance().NtGdiExtTextOutW);


	//Debug
	ShvOsDebugPrint("NtCreateDebugObject:[%p]\n", GlobalConfig::Instance().NtCreateDebugObject);
	ShvOsDebugPrint("NtDebugActiveProcess:[%p]\n", GlobalConfig::Instance().NtDebugActiveProcess);
	ShvOsDebugPrint("DbgkCreateThread:[%p]\n", GlobalConfig::Instance().DbgkCreateThread);
	ShvOsDebugPrint("DbgkExitThread:[%p]\n", GlobalConfig::Instance().DbgkExitThread);
	ShvOsDebugPrint("DbgkExitProcess:[%p]\n", GlobalConfig::Instance().DbgkExitProcess);
	ShvOsDebugPrint("DbgkMapViewOfSection:[%p]\n", GlobalConfig::Instance().DbgkMapViewOfSection);
	ShvOsDebugPrint("DbgkUnMapViewOfSection:[%p]\n", GlobalConfig::Instance().DbgkUnMapViewOfSection);
	ShvOsDebugPrint("KiDispatchException:[%p]\n", GlobalConfig::Instance().KiDispatchException);
	ShvOsDebugPrint("NtWaitForDebugEvent:[%p]\n", GlobalConfig::Instance().NtWaitForDebugEvent);
	ShvOsDebugPrint("DbgkpCloseObject:[%p]\n", GlobalConfig::Instance().DbgkpCloseObject);
	ShvOsDebugPrint("NtDebugContinue:[%p]\n", GlobalConfig::Instance().NtDebugContinue);
	ShvOsDebugPrint("DbgkpMarkProcessPeb:[%p]\n", GlobalConfig::Instance().DbgkpMarkProcessPeb);
	ShvOsDebugPrint("DbgkForwardException:[%p]\n", GlobalConfig::Instance().DbgkForwardException);

	ShvOsDebugPrint("ObpCallPreOperationCallbacks:[%p]\n", GlobalConfig::Instance().ObpCallPreOperationCallbacks);
	ShvOsDebugPrint("ObpCallPostOperationCallbacks:[%p]\n", GlobalConfig::Instance().ObpCallPostOperationCallbacks);


	ShvOsDebugPrint("ObCreateObjectType:[%p]\n", GlobalConfig::Instance().ObCreateObjectType);
	ShvOsDebugPrint("ObTypeIndexTable:[%p]\n", GlobalConfig::Instance().ObTypeIndexTable);
	ShvOsDebugPrint("DbgkDebugObjectType:[%p]\n", GlobalConfig::Instance().DbgkDebugObjectType);
	ShvOsDebugPrint("PspLoadImageNotifyRoutine:[%p]\n", GlobalConfig::Instance().PspLoadImageNotifyRoutine);
	ShvOsDebugPrint("CallbackListHead:[%p]\n", GlobalConfig::Instance().CallbackListHead);
	ShvOsDebugPrint("PspCreateProcessNotifyRoutine:[%p]\n", GlobalConfig::Instance().PspCreateProcessNotifyRoutine);

	ShvOsDebugPrint("PsTerminateProcess:[%p]\n", GlobalConfig::Instance().PsTerminateProcess);
	ShvOsDebugPrint("DbgkpWakeTarget:[%p]\n", GlobalConfig::Instance().DbgkpWakeTarget);
	ShvOsDebugPrint("PsGetNextProcess:[%p]\n", GlobalConfig::Instance().PsGetNextProcess);
	ShvOsDebugPrint("PspCheckForInvalidAccessByProtection:[%p]\n", GlobalConfig::Instance().PspCheckForInvalidAccessByProtection);
	ShvOsDebugPrint("PsGetNextProcessThread:[%p]\n", GlobalConfig::Instance().PsGetNextProcessThread);
	ShvOsDebugPrint("PsSynchronizeWithThreadInsertion:[%p]\n", GlobalConfig::Instance().PsSynchronizeWithThreadInsertion);
	ShvOsDebugPrint("PsSuspendThread:[%p]\n", GlobalConfig::Instance().PsSuspendThread);
	ShvOsDebugPrint("PsResumeThread:[%p]\n", GlobalConfig::Instance().PsResumeThread);
	ShvOsDebugPrint("DbgkpSectionToFileHandle:[%p]\n", GlobalConfig::Instance().DbgkpSectionToFileHandle);
	ShvOsDebugPrint("PsQuerySystemDllInfo:[%p]\n", GlobalConfig::Instance().PsQuerySystemDllInfo);
	ShvOsDebugPrint("DbgkpSuspendProcess:[%p]\n", GlobalConfig::Instance().DbgkpSuspendProcess);
	ShvOsDebugPrint("PsThawMultiProcess:[%p]\n", GlobalConfig::Instance().PsThawMultiProcess);
	ShvOsDebugPrint("MmGetFileNameForAddress:[%p]\n", GlobalConfig::Instance().MmGetFileNameForAddress);
	ShvOsDebugPrint("PsCallImageNotifyRoutines:[%p]\n", GlobalConfig::Instance().PsCallImageNotifyRoutines);
	ShvOsDebugPrint("PspReferenceSystemDll:[%p]\n", GlobalConfig::Instance().PspReferenceSystemDll);
	ShvOsDebugPrint("MiSectionControlArea:[%p]\n", GlobalConfig::Instance().MiSectionControlArea);
	ShvOsDebugPrint("MiReferenceControlAreaFile:[%p]\n", GlobalConfig::Instance().MiReferenceControlAreaFile);
	ShvOsDebugPrint("ObFastDereferenceObject:[%p]\n", GlobalConfig::Instance().ObFastDereferenceObject);
	ShvOsDebugPrint("DbgkpConvertKernelToUserStateChange:[%p]\n", GlobalConfig::Instance().DbgkpConvertKernelToUserStateChange);

	ShvOsDebugPrint("DebugPort:[%p]\n", GlobalConfig::Instance().DebugPortOffset);
	ShvOsDebugPrint("WoW64Process:[%p]\n", GlobalConfig::Instance().WoW64ProcessOffset);
	ShvOsDebugPrint("ProtectionOffset:[%p]\n", GlobalConfig::Instance().ProtectionOffset);
	ShvOsDebugPrint("PcbSecureStateOffset:[%p]\n", GlobalConfig::Instance().PcbSecureStateOffset);
	ShvOsDebugPrint("RundownProtectOffset:[%p]\n", GlobalConfig::Instance().RundownProtectOffset);
	ShvOsDebugPrint("SectionObjectOffset:[%p]\n", GlobalConfig::Instance().SectionObjectOffset);
	ShvOsDebugPrint("UniqueProcessIdOffset:[%p]\n", GlobalConfig::Instance().UniqueProcessIdOffset);
	ShvOsDebugPrint("MiscFlagsOffset:[%p]\n", GlobalConfig::Instance().MiscFlagsOffset);
	ShvOsDebugPrint("CrossThreadFlagsOffset:[%p]\n", GlobalConfig::Instance().CrossThreadFlagsOffset);
	ShvOsDebugPrint("ThreadRundownProtectOffset:[%p]\n", GlobalConfig::Instance().ThreadRundownProtectOffset);
	ShvOsDebugPrint("SectionBaseAddressOffset:[%p]\n", GlobalConfig::Instance().SectionBaseAddressOffset);
	ShvOsDebugPrint("Win32StartAddressOffset:[%p]\n", GlobalConfig::Instance().Win32StartAddressOffset);
	ShvOsDebugPrint("CidOffset:[%p]\n", GlobalConfig::Instance().CidOffset);
	ShvOsDebugPrint("ApcStateOffset:[%p]\n", GlobalConfig::Instance().ApcStateOffset);
	ShvOsDebugPrint("ApcStateProcessOffset:[%p]\n", GlobalConfig::Instance().ApcStateProcessOffset);
	ShvOsDebugPrint("PebOffset:[%p]\n", GlobalConfig::Instance().PebOffset);
	ShvOsDebugPrint("TebOffset:[%p]\n", GlobalConfig::Instance().TebOffset);
	ShvOsDebugPrint("StaticUnicodeBufferOffset:[%p]\n", GlobalConfig::Instance().StaticUnicodeBufferOffset);
	ShvOsDebugPrint("NtTibArbitraryUserPointerOffset:[%p]\n", GlobalConfig::Instance().NtTibArbitraryUserPointerOffset);
	ShvOsDebugPrint("FlagsOffset:[%p]\n", GlobalConfig::Instance().FlagsOffset);
	ShvOsDebugPrint("SameThreadPassiveFlagsOffset:[%p]\n", GlobalConfig::Instance().SameThreadPassiveFlagsOffset);
	ShvOsDebugPrint("ExitTimeOffset:[%p]\n", GlobalConfig::Instance().ExitTimeOffset);
	ShvOsDebugPrint("SameTebFlagsOffset:[%p]\n", GlobalConfig::Instance().SameTebFlagsOffset);
	ShvOsDebugPrint("TcbPreviousModeOffset:[%p]\n", GlobalConfig::Instance().TcbPreviousModeOffset);
	ShvOsDebugPrint("TcbProcessOffset:[%p]\n", GlobalConfig::Instance().TcbProcessOffset);
	ShvOsDebugPrint("MachineOffset:[%p]\n", GlobalConfig::Instance().MachineOffset);
	ShvOsDebugPrint("DbgkpOpenHandles:[%p]\n", GlobalConfig::Instance().DbgkpOpenHandles);
	ShvOsDebugPrint("DbgkpSendApiMessageLpc:[%p]\n", GlobalConfig::Instance().DbgkpSendApiMessageLpc);
	ShvOsDebugPrint("DbgkpSendErrorMessage:[%p]\n", GlobalConfig::Instance().DbgkpSendErrorMessage);
	ShvOsDebugPrint("PsCaptureExceptionPort:[%p]\n", GlobalConfig::Instance().PsCaptureExceptionPort);
	ShvOsDebugPrint("ObpReferenceObjectByHandleWithTag:[%p]\n", GlobalConfig::Instance().ObpReferenceObjectByHandleWithTag);
	ShvOsDebugPrint("ObjectTable:[%p]\n", GlobalConfig::Instance().ObjectTable);
	ShvOsDebugPrint("ActiveProcessLinksOffset:[%p]\n", GlobalConfig::Instance().ActiveProcessLinksOffset);
	ShvOsDebugPrint("DirectoryTableBaseOffset:[%p]\n", GlobalConfig::Instance().DirectoryTableBaseOffset);
	ShvOsDebugPrint("UserDirectoryTableBaseOffset:[%p]\n", GlobalConfig::Instance().UserDirectoryTableBaseOffset);
	ShvOsDebugPrint("ZwProtectVirtualMemory:[%p]\n", GlobalConfig::Instance().ZwProtectVirtualMemory);
	ShvOsDebugPrint("ThreadListHeadOffset:[%p]\n", GlobalConfig::Instance().ThreadListHeadOffset);
	ShvOsDebugPrint("ThreadListEntryOffset:[%p]\n", GlobalConfig::Instance().ThreadListEntryOffset);



	if (GlobalConfig::Instance().NtSetInformationThread &&
		GlobalConfig::Instance().NtQueryInformationProcess &&
		GlobalConfig::Instance().NtQueryObject &&
		GlobalConfig::Instance().NtSystemDebugControl &&
		GlobalConfig::Instance().NtSetContextThread &&
		GlobalConfig::Instance().NtQuerySystemInformation &&
		GlobalConfig::Instance().NtGetContextThread &&
		GlobalConfig::Instance().NtClose &&
		GlobalConfig::Instance().NtQueryInformationThread &&
		GlobalConfig::Instance().NtCreateThreadEx &&
		GlobalConfig::Instance().NtCreateFile &&
		GlobalConfig::Instance().NtCreateProcessEx &&
		GlobalConfig::Instance().NtYieldExecution &&
		GlobalConfig::Instance().NtQuerySystemTime &&
		GlobalConfig::Instance().NtQueryPerformanceCounter &&
		GlobalConfig::Instance().NtContinue &&
		GlobalConfig::Instance().NtContinueEx &&
		GlobalConfig::Instance().NtQueryInformationJobObject &&
		GlobalConfig::Instance().NtCreateUserProcess &&
		GlobalConfig::Instance().NtGetNextProcess &&
		GlobalConfig::Instance().NtOpenProcess &&
		GlobalConfig::Instance().NtOpenThread &&
		GlobalConfig::Instance().NtSetInformationProcess &&
		GlobalConfig::Instance().NtDebugActiveProcess &&
		GlobalConfig::Instance().NtCreateDebugObject &&
		GlobalConfig::Instance().NtRemoveProcessDebug &&
		GlobalConfig::Instance().NtWaitForDebugEvent &&
		GlobalConfig::Instance().NtDebugContinue &&
		GlobalConfig::Instance().NtReadVirtualMemory &&
		GlobalConfig::Instance().NtWriteVirtualMemory &&
		GlobalConfig::Instance().NtTerminateProcess &&
		GlobalConfig::Instance().NtTerminateThread &&
		GlobalConfig::Instance().MmPfnDatabaseAddress &&
		GlobalConfig::Instance().ThreadHideFromDebuggerFlagOffset &&
		GlobalConfig::Instance().BypassProcessFreezeFlagOffset &&
		GlobalConfig::Instance().SeAuditProcessCreationInfoOffset &&
		GlobalConfig::Instance().ThreadBreakOnTerminationFlagOffset &&
		GlobalConfig::Instance().PicoContextOffset &&
		GlobalConfig::Instance().RestrictSetThreadContextOffset &&
		GlobalConfig::Instance().KiUserExceptionDispatcherAddress &&
		GlobalConfig::Instance().NtUserGetThreadState &&
		GlobalConfig::Instance().NtUserFindWindowEx &&
		GlobalConfig::Instance().NtUserBuildHwndList &&
		GlobalConfig::Instance().NtUserQueryWindow &&
		GlobalConfig::Instance().NtUserGetForegroundWindow &&
		GlobalConfig::Instance().NtUserGetClassName &&
		GlobalConfig::Instance().NtUserInternalGetWindowText &&
		GlobalConfig::Instance().NtUserEnumDisplayDevices &&
		GlobalConfig::Instance().NtGdiExtTextOutW &&

		GlobalConfig::Instance().NtCreateDebugObject &&
		GlobalConfig::Instance().NtDebugActiveProcess &&
		GlobalConfig::Instance().DbgkCreateThread &&
		GlobalConfig::Instance().DbgkExitThread &&
		GlobalConfig::Instance().DbgkExitProcess &&
		GlobalConfig::Instance().DbgkMapViewOfSection &&
		GlobalConfig::Instance().DbgkUnMapViewOfSection &&
		GlobalConfig::Instance().KiDispatchException &&
		GlobalConfig::Instance().NtWaitForDebugEvent &&
		GlobalConfig::Instance().DbgkpCloseObject &&
		GlobalConfig::Instance().NtDebugContinue &&
		GlobalConfig::Instance().DbgkpMarkProcessPeb &&
		GlobalConfig::Instance().DbgkForwardException &&
		GlobalConfig::Instance().ObCreateObjectType &&
		GlobalConfig::Instance().ObTypeIndexTable &&
		GlobalConfig::Instance().PsTerminateProcess &&
		GlobalConfig::Instance().DbgkpWakeTarget &&
		GlobalConfig::Instance().PsGetNextProcess &&
		GlobalConfig::Instance().DebugPortOffset &&
		GlobalConfig::Instance().WoW64ProcessOffset &&
		GlobalConfig::Instance().DbgkDebugObjectType &&
		GlobalConfig::Instance().ProtectionOffset &&
		GlobalConfig::Instance().PcbSecureStateOffset &&
		GlobalConfig::Instance().RundownProtectOffset &&
		GlobalConfig::Instance().UniqueProcessIdOffset &&
		GlobalConfig::Instance().PsGetNextProcessThread &&
		GlobalConfig::Instance().MiscFlagsOffset &&
		GlobalConfig::Instance().PsSynchronizeWithThreadInsertion &&
		GlobalConfig::Instance().CrossThreadFlagsOffset &&
		GlobalConfig::Instance().ThreadRundownProtectOffset &&
		GlobalConfig::Instance().PsSuspendThread &&
		GlobalConfig::Instance().SectionObjectOffset &&
		GlobalConfig::Instance().DbgkpSectionToFileHandle &&
		GlobalConfig::Instance().SectionBaseAddressOffset &&
		GlobalConfig::Instance().Win32StartAddressOffset &&
		GlobalConfig::Instance().PsResumeThread &&
		GlobalConfig::Instance().CidOffset &&
		GlobalConfig::Instance().PsQuerySystemDllInfo &&
		GlobalConfig::Instance().ApcStateOffset &&
		GlobalConfig::Instance().ApcStateProcessOffset &&
		GlobalConfig::Instance().DbgkpSuspendProcess &&
		GlobalConfig::Instance().PsThawMultiProcess &&
		GlobalConfig::Instance().MmGetFileNameForAddress &&
		GlobalConfig::Instance().PebOffset &&
		GlobalConfig::Instance().TebOffset &&
		GlobalConfig::Instance().StaticUnicodeBufferOffset &&
		GlobalConfig::Instance().NtTibArbitraryUserPointerOffset &&
		GlobalConfig::Instance().FlagsOffset &&
		GlobalConfig::Instance().PsCallImageNotifyRoutines &&
		GlobalConfig::Instance().PspReferenceSystemDll &&
		GlobalConfig::Instance().MiSectionControlArea &&
		GlobalConfig::Instance().MiReferenceControlAreaFile &&
		GlobalConfig::Instance().ObFastDereferenceObject &&
		GlobalConfig::Instance().SameThreadPassiveFlagsOffset &&
		GlobalConfig::Instance().ExitTimeOffset &&
		GlobalConfig::Instance().SameTebFlagsOffset &&
		GlobalConfig::Instance().TcbPreviousModeOffset &&
		GlobalConfig::Instance().TcbProcessOffset &&
		GlobalConfig::Instance().MachineOffset &&
		GlobalConfig::Instance().DbgkpOpenHandles &&
		GlobalConfig::Instance().DbgkpSendApiMessageLpc &&
		GlobalConfig::Instance().DbgkpSendErrorMessage &&
		GlobalConfig::Instance().PsCaptureExceptionPort &&
		GlobalConfig::Instance().DbgkpConvertKernelToUserStateChange &&
		GlobalConfig::Instance().ObpReferenceObjectByHandleWithTag &&
		GlobalConfig::Instance().PspLoadImageNotifyRoutine &&
		GlobalConfig::Instance().CallbackListHead &&
		GlobalConfig::Instance().PspCreateProcessNotifyRoutine &&
		GlobalConfig::Instance().PspCreateThreadNotifyRoutine &&
		GlobalConfig::Instance().ObjectTable &&
		GlobalConfig::Instance().ObpCallPostOperationCallbacks &&
		GlobalConfig::Instance().ObpCallPreOperationCallbacks &&
		GlobalConfig::Instance().ActiveProcessLinksOffset &&
		GlobalConfig::Instance().DirectoryTableBaseOffset &&
		GlobalConfig::Instance().UserDirectoryTableBaseOffset &&
		GlobalConfig::Instance().ZwProtectVirtualMemory &&
		GlobalConfig::Instance().ThreadListHeadOffset &&
		GlobalConfig::Instance().ThreadListEntryOffset &&
		GlobalConfig::Instance().PspCheckForInvalidAccessByProtection)

		return TRUE;
	else
		return FALSE;
}

BOOLEAN BuildComunication()
{
	UNICODE_STRING DriverName = { 0 };
	RtlInitUnicodeString(&DriverName, L"\\Driver\\volmgr");
	PDRIVER_OBJECT DriverObject = NULL;

	if (NT_SUCCESS(ObReferenceObjectByName(
		&DriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&DriverObject
	)) == FALSE)
	{
		ShvOsDebugPrint("ObReferenceObjectByName Faild!\n");
		return FALSE;
	}

	if (!DriverObject)
	{
		ShvOsDebugPrint("driverObject is NULL!\n");
		return FALSE;
	}

	GlobalConfig::Instance().ComunicateFunctionAddress = (UINT64)DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	return EPTHookFunctionTwoTrampoline(GlobalConfig::Instance().ComunicateFunctionAddress,
		(UINT64)ProxIoctlFuntion,
		(UINT64)GlobalConfig::Instance().volmgrCodeCaves[GlobalConfig::Instance().volmgrAlignIndex++],
		(UINT64*)&OriginalIoctlFuntion,
		(UINT64)GlobalConfig::Instance().volmgrAddress);
}




EXTERN_C VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	CallBack::Destory();
	DebugSystem::Destory();
	Hide::Destory();
	UserHook::Destory();
	Handle::Destory();
	Protect::Destory();

	//卸载通讯
	UnHookSsdt(GlobalConfig::Instance().ComunicateFunctionAddress);

	//EptHookDriverCallBackDestory();
	//HiderUninitialize();
	//LARGE_INTEGER WaitTime;
	//WaitTime.QuadPart = -30000000LL; // 3000ms
	//KeDelayExecutionThread(KernelMode, FALSE, &WaitTime);
	//PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
	//PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);

	//ShvOsDebugPrint("serverdbg DriverUnload STATUS_SUCCESS!\n");
}
EXTERN_C BOOLEAN ShvVmCallEx(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9, UINT64 r10, UINT64 r11, UINT64 r12, UINT64 r13, UINT64 r14, UINT64 r15);

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DeleteMySelf(pRegPath); //自删除
	//UNREFERENCED_PARAMETER(pRegPath);
	pDriverObject->DriverUnload = DriverUnload;
	RTL_OSVERSIONINFOW VersionInfo = { 0 };
	VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&VersionInfo);
	GlobalConfig::Instance().CurrentWindowsBuildNumber = VersionInfo.dwBuildNumber;

	do
	{
		if (FindCodeCaves() == FALSE)
		{
			ShvOsDebugPrint("FindCodeCaves Faild!\n");
			break;
		}

		if (InitOffsets() == FALSE)
		{
			ShvOsDebugPrint("InitOffsets Faild!\n");
			break;
		}
		//建立通讯
		if (BuildComunication() == FALSE)
		{
			ShvOsDebugPrint("BuildComunication Faild!\n");
			break;
		}

		CallBack::Initialize(pDriverObject);
		//CallBack::Register();
		Handle::Initialize();
		Protect::Initialize();
		UserHook::Initialize();

		DebugSystem::Initialize();
		Hide::Initialize();

		//PEPROCESS TargetEprocess = GetProcessById((HANDLE)2140);

		//UINT64 Cr3 = GetCr3(TargetEprocess);

		//PVOID FakePageVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
		//if (!FakePageVirtualAddress)
		//{
		//	ShvOsDebugPrint("ExAllocatePoolWithTag faild\n");
		//	return FALSE;
		//}

		//RtlZeroMemory(FakePageVirtualAddress, PAGE_SIZE);


		//UINT64 FakePagePhysicalAddress = MmGetPhysicalAddress(FakePageVirtualAddress).QuadPart;
		//PMDL PMdl = { 0 };
		//Memory::LockMemory(2140, (PVOID)0x230000, (SIZE_T)0xD8000, &PMdl);
		//KAFFINITY AffinityMask;
		//for (SIZE_T i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
		//{
		//	AffinityMask = MathPower(2, (int)i);
		//	KeSetSystemAffinityThread(AffinityMask);
		//	//0x7FF776050000	0xD8000	
		//	ShvVmCallEx(VMCALL_EPT_HIDE_MEMORY, 2140, Cr3, 0x230000, 0xD8000, FakePagePhysicalAddress, 0, 0, 0, 0);
		//}

		return STATUS_SUCCESS;
	} while (FALSE);
	return STATUS_UNSUCCESSFUL;
}

