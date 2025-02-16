#include "Hides.h"
#include "Utils.h"

EXTERN_C NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C NTSTATUS NTAPI ZwQueryInformationProcess(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

EXTERN_C NTSTATUS NTAPI ZwSetInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
);
EXTERN_C BOOLEAN NTAPI PsIsProcessBeingDebugged(PEPROCESS Process);



EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb
(
	IN PEPROCESS Process
);


CONST char* SystemName[] =
{ "werfault.exe"
,"svchost.exe",
"explorer.exe"
,"cmd.exe",
"conhost.exe"  ,
"csrss.exe" };


CONST unsigned short* HiddenDeviceNames[] =
{
	L"\\??\\shv",
	L"\\??\\serverdbg"
};

CONST unsigned short* HiddenWindowNames[] =
{
	L"x64dbg",
	L"x32dbg",
	L"Process Hacker",
	L"Import reconstructor",
	L"[CPU",
	L"Debug",
	L"scylla",
	L"HyperHide",
	L"disassembly",
	L"ida",
	L"HyperHide",
	L"Sysinternals",
	L"虚途" //虚途
};

CONST unsigned short* HiddenApplicationNames[] =
{
	L"ollydbg.exe",
	L"ida.exe",
	L"ida64.exe",
	L"idag.exe",
	L"idag64.exe",
	L"idaw.exe",
	L"idaw64.exe",
	L"idaq.exe",
	L"idaq64.exe",
	L"idau.exe",
	L"idau64.exe",
	L"scylla.exe",
	L"scylla_x64.exe",
	L"scylla_x86.exe",
	L"protection_id.exe",
	L"x64dbg.exe",
	L"x32dbg.exe",
	L"reshacker.exe",
	L"ImportREC.exe",
	L"devenv.exe",
	L"ProcessHacker.exe",
	L"tcpview.exe",
	L"autoruns.exe",
	L"autorunsc.exe",
	L"filemon.exe",
	L"procmon.exe",
	L"regmon.exe",
	L"wireshark.exe",
	L"dumpcap.exe",
	L"HookExplorer.exe",
	L"ImportRCE.exe",
	L"PETools.exe",
	L"LordPE.exe",
	L"SysInspector.exe",
	L"proc_analyzer.exe",
	L"sysAnalyzer.exe",
	L"sniff_hit.exe",
	L"joeboxcontrol.exe",
	L"joeboxserver.exe",
	L"ResourceHacker.exe",
	L"fiddler.exe",
	L"httpdebugger.exe",
	L"procexp64.exe",
	L"procexp.exe",
	L"Dbgview.exe",
	L"procmon64.exe",
	L"xtlh.exe",//虚途
};

CONST unsigned short* HiddenWindowClassNames[] =
{
	L"Qt5QWindowIcon" // Ida and x64dbg ClassNames
	L"ObsidianGUI",
	L"idawindow",
	L"tnavbox",
	L"idaview",
	L"tgrzoom",
	L"Qt672dQWindowIcon" //虚途
};



VOID TruncateThreadList(PEPROCESS TargetProcess, PETHREAD ThreadObject)
{
	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;
		//如果在回调中检测到是被调试的进程则进入循环

		if (HiddenProcess->DebuggedProcess == TargetProcess)
		{
			//ShvOsDebugPrint("TruncateThreadList TargetProcess:[%p]\n", TargetProcess);
			PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;
			while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
			{
				PHIDDEN_THREAD HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
				CurrentThread = CurrentThread->Flink;

				if (HiddenThread->ThreadObject == ThreadObject)
				{
					//ShvOsDebugPrint("TruncateThreadList\n");
					RemoveEntryList(&HiddenThread->HiddenThreadList);
					ExFreePoolWithTag(HiddenThread, POOLTAG);

					goto End;
				}
			}
		}
	}

End:
	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
}

VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	if (Create == FALSE)
	{
		PETHREAD CurrentThread;
		if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &CurrentThread)) == TRUE)
		{
			TruncateThreadList(PidToProcess(ProcessId), CurrentThread);
		}

	}
}


BOOLEAN IsSetThreadContextRestricted(PEPROCESS TargetProcess)
{


	if (GlobalConfig::Instance().CurrentWindowsBuildNumber < WINDOWS_10_VERSION_REDSTONE2)
		return FALSE;
	else if (GlobalConfig::Instance().CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
		return *(ULONG*)((ULONG64)TargetProcess + GlobalConfig::Instance().RestrictSetThreadContextOffset) & 0x2 ? TRUE : FALSE;
	else
		return *(ULONG*)((ULONG64)TargetProcess + GlobalConfig::Instance().RestrictSetThreadContextOffset) & 0x20000 ? TRUE : FALSE;
}

BOOLEAN IsDriverHandleHidden(PUNICODE_STRING SymLink)
{
	if (SymLink->Buffer == NULL || SymLink->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbiddenSymLink;

	for (ULONG64 i = 0; i < sizeof(HiddenDeviceNames) / sizeof(HiddenDeviceNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbiddenSymLink, HiddenDeviceNames[i]);
		if (RtlCompareUnicodeString(&ForbiddenSymLink, SymLink, TRUE) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN IsPicoContextNull(PETHREAD TargetThread)
{
	if (GlobalConfig::Instance().CurrentWindowsBuildNumber < WINDOWS_8_1)
		return TRUE;
	else
		return !(*(ULONG64*)((ULONG64)TargetThread + GlobalConfig::Instance().PicoContextOffset));
}

PHIDDEN_PROCESS QueryHiddenProcess(PEPROCESS TargetProcess)
{
	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;

		if (HiddenProcess->DebuggedProcess == TargetProcess)
		{
			KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
			return HiddenProcess;
		}
	}

	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	return NULL;
}

VOID FilterHandles(PSYSTEM_HANDLE_INFORMATION HandleInfo)
{
	ULONG TotalDeletedHandles = 0;
	BOOLEAN Found;

	do
	{
		ULONG FirstHandlePosition = 0;
		Found = FALSE;

		for (ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
		{
			PEPROCESS OriginalProcess = PidToProcess((HANDLE)HandleInfo->Handles[i].UniqueProcessId);
			if (OriginalProcess != NULL)
			{
				UNICODE_STRING ProcessName = PsQueryFullProcessImageName(OriginalProcess);

				if (Found == FALSE && IsProcessNameBad(&ProcessName) == TRUE)
				{
					FirstHandlePosition = i;
					Found = TRUE;
				}

				else if (Found == TRUE && IsProcessNameBad(&ProcessName) == FALSE)
				{
					RtlCopyBytes(&HandleInfo->Handles[FirstHandlePosition], &HandleInfo->Handles[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (HandleInfo->NumberOfHandles - i));
					HandleInfo->NumberOfHandles = HandleInfo->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
					break;
				}

				if (i + 1 == HandleInfo->NumberOfHandles && Found == TRUE)
				{
					RtlSecureZeroMemory(&HandleInfo->Handles[FirstHandlePosition], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (i - FirstHandlePosition));
					HandleInfo->NumberOfHandles = HandleInfo->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
				}
			}
		}
	} while (Found == TRUE);


	RtlSecureZeroMemory(&HandleInfo->Handles[HandleInfo->NumberOfHandles], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * TotalDeletedHandles);
}


VOID FilterHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX HandleInfoEx)
{
	ULONG TotalDeletedHandles = 0;
	BOOLEAN Found;

	do
	{
		ULONG FirstHandlePosition = 0;
		Found = FALSE;

		for (ULONG i = 0; i < HandleInfoEx->NumberOfHandles; i++)
		{
			PEPROCESS OriginalProcess = PidToProcess((HANDLE)HandleInfoEx->Handles[i].UniqueProcessId);
			if (OriginalProcess != NULL)
			{
				UNICODE_STRING ProcessName = PsQueryFullProcessImageName(OriginalProcess);

				if (Found == FALSE && IsProcessNameBad(&ProcessName) == TRUE)
				{
					FirstHandlePosition = i;
					Found = TRUE;
				}

				else if (Found == TRUE && IsProcessNameBad(&ProcessName) == FALSE)
				{
					RtlCopyBytes(&HandleInfoEx->Handles[FirstHandlePosition], &HandleInfoEx->Handles[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (HandleInfoEx->NumberOfHandles - i));
					HandleInfoEx->NumberOfHandles = HandleInfoEx->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
					break;
				}

				if (i + 1 == HandleInfoEx->NumberOfHandles && Found == TRUE)
				{
					RtlSecureZeroMemory(&HandleInfoEx->Handles[FirstHandlePosition], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (i - FirstHandlePosition));
					HandleInfoEx->NumberOfHandles = HandleInfoEx->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
				}
			}
		}
	} while (Found == TRUE);


	RtlSecureZeroMemory(&HandleInfoEx->Handles[HandleInfoEx->NumberOfHandles], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * TotalDeletedHandles);
}

VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo)
{
	//
	// First process is always system so there won't be a case when forbidden process is first
	//
	PSYSTEM_PROCESS_INFO PrevProcessInfo = NULL;

	while (PrevProcessInfo != ProcessInfo)
	{
		ULONG Offset = ProcessInfo->NextEntryOffset;

		if (IsProcessNameBad(&ProcessInfo->ImageName) == TRUE)
		{
			if (ProcessInfo->NextEntryOffset == NULL)
				PrevProcessInfo->NextEntryOffset = NULL;

			else
				PrevProcessInfo->NextEntryOffset += ProcessInfo->NextEntryOffset;

			RtlSecureZeroMemory(ProcessInfo, sizeof(SYSTEM_PROCESS_INFO) + ProcessInfo->NumberOfThreads * sizeof(SYSTEM_THREAD_INFORMATION) - sizeof(SYSTEM_THREAD_INFORMATION));
		}

		else
		{
			PrevProcessInfo = ProcessInfo;
		}

		ProcessInfo = (PSYSTEM_PROCESS_INFO)((UCHAR*)ProcessInfo + Offset);
	}
}

VOID CounterUpdater(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	LARGE_INTEGER TimeToWait = { 0 };
	TimeToWait.QuadPart = -10000LL; // relative 1ms

	while (GlobalConfig::Instance().StopCounterThread == FALSE)
	{
		//ShvOsDebugPrint("CounterUpdater\n");
		KeDelayExecutionThread(KernelMode, FALSE, &TimeToWait);

		KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);
		PLIST_ENTRY current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
		while (current != &GlobalConfig::Instance().HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(current, HIDDEN_PROCESS, HiddenProcessesList);
			current = current->Flink;

			if (HiddenProcess->DebuggedProcess != NULL &&
				HiddenProcess->ProcessPaused == FALSE &&
				HiddenProcess->Kusd.KuserSharedData != NULL &&
				HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == TRUE)
			{

				*(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->InterruptTime = *(ULONG64*)&GlobalConfig::Instance().KernelKuserSharedDataAddress->InterruptTime.LowPart - HiddenProcess->Kusd.DeltaInterruptTime;
				HiddenProcess->Kusd.KuserSharedData->InterruptTime.High2Time = HiddenProcess->Kusd.KuserSharedData->InterruptTime.High1Time;

				*(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->SystemTime = *(ULONG64*)&GlobalConfig::Instance().KernelKuserSharedDataAddress->SystemTime.LowPart - HiddenProcess->Kusd.DeltaSystemTime;
				HiddenProcess->Kusd.KuserSharedData->SystemTime.High2Time = HiddenProcess->Kusd.KuserSharedData->SystemTime.High1Time;

				HiddenProcess->Kusd.KuserSharedData->LastSystemRITEventTickCount = GlobalConfig::Instance().KernelKuserSharedDataAddress->LastSystemRITEventTickCount - HiddenProcess->Kusd.DeltaLastSystemRITEventTickCount;

				*(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->TickCount = *(ULONG64*)&GlobalConfig::Instance().KernelKuserSharedDataAddress->TickCount.LowPart - HiddenProcess->Kusd.DeltaTickCount;
				HiddenProcess->Kusd.KuserSharedData->TickCount.High2Time = HiddenProcess->Kusd.KuserSharedData->TickCount.High1Time;

				HiddenProcess->Kusd.KuserSharedData->TimeUpdateLock = GlobalConfig::Instance().KernelKuserSharedDataAddress->TimeUpdateLock - HiddenProcess->Kusd.DeltaTimeUpdateLock;

				HiddenProcess->Kusd.KuserSharedData->BaselineSystemTimeQpc = GlobalConfig::Instance().KernelKuserSharedDataAddress->BaselineSystemTimeQpc - HiddenProcess->Kusd.DeltaBaselineSystemQpc;
				HiddenProcess->Kusd.KuserSharedData->BaselineInterruptTimeQpc = HiddenProcess->Kusd.KuserSharedData->BaselineSystemTimeQpc;
			}
		}
		KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

BOOLEAN HiderInitialize()
{

	InitializeListHead(&GlobalConfig::Instance().HiddenProcessesHead);
	KeInitializeGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	GlobalConfig::Instance().KernelKuserSharedDataAddress = (PKUSER_SHARED_DATA)(KUSER_SHARED_DATA_KERNELMODE);
	GlobalConfig::Instance().StopCounterThread = FALSE;

	if (NT_SUCCESS(PsCreateSystemThread(&GlobalConfig::Instance().CounterThreadHandle, 0, 0, 0, 0, CounterUpdater, NULL)) == FALSE)
	{
		ShvOsDebugPrint("Couldn't create system thread\n");
		return FALSE;
	}
	return TRUE;
}

BOOLEAN IsDebuggerProcess(PEPROCESS TargetProcess)
{
	BOOLEAN Status = FALSE;
	if (TargetProcess == NULL)
	{
		ShvOsDebugPrint("Target process equal null\n");
		return Status;
	}

	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;

		if (HiddenProcess->DebuggerProcess == TargetProcess)
		{
			Status = TRUE;
			break;
		}
	}
	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	return Status;
}

VOID DeleteThreadList(PHIDDEN_PROCESS HiddenProcess)
{
	PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;
	while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
	{
		PHIDDEN_THREAD HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
		RemoveEntryList(CurrentThread);
		CurrentThread = CurrentThread->Flink;
		ExFreePoolWithTag(HiddenThread, POOLTAG);
	}
}

VOID UnHookKuserSharedData(PHIDDEN_PROCESS HiddenProcess)
{
	KAPC_STATE State;
	HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] = FALSE;

	KeStackAttachProcess((PRKPROCESS)HiddenProcess->DebuggedProcess, &State);

	PMMPFN FakeKUSDMmpfn = (PMMPFN)(GlobalConfig::Instance().MmPfnDatabaseAddress + HiddenProcess->Kusd.PteKuserSharedData->PageFrameNumber);
	FakeKUSDMmpfn->u4.EntireField &= ~0x200000000000000;

	MmFreeContiguousMemory(HiddenProcess->Kusd.KuserSharedData);

	HiddenProcess->Kusd.KuserSharedData = NULL;
	HiddenProcess->Kusd.PteKuserSharedData->PageFrameNumber = HiddenProcess->Kusd.OriginalKuserSharedDataPfn;
	KeUnstackDetachProcess(&State);
}

BOOLEAN RemoveEntry(PEPROCESS TargetProcess)
{
	if (TargetProcess == NULL)
	{
		ShvOsDebugPrint("Target process equal null\n");
		return FALSE;
	}

	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;

		if (HiddenProcess->DebuggedProcess == TargetProcess || HiddenProcess->DebuggerProcess == TargetProcess)
		{
			ShvOsDebugPrint("RemoveEntry HiddenProcess->DebuggedProcess:[%p]  ", HiddenProcess->DebuggedProcess);
			ShvOsDebugPrint("HiddenProcess->DebuggerProcess:[%p]\n", HiddenProcess->DebuggedProcess);
			
			DeleteThreadList(HiddenProcess);

			RemoveEntryList(Current->Blink);

			if (HiddenProcess->Kusd.KuserSharedData != NULL)
			{
				UnHookKuserSharedData(HiddenProcess);
			}

			ExFreePoolWithTag(HiddenProcess, POOLTAG);
		}
	}

	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	return TRUE;
}

VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{

	if (Create == FALSE)
	{
		RemoveEntry(PidToProcess(ProcessId));
	}

}

VOID HiderUninitialize()
{
	PETHREAD CounterThread;
	GlobalConfig::Instance().StopCounterThread = TRUE;
	ObReferenceObjectByHandle(GlobalConfig::Instance().CounterThreadHandle, NULL, *PsThreadType, KernelMode, (PVOID*)&CounterThread, NULL);
	KeWaitForSingleObject(CounterThread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(CounterThread);
	ZwClose(GlobalConfig::Instance().CounterThreadHandle);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;

		if (HiddenProcess->HiddenThreads.HiddenThreadList.Flink != NULL)
		{
			if (HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == TRUE)
			{
				HiddenProcess->Kusd.PteKuserSharedData->PageFrameNumber = HiddenProcess->Kusd.OriginalKuserSharedDataPfn;
				MmFreeContiguousMemory(HiddenProcess->Kusd.KuserSharedData);
			}

			PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;
			while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
			{
				PHIDDEN_THREAD HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
				CurrentThread = CurrentThread->Flink;
				ExFreePoolWithTag(HiddenThread, POOLTAG);
			}
		}

		ExFreePoolWithTag(HiddenProcess, POOLTAG);
	}

}

//对于这个函数，现在想的是，如果虚途领航传递参数到驱动，那么DebuggerProcess就是虚途领航进程
//而DebuggedProcess是要被调试的目标进程
BOOLEAN CreateEntry(PEPROCESS DebuggerProcess, PEPROCESS DebuggedProcess)
{
	PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)ExAllocatePoolWithTag(NonPagedPool, sizeof(HIDDEN_PROCESS), POOLTAG);
	if (HiddenProcess == NULL)
	{
		ShvOsDebugPrint("Allocation failed\n");

		return FALSE;
	}
	RtlSecureZeroMemory(HiddenProcess, sizeof(HIDDEN_PROCESS));

	HiddenProcess->DebuggedProcess = DebuggedProcess;
	HiddenProcess->DebuggerProcess = DebuggerProcess;
	ShvOsDebugPrint("HiddenProcess->DebuggedProcess:[%p]\n", DebuggedProcess);
	ShvOsDebugPrint("HiddenProcess->DebuggerProcess:[%p]\n", DebuggerProcess);

	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	InsertTailList(&GlobalConfig::Instance().HiddenProcessesHead, &HiddenProcess->HiddenProcessesList);
	InitializeListHead(&HiddenProcess->HiddenThreads.HiddenThreadList);
	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	return TRUE;
}

ULONG64 GetPteAddress(ULONG64 Address)
{
	RTL_OSVERSIONINFOW versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&versionInfo);

	if (versionInfo.dwBuildNumber <= WINDOWS_10_VERSION_THRESHOLD2)
	{
		return (ULONG64)(((Address >> 9) & 0x7FFFFFFFF8) - 0x98000000000);
	}
	else
	{
		return GlobalConfig::Instance().MiGetPteAddress(Address);
	}
}

VOID HookKuserSharedData(PHIDDEN_PROCESS HiddenProcess)
{
	KAPC_STATE State;
	PHYSICAL_ADDRESS PhysicalMax;
	PhysicalMax.QuadPart = ~0ULL;

	PVOID NewKuserSharedData = MmAllocateContiguousMemory(PAGE_SIZE, PhysicalMax);

	ULONG64 PfnNewKuserSharedData = MmGetPhysicalAddress(NewKuserSharedData).QuadPart >> PAGE_SHIFT;

	KeStackAttachProcess((PRKPROCESS)HiddenProcess->DebuggedProcess, &State);

	PMMPFN FakeKUSDMmpfn = (PMMPFN)(GlobalConfig::Instance().MmPfnDatabaseAddress + PfnNewKuserSharedData);

	FakeKUSDMmpfn->u4.EntireField |= 0x200000000000000;

	RtlCopyMemory(NewKuserSharedData, (PVOID)KUSER_SHARED_DATA_USERMODE, PAGE_SIZE);

	HiddenProcess->Kusd.PteKuserSharedData = (VMX_PTE*)GetPteAddress(KUSER_SHARED_DATA_USERMODE);

	HiddenProcess->Kusd.OriginalKuserSharedDataPfn = (ULONG)HiddenProcess->Kusd.PteKuserSharedData->PageFrameNumber;
	HiddenProcess->Kusd.PteKuserSharedData->PageFrameNumber = PfnNewKuserSharedData;
	HiddenProcess->Kusd.KuserSharedData = (PKUSER_SHARED_DATA)NewKuserSharedData;

	KeUnstackDetachProcess(&State);
}

//
// Append and return.If thread struct already exist return it
//
PHIDDEN_THREAD AppendThreadList(PEPROCESS TargetProcess, PETHREAD ThreadObject)
{
	ShvOsDebugPrint("AppendThreadList\n");
	PHIDDEN_THREAD HiddenThread = NULL;
	BOOLEAN Acquired = KeTryToAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;

		if (HiddenProcess->DebuggedProcess == TargetProcess)
		{
			PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;

			while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
			{
				HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
				CurrentThread = CurrentThread->Flink;

				if (HiddenThread->ThreadObject == ThreadObject)
					goto End;
			}

			HiddenThread = (PHIDDEN_THREAD)ExAllocatePoolWithTag(NonPagedPool, sizeof(HIDDEN_THREAD), POOLTAG);
			if (HiddenThread == NULL)
				return NULL;

			RtlSecureZeroMemory(HiddenThread, sizeof(HIDDEN_THREAD));
			HiddenThread->ThreadObject = ThreadObject;

			InsertTailList(&HiddenProcess->HiddenThreads.HiddenThreadList, &HiddenThread->HiddenThreadList);
			break;
		}
	}

End:
	if (Acquired == TRUE)
		KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	return HiddenThread;
}

BOOLEAN ClearThreadHideFromDebuggerFlag(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, POOLTAG);

	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, POOLTAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;

				Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread);

				if (NT_SUCCESS(Status) == TRUE)
				{
					if (*(ULONG*)((ULONG64)Thread + GlobalConfig::Instance().ThreadHideFromDebuggerFlagOffset) & 0x4)
					{
						PHIDDEN_THREAD HiddenThread = AppendThreadList(TargetProcess, Thread);
						if (HiddenThread != NULL)
							HiddenThread->IsThreadHidden = TRUE;

						*(ULONG*)((ULONG64)Thread + GlobalConfig::Instance().ThreadHideFromDebuggerFlagOffset) &= ~0x4LU;
					}
				}
			}

			ExFreePoolWithTag(ProcInfo, POOLTAG);
			return TRUE;
		}
	}

	ExFreePoolWithTag(ProcInfo, POOLTAG);
	return FALSE;
}

BOOLEAN ClearBypassProcessFreezeFlag(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	if (GlobalConfig::Instance().CurrentWindowsBuildNumber < WINDOWS_10_VERSION_19H1)
	{
		ShvOsDebugPrint("This flag doesn't exit on this version of windows\n");
		return FALSE;
	}

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, POOLTAG);

	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, POOLTAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread);

				if (NT_SUCCESS(Status) == TRUE)
					*(ULONG*)((ULONG64)Thread + GlobalConfig::Instance().BypassProcessFreezeFlagOffset) &= ~(1 << 21);
			}

			ExFreePoolWithTag(ProcInfo, POOLTAG);
			return TRUE;
		}
	}

	ExFreePoolWithTag(ProcInfo, POOLTAG);
	return FALSE;
}

BOOLEAN SetPebDeuggerFlag(PEPROCESS TargetProcess, BOOLEAN Value)
{
	PPEB Peb = PsGetProcessPeb(TargetProcess);
	PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);
	if (Peb32 != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb32->BeingDebugged = Value;

			Peb->BeingDebugged = Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ShvOsDebugPrint("Access Violation\n");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}
	else if (Peb != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb->BeingDebugged = Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ShvOsDebugPrint("Access Violation\n");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}
		KeUnstackDetachProcess(&State);
	}
	else
	{
		ShvOsDebugPrint("Both pebs doesn't exist\n");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN ClearPebNtGlobalFlag(PEPROCESS TargetProcess)
{
	PPEB Peb = PsGetProcessPeb(TargetProcess);
	PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);
	if (Peb32 != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb32->NtGlobalFlag &= ~0x70;

			Peb->NtGlobalFlag &= ~0x70;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ShvOsDebugPrint("Access Violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}
	else if (Peb != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb->NtGlobalFlag &= ~0x70;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ShvOsDebugPrint("Access Violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}
		KeUnstackDetachProcess(&State);
	}
	else
	{
		ShvOsDebugPrint("Both pebs doesn't exist");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN ClearHeapFlags(PEPROCESS TargetProcess)
{
	PPEB Peb = (PPEB)PsGetProcessPeb(TargetProcess);
	PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

	// https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/heap-flags/
	// In all versions of Windows, the value of the Flags 
	// field is normally set to HEAP_GROWABLE(2), 
	// and the ForceFlags field is normally set to 0

	// 32-bit process.Both of these default values depend on the[subsystem] of its host process
	if (Peb32 != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

		__try
		{
			for (size_t i = 0; i < Peb32->NumberOfHeaps; i++)
			{
				ULONG Heap = *(ULONG*)(Peb32->ProcessHeaps + 4 * i);

				// Heap Flags
				*(ULONG*)(Heap + 0x40) &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED);

				// Heap Force Flags
				*(ULONG*)(Heap + 0x44) &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ShvOsDebugPrint("Access violation\n");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}

	if (Peb != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

		__try
		{
			for (size_t i = 0; i < Peb->NumberOfHeaps; i++)
			{
				PHEAP Heap = (PHEAP)Peb->ProcessHeaps;
				Heap->Flags &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED);
				Heap->ForceFlags &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ShvOsDebugPrint("Access violation\n");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}
	else
	{
		ShvOsDebugPrint("Both Peb and Peb32 doesn't exist\n");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN ClearProcessBreakOnTerminationFlag(PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG BreakOnTermination;
		if (ZwQueryInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG), NULL) >= 0)
		{
			HiddenProcess->ValueProcessBreakOnTermination = BreakOnTermination & 1;

			BreakOnTermination = 0;
			if (ZwSetInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG)) >= 0)
				return TRUE;
		}

		ObCloseHandle(ProcessHandle, KernelMode);
	}

	return FALSE;
}

BOOLEAN ClearThreadBreakOnTerminationFlags(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, POOLTAG);
	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, POOLTAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				if (PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread) >= 0)
				{

					if (*(ULONG*)((ULONG64)Thread + GlobalConfig::Instance().ThreadBreakOnTerminationFlagOffset) & 0x20)
					{
						PHIDDEN_THREAD HiddenThread = AppendThreadList(TargetProcess, Thread);
						if (HiddenThread != NULL)
						{
							HiddenThread->BreakOnTermination = TRUE;

							*(ULONG*)((ULONG64)Thread + GlobalConfig::Instance().ThreadBreakOnTerminationFlagOffset) &= ~0x20;

							ExFreePoolWithTag(ProcInfo, POOLTAG);
							return TRUE;
						}
					}
				}
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, POOLTAG);
	return FALSE;
}

VOID SaveProcessDebugFlags(PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG DebugFlags;
		if (ZwQueryInformationProcess(ProcessHandle, ProcessDebugFlags, &DebugFlags, sizeof(ULONG), NULL) >= 0 && PsIsProcessBeingDebugged(HiddenProcess->DebuggedProcess) == FALSE)
		{
			HiddenProcess->ValueProcessDebugFlags = !DebugFlags;
		}

		ObCloseHandle(ProcessHandle, KernelMode);
	}
}

VOID SaveProcessHandleTracing(PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG64 ProcessInformationBuffer[2] = { 0 };

		NTSTATUS Status = ZwQueryInformationProcess(ProcessHandle, ProcessHandleTracing, &ProcessInformationBuffer[0], 16, NULL);
		if (Status == STATUS_SUCCESS)
			HiddenProcess->ProcessHandleTracingEnabled = 1;
		else if (Status == STATUS_INVALID_PARAMETER)
			HiddenProcess->ProcessHandleTracingEnabled = 0;

		ObCloseHandle(ProcessHandle, KernelMode);
	}
}

BOOLEAN Hide(PHIDE_INFO HideInfo)
{
	PEPROCESS TargetProcess = PidToProcess((HANDLE)HideInfo->Pid);

	if (TargetProcess == NULL)
	{
		ShvOsDebugPrint("Process with pid: %d doesn't exist\n", HideInfo->Pid);
		return FALSE;
	}

	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
	while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
		Current = Current->Flink;

		if (HiddenProcess->DebuggedProcess == TargetProcess)
		{
			if (HideInfo->HookKuserSharedData == TRUE && HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == FALSE)
				HookKuserSharedData(HiddenProcess);

			else if (HideInfo->HookKuserSharedData == FALSE && HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == TRUE)
				UnHookKuserSharedData(HiddenProcess);

			if (HideInfo->HookNtSetInformationThread == TRUE && HiddenProcess->HideTypes[HIDE_NT_SET_INFORMATION_THREAD] == FALSE)
				InitializeListHead(&HiddenProcess->HiddenThreads.HiddenThreadList);

			if (HideInfo->ClearHideFromDebuggerFlag == TRUE && HiddenProcess->HideFromDebuggerFlagCleared == FALSE)
			{
				ClearThreadHideFromDebuggerFlag(HiddenProcess->DebuggedProcess);
				HiddenProcess->HideFromDebuggerFlagCleared = TRUE;
			}

			if (HideInfo->ClearBypassProcessFreeze == TRUE && HiddenProcess->BypassProcessFreezeFlagCleared == FALSE)
			{
				ClearBypassProcessFreezeFlag(HiddenProcess->DebuggedProcess);
				HiddenProcess->BypassProcessFreezeFlagCleared = TRUE;
			}

			if (HideInfo->ClearPebBeingDebugged == TRUE && HiddenProcess->PebBeingDebuggedCleared == FALSE)
			{
				SetPebDeuggerFlag(HiddenProcess->DebuggedProcess, FALSE);
				HiddenProcess->PebBeingDebuggedCleared = TRUE;
			}

			if (HideInfo->ClearPebNtGlobalFlag == TRUE && HiddenProcess->PebNtGlobalFlagCleared == FALSE)
			{
				ClearPebNtGlobalFlag(HiddenProcess->DebuggedProcess);
				HiddenProcess->PebNtGlobalFlagCleared = TRUE;
			}

			if (HideInfo->ClearHeapFlags == TRUE && HiddenProcess->HeapFlagsCleared == FALSE)
			{
				ClearHeapFlags(HiddenProcess->DebuggedProcess);
				HiddenProcess->HeapFlagsCleared = TRUE;
			}

			if (HideInfo->ClearKuserSharedData == TRUE && HiddenProcess->KUserSharedDataCleared == FALSE)
			{
				if (HiddenProcess->Kusd.KuserSharedData != NULL)
				{
					HiddenProcess->Kusd.KuserSharedData->KdDebuggerEnabled = 0;
					HiddenProcess->KUserSharedDataCleared = TRUE;
				}
			}

			if (HideInfo->ClearProcessBreakOnTerminationFlag == TRUE && HiddenProcess->ProcessBreakOnTerminationCleared == FALSE)
			{
				ClearProcessBreakOnTerminationFlag(HiddenProcess);
				HiddenProcess->ProcessBreakOnTerminationCleared = TRUE;
			}

			if (HideInfo->ClearThreadBreakOnTerminationFlag == TRUE && HiddenProcess->ThreadBreakOnTerminationCleared == FALSE)
			{
				ClearThreadBreakOnTerminationFlags(HiddenProcess->DebuggedProcess);
				HiddenProcess->ThreadBreakOnTerminationCleared = TRUE;
			}

			if (HideInfo->SaveProcessDebugFlags == TRUE && HiddenProcess->ProcessDebugFlagsSaved == FALSE)
			{
				SaveProcessDebugFlags(HiddenProcess);
				HiddenProcess->ProcessDebugFlagsSaved = TRUE;
			}

			if (HideInfo->SaveProcessHandleTracing == TRUE && HiddenProcess->ProcessHandleTracingSaved == FALSE)
			{
				SaveProcessHandleTracing(HiddenProcess);
				HiddenProcess->ProcessHandleTracingSaved = TRUE;
			}

			RtlCopyBytes(&HiddenProcess->HideTypes[0], &HideInfo->HookNtQueryInformationProcess, HIDE_LAST);
			ShvOsDebugPrint("RtlCopyBytes\n");
			KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
			return TRUE;
		}
	}

	ShvOsDebugPrint("Process with pid %d isn't in list\n", HideInfo->Pid);
	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	return FALSE;
}

BOOLEAN IsHidden(PEPROCESS TargetProcess, INT32 HideType)
{
	BOOLEAN Status = FALSE;
	if (HideType >= HIDE_LAST)
	{
		ShvOsDebugPrint("Wrong hide type\n");
		return Status;
	}

	KeAcquireGuardedMutex(&GlobalConfig::Instance().HiderMutex);

	//这里只对目标进程进行操作，局限比较大
	{
		PLIST_ENTRY Current = GlobalConfig::Instance().HiddenProcessesHead.Flink;
		while (Current != &GlobalConfig::Instance().HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			//DebuggedProcess是被调试的进程，这三行代码的作用是判断被调试的进程他的隐藏类型
			if (HiddenProcess->DebuggedProcess == TargetProcess)
			{
				Status = HiddenProcess->HideTypes[HideType];
				break;
			}
		}
	}

	//这里改成除了系统进程可以访问我们的隐藏，其他进程都不可以
	//{
	//	if (!PsIsSystemProcess(TargetProcess) && !IsSystemProcess(TargetProcess, SystemName))
	//	{
	//		KeReleaseGuardedMutex(&globalHiderMutex);
	//		return FALSE;
	//	}
	//	else
	//	{
	//		KeReleaseGuardedMutex(&globalHiderMutex);
	//		//不是系统进程我们就返回真
	//		return TRUE;
	//	}
	//}

	KeReleaseGuardedMutex(&GlobalConfig::Instance().HiderMutex);
	return Status;
}


BOOLEAN IsProcessNameBad(PUNICODE_STRING ProcessName)
{
	if (ProcessName->Buffer == NULL || ProcessName->Length == NULL)
		return FALSE;

	UNICODE_STRING CurrentProcessName = PsQueryFullProcessImageName(IoGetCurrentProcess());
	if (RtlCompareUnicodeString(ProcessName, &CurrentProcessName, FALSE) == 0)
		return FALSE;

	UNICODE_STRING ForbiddenProcessName;
	for (ULONG64 i = 0; i < sizeof(HiddenApplicationNames) / sizeof(HiddenApplicationNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbiddenProcessName, HiddenApplicationNames[i]);
		if (RtlCompareUnicodeString(&ForbiddenProcessName, ProcessName, TRUE) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN IsProcessWindowBad(PUNICODE_STRING WindowName)
{
	if (WindowName->Buffer == NULL || WindowName->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbiddenWindowName;
	for (ULONG64 i = 0; i < sizeof(HiddenWindowNames) / sizeof(HiddenWindowNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbiddenWindowName, HiddenWindowNames[i]);
		if (RtlUnicodeStringContains(WindowName, &ForbiddenWindowName, TRUE) == 0)
			return TRUE;
	}

	return FALSE;
}

BOOLEAN IsProcessWindowClassBad(PUNICODE_STRING WindowClassName)
{
	if (WindowClassName->Buffer == NULL || WindowClassName->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbbidenWindowClassName;

	for (ULONG64 i = 0; i < sizeof(HiddenWindowClassNames) / sizeof(HiddenWindowClassNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbbidenWindowClassName, HiddenWindowClassNames[i]);
		if (RtlCompareUnicodeString(WindowClassName, &ForbbidenWindowClassName, FALSE) == 0)
			return TRUE;
	}

	return FALSE;
}

BOOLEAN IsWindowBad(HANDLE hWnd)
{
	if (!GlobalConfig::Instance().OriginalNtUserQueryWindow)
	{
		ShvOsDebugPrint("GlobalConfig::Instance().OriginalNtUserQueryWindow is NULL\n");
		return FALSE;
	}

	PEPROCESS WindProcess = PidToProcess(GlobalConfig::Instance().OriginalNtUserQueryWindow(hWnd, WindowProcess));
	if (WindProcess == IoGetCurrentProcess())
		return FALSE;

	UNICODE_STRING WindowProcessName = PsQueryFullProcessImageName(WindProcess);

	return IsProcessNameBad(&WindowProcessName);
}

PEPROCESS GetProcessByName(CONST unsigned short* ProcessName)
{
	NTSTATUS Status;
	ULONG Bytes;


	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, POOLTAG);
	if (ProcInfo == NULL)
		return NULL;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, POOLTAG);
		return NULL;
	}

	UNICODE_STRING ProcessImageName;
	RtlCreateUnicodeString(&ProcessImageName, ProcessName);

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (Entry->ImageName.Buffer != NULL)
		{
			if (RtlCompareUnicodeString(&Entry->ImageName, &ProcessImageName, TRUE) == 0)
			{
				PEPROCESS CurrentPeprocess = PidToProcess(Entry->ProcessId);
				ExFreePoolWithTag(ProcInfo, POOLTAG);
				return CurrentPeprocess;
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, POOLTAG);
	return NULL;
}

