#include "EptHook.h"
#include "StructForEptHook.h"
#include "hides.h"
#include <intrin.h>
EXTERN_C BOOLEAN ShvVmCall(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9);
EXTERN_C BOOLEAN ShvVmCallEx(UINT64 vmcall_reason, UINT64 rdx, UINT64 r8, UINT64 r9, UINT64 r10, UINT64 r11, UINT64 r12, UINT64 r13, UINT64 r14, UINT64 r15);





VOID UnHookSsdt(UINT64 AddressOfTargetFunction)
{
	KAFFINITY AffinityMask;
	for (size_t i = 0; i < KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCall(VMCALL_EPT_UNHOOK_FUNCTION, AddressOfTargetFunction, 0, 0);
	}
}
VOID UnHookSssdt(UINT64 AddressOfTargetFunction)
{
	KAPC_STATE State;
	KAFFINITY AffinityMask;
	PEPROCESS CsrssProcess = GetCsrssProcess();

	KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

	for (size_t i = 0; i < KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);
		KeSetSystemAffinityThread(AffinityMask);
		ShvVmCall(VMCALL_EPT_UNHOOK_FUNCTION, AddressOfTargetFunction, 0, 0);
	}

	KeUnstackDetachProcess(&State);
}
BOOLEAN EPTHookFunctionTwoTrampoline(UINT64 targetAddress, UINT64 proxFucntion, UINT64 trampolineAddress, UINT64* originalFunction, UINT64 hookedModuleAddress)
{

	BOOLEAN rValue = FALSE;

	KAFFINITY AffinityMask;

	for (size_t i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);

		KeSetSystemAffinityThread(AffinityMask);

		rValue = ShvVmCallEx((UINT64)VMCALL_EPT_HOOK_FUNCTION_TWO_TRAMPOLINE, targetAddress, proxFucntion, trampolineAddress, (UINT64)originalFunction, hookedModuleAddress, 0, 0, 0, 0);

		if (!rValue)
			return rValue;
	}
	return TRUE;
}


BOOLEAN HookSssdtTwoTrampoline(PVOID AddressOfTargetFunction, PVOID ProxFunctionAddress, PVOID* OriginFunction)
{
	KAPC_STATE State;
	PEPROCESS CsrssProcess = GetCsrssProcess();

	KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

	if (!EPTHookFunctionTwoTrampoline((UINT64)AddressOfTargetFunction,
		(UINT64)ProxFunctionAddress,
		(UINT64)GlobalConfig::Instance().Win32kCodeCaves[GlobalConfig::Instance().Win32kAlignIndex++],
		(UINT64*)OriginFunction,
		(UINT64)GlobalConfig::Instance().Win32kAddress))
	{
		KeUnstackDetachProcess(&State);
		return FALSE;
	}

	KeUnstackDetachProcess(&State);
	return TRUE;
}
BOOLEAN HookSsdtTwoTrampoline(PVOID AddressOfTargetFunction, PVOID ProxFunctionAddress, PVOID* OriginFunction)
{

	if (!EPTHookFunctionTwoTrampoline((UINT64)AddressOfTargetFunction,
		(UINT64)ProxFunctionAddress,
		(UINT64)GlobalConfig::Instance().KernelCodeCaves[GlobalConfig::Instance().KernelAlignIndex++],
		(UINT64*)OriginFunction,
		(UINT64)GlobalConfig::Instance().NtoskrnlAddress))
		return FALSE;


	return TRUE;
}

BOOLEAN EPTHookFunctionOneTrampoline(UINT64 targetAddress, UINT64 proxFucntion, UINT64* originalFunction)
{
	BOOLEAN rValue = FALSE;

	KAFFINITY AffinityMask;

	for (size_t i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);

		KeSetSystemAffinityThread(AffinityMask);

		rValue = ShvVmCallEx(VMCALL_EPT_HOOK_FUNCTION_ONE_TRAMPOLINE, targetAddress, proxFucntion, (UINT64)originalFunction, 0, 0, 0, 0, 0, 0);
		if (!rValue)
			return rValue;
	}
	return TRUE;
}

NTSTATUS(NTAPI* OriginalNtOpenProcess)(PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId);
NTSTATUS NTAPI ProxNtOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId)
{
	//如果被调试进程的HIDE_NT_OPEN_PROCESS开关被设置，那么就进入if语句中
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_OPEN_PROCESS) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForWrite(ProcessHandle, 4, 1);
			ProbeForWrite(ObjectAttributes, 28, 4);
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
		if (ClientId != NULL)
		{

			__try
			{
				ProbeForRead(ClientId, 1, 4);
				volatile ULONG64 Touch = (ULONG64)ClientId->UniqueProcess;
				Touch = (ULONG64)ClientId->UniqueThread;
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			if (ClientId->UniqueProcess == NULL)
				return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

			PEPROCESS TargetProcess = PidToProcess(ClientId->UniqueProcess);

			UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(TargetProcess);

			//如果被调试进程想要打开我们要保护的程序比如说CheatEngine,那么我们就让他打不开
			if (IsProcessNameBad(&ProcessImageName) == TRUE)
			{

				//ShvOsDebugPrint("IsProcessNameBad\n");

				HANDLE OldPid = ClientId->UniqueProcess;

				ClientId->UniqueProcess = UlongToHandle(0xFFFFFFFC);

				NTSTATUS Status = OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

				ClientId->UniqueProcess = OldPid;

				return Status;
			}
		}

	}
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

}

NTSTATUS(NTAPI* OriginalNtContinueEx)(PCONTEXT Context, UINT64 TestAlert);
NTSTATUS NTAPI ProxNtContinueEx(PCONTEXT Context, UINT64 TestAlert)
{
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (IsHidden(CurrentProcess, HIDE_NT_CONTINUE) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForRead(Context, 1, 16);

			PHIDDEN_THREAD HiddenThread = AppendThreadList(CurrentProcess, (PETHREAD)KeGetCurrentThread());

			if ((Context->Dr0 != __readdr(0) && Context->Dr1 != __readdr(1) &&
				Context->Dr2 != __readdr(2) && Context->Dr3 != __readdr(3) &&
				Context->ContextFlags & 0x10 && HiddenThread != NULL) == TRUE)
			{
				RtlCopyBytes(&HiddenThread->FakeDebugContext.DR0, &Context->Dr0, sizeof(UINT64) * 6);
				RtlCopyBytes(&HiddenThread->FakeDebugContext.DebugControl, &Context->DebugControl, sizeof(UINT64) * 5);
			}

			Context->ContextFlags &= ~0x10;

			return OriginalNtContinueEx(Context, TestAlert);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	return OriginalNtContinueEx(Context, TestAlert);
}

HANDLE(NTAPI* OriginalNtUserFindWindowEx)(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type);
HANDLE NTAPI ProxNtUserFindWindowEx(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type)
{

	HANDLE hWnd = OriginalNtUserFindWindowEx(hwndParent, hwndChild, ClassName, WindowName, Type);
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_FIND_WINDOW_EX) == TRUE &&
		hWnd != NULL)
	{
		if (IsProcessWindowBad(WindowName) == TRUE || IsProcessWindowClassBad(ClassName) == TRUE)
			return 0;
	}

	return hWnd;
}


//有很大问题，需要思考
HANDLE(NTAPI* OriginalNtUserGetForegroundWindow)();
HANDLE NTAPI ProxNtUserGetForegroundWindow()
{
	HANDLE hWnd = OriginalNtUserGetForegroundWindow();
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_GET_FOREGROUND_WINDOW) == TRUE &&
		hWnd != NULL && IsWindowBad(hWnd) == TRUE)
	{
		if (GlobalConfig::Instance().NtUserGetThreadState)
			hWnd = GlobalConfig::Instance().NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
		else
		{
			ShvOsDebugPrint("GlobalConfig::Instance().NtUserGetThreadState is NULL\n");
		}
	}
	return hWnd;
}

HANDLE(NTAPI* OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);
HANDLE NTAPI ProxNtUserQueryWindow(HANDLE hWnd, WINDOWINFOCLASS WindowInfo)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_QUERY_WINDOW) == TRUE &&
		(WindowInfo == WindowProcess || WindowInfo == WindowThread) &&
		IsWindowBad(hWnd))
	{
		if (WindowInfo == WindowProcess)
			return PsGetCurrentProcessId();

		if (WindowInfo == WindowThread)
			return PsGetCurrentProcessId();
	}
	return OriginalNtUserQueryWindow(hWnd, WindowInfo);
}

NTSTATUS(NTAPI* OriginalNtUserBuildHwndList)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
NTSTATUS NTAPI ProxNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize)
{
	NTSTATUS Status = OriginalNtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_BUILD_HWND_LIST) == TRUE &&
		NT_SUCCESS(Status) == TRUE &&
		pWnd != NULL &&
		pBufSize != NULL)
	{
		for (size_t i = 0; i < *pBufSize; i++)
		{
			if (pWnd[i] != NULL && IsWindowBad(pWnd[i]) == TRUE)
			{
				if (i == *pBufSize - 1)
				{
					pWnd[i] = NULL;
					*pBufSize -= 1;
					continue;
				}

				for (size_t j = i + 1; j < *pBufSize; j++)
				{
					pWnd[i] = pWnd[j];
				}

				pWnd[*pBufSize - 1] = NULL;
				*pBufSize -= 1;
				continue;
			}
		}
	}

	return Status;
}



NTSTATUS(__fastcall* OriginalNtGdiExtTextOutW)(__int64 a1, unsigned int a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, int a7, __int64 a8, int a9);
NTSTATUS __fastcall ProxNtGdiExtTextOutW(__int64 a1, unsigned int a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, int a7, __int64 a8, int a9)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG StringSize = 0;

	if ((a7 > 0xFFFF) || (a7 > 0 && a6 == NULL))
	{
		Status = OriginalNtGdiExtTextOutW(a1, a2, a3, a4, a5, a6, a7, a8, a9);
		return Status;
	}

	if (a7 > 0)
	{

		StringSize = a7 * sizeof(WCHAR);
		ProbeForRead((volatile void*)a6, StringSize, 1);

		// 用一个缓冲区初始化字符串
		UNICODE_STRING dst;
		WCHAR dst_buf[256];
		RtlCopyMemory((PVOID)dst_buf, (PVOID)a6, (USHORT)StringSize);
		RtlInitEmptyUnicodeString(&dst, dst_buf, (USHORT)StringSize);
		ShvOsDebugPrint("%wZ\n", &dst);
	}

	Status = OriginalNtGdiExtTextOutW(a1, a2, a3, a4, a5, a6, a7, a8, a9);

	return Status;
}

//VOID NTAPI ProxKiDispatchException(PEXCEPTION_RECORD ExceptionRecord, PKEXCEPTION_FRAME ExceptionFrame, PKTRAP_FRAME TrapFrame, KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance)
//{
//
//	OriginalKiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
//	if (PreviousMode == UserMode && TrapFrame->Rip == GlobalConfig::Instance().KiUserExceptionDispatcherAddress)
//	{
//		PEPROCESS CurrentProcess = IoGetCurrentProcess();
//		if (IsHidden(CurrentProcess, HIDE_KI_EXCEPTION_DISPATCH) == TRUE)
//		{
//
//			PETHREAD CurentThread = (PETHREAD)KeGetCurrentThread();
//			PHIDDEN_THREAD HiddenThread = AppendThreadList(CurrentProcess, CurentThread);
//
//			PCONTEXT UserModeContext = (PCONTEXT)TrapFrame->Rsp;
//
//			if (HiddenThread != NULL)
//			{
//				if (PsGetProcessWow64Process(CurrentProcess) == NULL)
//				{
//					RtlCopyBytes(&UserModeContext->Dr0, &HiddenThread->FakeDebugContext.DR0, sizeof(ULONG64) * 6);
//					RtlCopyBytes(&UserModeContext->DebugControl, &HiddenThread->FakeDebugContext.DebugControl, sizeof(ULONG64) * 5);
//					DbgPrint("RtlCopyBytes \n");
//				}
//
//				else
//				{
//					UserModeContext->Dr0 = HiddenThread->FakeWow64DebugContext.DR0;
//					UserModeContext->Dr1 = HiddenThread->FakeWow64DebugContext.DR1;
//					UserModeContext->Dr2 = HiddenThread->FakeWow64DebugContext.DR2;
//					UserModeContext->Dr3 = HiddenThread->FakeWow64DebugContext.DR3;
//					UserModeContext->Dr6 = HiddenThread->FakeWow64DebugContext.DR6;
//					UserModeContext->Dr7 = HiddenThread->FakeWow64DebugContext.DR7;
//
//					RtlSecureZeroMemory(&TrapFrame->DebugControl, sizeof(ULONG64) * 5);
//					DbgPrint("RtlSecureZeroMemory \n");
//				}
//			}
//		}
//
//	}
//
//
//
//
//
//}

INT64(__fastcall* OriginalNtUserEnumDisplayDevices)(INT64 a1,
	UINT32 a2,
	PVOID a3,
	INT32 a4);

INT64 __fastcall ProxNtUserEnumDisplayDevices(INT64 a1,
	UINT32 a2,
	PVOID a3,
	INT32 a4)
{

	__int64 value = OriginalNtUserEnumDisplayDevices(a1, a2, a3, a4);

	//PUCHAR pProcessNameStr = PsGetProcessImageFileName(IoGetCurrentProcess());

	//if (CompareProcessName(pProcessNameStr, "eztest.exe"))
	//{
	//	ShvOsDebugPrint("Find!!! [%s] index:[%d] ProxNtUserEnumDisplayDevices value:[%p]\n", pProcessNameStr, a2, value);

	//	//return (UINT64)0;
	//}
	//else
	//{
	//	ShvOsDebugPrint("[%s] index:[%d] ProxNtUserEnumDisplayDevices value:[%p]\n", pProcessNameStr, a2, value);


	//}

	return value;
}
INT64(__fastcall* OriginalNtUserGetThreadState)(INT32 Routine);

INT64 __fastcall ProxNtUserGetThreadState(INT32 Routine)
{
	__int64 value = OriginalNtUserGetThreadState(Routine);

	//PUCHAR pProcessNameStr = PsGetProcessImageFileName(IoGetCurrentProcess());

	//if (CompareProcessName(pProcessNameStr, "eztest.exe"))
	//{
	//	ShvOsDebugPrint("Find!!! [%s] Routine:[%d] ProxNtUserGetThreadState value:[%p]\n", pProcessNameStr, Routine, value);

	//	//return (UINT64)0;
	//}
	//else
	//{
	//	if (Routine == 80)
	//		ShvOsDebugPrint("[%s] Routine:[%d] ProxNtUserGetThreadState value:[%p]\n", pProcessNameStr, Routine, value);
	//}

	return value;
}

NTSTATUS(NTAPI* OriginalNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, UINT32 SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProxNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, UINT32 SystemInformationLength, PULONG ReturnLength)
{

	NTSTATUS Status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	PEPROCESS CurrentProcess = IoGetCurrentProcess();

	if (ExGetPreviousMode() == UserMode &&
		IsHidden(CurrentProcess, HIDE_NT_QUERY_SYSTEM_INFORMATION) == TRUE &&
		NT_SUCCESS(Status) == TRUE
		)
	{
		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

			BACKUP_RETURNLENGTH();
			DebuggerInfo->DebuggerEnabled = 0;
			DebuggerInfo->DebuggerNotPresent = 1;
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemProcessInformation ||
			SystemInformationClass == SystemSessionProcessInformation ||
			SystemInformationClass == SystemExtendedProcessInformation ||
			SystemInformationClass == SystemFullProcessInformation)
		{
			PSYSTEM_PROCESS_INFO ProcessInfo = (PSYSTEM_PROCESS_INFO)SystemInformation;
			if (SystemInformationClass == SystemSessionProcessInformation)
				ProcessInfo = (PSYSTEM_PROCESS_INFO)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

			BACKUP_RETURNLENGTH();
			DbgPrint("FilterProcesses\n");
			FilterProcesses(ProcessInfo);

			for (PSYSTEM_PROCESS_INFO Entry = ProcessInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
			{
				if (IsHidden(PidToProcess(Entry->ProcessId), HIDE_NT_QUERY_SYSTEM_INFORMATION) == TRUE)
				{
					PEPROCESS ExplorerProcess = GetProcessByName(L"explorer.exe");
					if (ExplorerProcess != NULL)
						Entry->InheritedFromProcessId = PsGetProcessId(ExplorerProcess);

					Entry->OtherOperationCount.QuadPart = 1;
				}
			}
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemCodeIntegrityInformation)
		{
			BACKUP_RETURNLENGTH();
			((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = 0x1; // CODEINTEGRITY_OPTION_ENABLED
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
		{
			BACKUP_RETURNLENGTH();
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemKernelDebuggerFlags)
		{
			BACKUP_RETURNLENGTH();
			*(UCHAR*)SystemInformation = NULL;
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemExtendedHandleInformation)
		{
			PSYSTEM_HANDLE_INFORMATION_EX HandleInfoEx = (PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation;

			BACKUP_RETURNLENGTH();
			FilterHandlesEx(HandleInfoEx);
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemHandleInformation)
		{
			PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)SystemInformation;

			BACKUP_RETURNLENGTH();
			FilterHandles(HandleInfo);
			RESTORE_RETURNLENGTH();
		}
	}
	return Status;
}

NTSTATUS(NTAPI* OriginalNtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NTSTATUS NTAPI ProxNtSetInformationThread(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength
)
{
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (IsHidden(CurrentProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		(ThreadInformationClass == ThreadHideFromDebugger || ThreadInformationClass == ThreadWow64Context ||
			ThreadInformationClass == ThreadBreakOnTermination))
	{
		if (ThreadInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ThreadInformation, ThreadInformationLength, sizeof(ULONG));
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
		//防止含有反作弊的程序将自己设置ThreadHideFromDebugger
		//如果这个标志位设置了，当调试器触发断点的时候程序就退出了，所以要处理
		if (ThreadInformationClass == ThreadHideFromDebugger)
		{
			if (ThreadInformationLength != 0)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD Thread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_INFORMATION, *PsThreadType, UserMode, (PVOID*)&Thread, NULL);

			if (NT_SUCCESS(Status) == TRUE)
			{
				PEPROCESS TargetThreadProcess = IoThreadToProcess(Thread);
				if (IsHidden(TargetThreadProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE)
				{

					//加入线程链表中
					PHIDDEN_THREAD HiddenThread = AppendThreadList(TargetThreadProcess, Thread);
					//记录一下这个线程被我们操作过
					HiddenThread->IsThreadHidden = TRUE;

					ObDereferenceObject(Thread);
					return Status;
				}

				ObDereferenceObject(Thread);
				return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}

			return Status;
		}
		else if (ThreadInformationClass == ThreadWow64Context)
		{
			//隐藏进程/线程保护：如果线程所属进程是隐藏的，代码会对线程上下文进行特殊处理，可能是为了伪装或防止某些外部工具获取到真实的调试信息

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
				if (IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE)
				{
					if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INFO_LENGTH_MISMATCH;
					}

					PVOID WoW64Process = PsGetCurrentProcessWow64Process();
					if (WoW64Process == 0)
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INVALID_PARAMETER;
					}

					__try
					{
						PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
						//保存原始的 ContextFlags：这用于在后面恢复。
						ULONG OriginalFlags = Wow64Context->ContextFlags;
						//清除调试上下文标志
						Wow64Context->ContextFlags &= ~0x10;
						//调用原始的 NtSetInformationThread 函数：将修改后的上下文传递给系统的原始函数进行设置。
						Status = OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
						//如果原始的 ContextFlags 中有调试上下文标志 (0x10)，则：
						if (OriginalFlags & 0x10)
						{
							//恢复 ContextFlags 中的调试标志。
							Wow64Context->ContextFlags |= 0x10;
							//将当前线程添加到隐藏线程列表中，调用 AppendThreadList 函数。
							PHIDDEN_THREAD HiddenThread = AppendThreadList(IoThreadToProcess(TargetThread), TargetThread);
							//将线程的调试上下文（Dr0 到 Dr5）复制到隐藏线程的 FakeWow64DebugContext 中，表示可能会伪装调试上下文。
							if (HiddenThread != NULL)
								RtlCopyBytes(&HiddenThread->FakeWow64DebugContext, &Wow64Context->Dr0, sizeof(ULONG) * 6);
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}

			return Status;
		}
		else if (ThreadInformationClass == ThreadBreakOnTermination)
		{
			//防止线程中断导致程序退出
			if (ThreadInformationLength != sizeof(ULONG))
				return STATUS_INFO_LENGTH_MISMATCH;

			__try
			{
				volatile ULONG Touch = *(ULONG*)ThreadInformation;
				UNREFERENCED_PARAMETER(Touch);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			LUID PrivilageValue;
			PrivilageValue.LowPart = SE_DEBUG_PRIVILEGE;
			if (SeSinglePrivilegeCheck(PrivilageValue, UserMode) == FALSE)
				return STATUS_PRIVILEGE_NOT_HELD;

			PETHREAD ThreadObject;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_INFORMATION, *PsThreadType, ExGetPreviousMode(), (PVOID*)&ThreadObject, NULL);

			if (NT_SUCCESS(Status) == TRUE)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(ThreadObject);
				if (IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE)
				{
					PHIDDEN_THREAD HiddenThread = AppendThreadList(TargetProcess, ThreadObject);
					if (HiddenThread != NULL)
						HiddenThread->BreakOnTermination = *(ULONG*)ThreadInformation ? TRUE : FALSE;

					ObDereferenceObject(ThreadHandle);
					return Status;
				}

				ObDereferenceObject(ThreadHandle);
				return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}

			return Status;
		}
	}

	return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS(NTAPI* OriginalNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProxNtQueryInformationProcess(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
)
{
	//假设我们在r3中填入反作弊的进程pid，并且设置了HIDE_NT_QUERY_INFORMATION_PROCESS
	//再满足ProcessInformationClass的标志，就进入if语句中处理
	if (ExGetPreviousMode() == UserMode &&
		IsHidden(IoGetCurrentProcess(), HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE &&
		(ProcessInformationClass == ProcessDebugObjectHandle || ProcessInformationClass == ProcessDebugPort ||
			ProcessInformationClass == ProcessDebugFlags || ProcessInformationClass == ProcessBreakOnTermination ||
			ProcessInformationClass == ProcessBasicInformation || ProcessInformationClass == ProcessIoCounters ||
			ProcessInformationClass == ProcessHandleTracing)
		)
	{

		if (ProcessInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
				if (ReturnLength != 0)
					ProbeForWrite(ReturnLength, 4, 1);
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		//如果反作弊想查询的类型是调试对象，那么则进入if中处理他
		if (ProcessInformationClass == ProcessDebugObjectHandle)
		{
			if (ProcessInformationLength != sizeof(ULONG64))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				//如果反作弊查询的类型为调试对象，并且反作弊查询的句柄是我们限制的进程，这里可以理解为自己查自己的调试句柄
				//当是这种情况的时候，就对其进行处理
				//调试的时候会生成调试对象（DebugObject)
				//若进程处于调试状态的时候，调试对象句柄值就存在
				//处于非调试状态的时候，调试对象句柄值为NULL
				if (IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG64*)ProcessInformation = NULL;
						if (ReturnLength != NULL) *ReturnLength = sizeof(ULONG64);

						Status = STATUS_PORT_NOT_SET;
					}

					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}
		else if (ProcessInformationClass == ProcessDebugPort)
		{
			if (ProcessInformationLength != sizeof(ULONG64))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				//这里处理反作弊查自己的ProcessDebugPort
				//进程处于调试状态就会为它分配一个调试端口，Debug Port
				//进程处于调试的时候，变量debugPort被设置为0xFFFFFFFF
				//非调试状态的时候，debugPort被设置为0x0
				if (IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG64*)ProcessInformation = 0;
						if (ReturnLength != 0)
							*ReturnLength = sizeof(ULONG64);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}
		else if (ProcessInformationClass == ProcessDebugFlags)
		{
			if (ProcessInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				//这里处理反作弊查自己的ProcessDebugFlags
				//检测Debug Flags(调试标志）的值可以判断进程处于调试状态，通过函数第三个参数就可以获取调试标志的值
				//若为0，则处于调试状态
				//若为1, 则处于非调试状态
				if (IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG*)ProcessInformation = (QueryHiddenProcess(TargetProcess)->ValueProcessDebugFlags == 0) ? PROCESS_DEBUG_INHERIT : 0;
						if (ReturnLength != 0)
							*ReturnLength = sizeof(ULONG);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}
		else if (ProcessInformationClass == ProcessBreakOnTermination)
		{
			if (ProcessInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x1000, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				//这里处理反作弊只要进程挂了，那么就触发BSoD的操作
				//当前的进程的BreakOnTermination位是否置位，即当前进程是否为Critical Process，若是的话，则触发BSoD的逻辑
				if (IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG*)ProcessInformation = QueryHiddenProcess(TargetProcess)->ValueProcessBreakOnTermination;
						if (ReturnLength != 0)
							*ReturnLength = sizeof(ULONG);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}
		NTSTATUS Status = OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		if (NT_SUCCESS(Status) == TRUE)
		{
			PEPROCESS TargetProcess;
			NTSTATUS ObStatus = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&TargetProcess, NULL);

			if (NT_SUCCESS(ObStatus) == TRUE)
			{
				ObDereferenceObject(TargetProcess);

				if (IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(TargetProcess);

					if (HiddenProcess != NULL)
					{

						if (ProcessInformationClass == ProcessBasicInformation)
						{
							//查反作弊进程自己的父进程的时候，咱们对他进行处理，让他的父进程始终为explorer.exe
							BACKUP_RETURNLENGTH();
							PEPROCESS ExplorerProcess = GetProcessByName(L"explorer.exe");
							if (ExplorerProcess != NULL)
								((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = (ULONG_PTR)PsGetProcessId(ExplorerProcess);
							RESTORE_RETURNLENGTH();
							return Status;
						}
						//将 OtherOperationCount 设置为 1 可能有以下几种可能的目的：
						//虚假的 I / O 数据返回：代码强制将非读写的其他操作次数设为 1，这意味着即使进程实际上没有执行任何 "其他操作"，
						//查询进程信息的调用者会看到有一次操作。这可能是用于隐藏进程的真实 I / O 活动。
						//测试或调试：这可能是测试或调试代码的一部分，故意修改进程的 I / O 计数器以验证调用者是否能够正确处理返回的伪造数据。
						//混淆或保护进程信息：在某些情况下，内核代码可能会被设计为模糊或混淆特定进程的信息，防止外部工具或攻击者准确地监视进程的活动。
						//通过设置一个固定的值，代码可以限制外部看到进程的真实 I / O 操作情况。
						else if (ProcessInformationClass == ProcessIoCounters)
						{

							BACKUP_RETURNLENGTH();
							((PIO_COUNTERS)ProcessInformation)->OtherOperationCount = 1;
							RESTORE_RETURNLENGTH();
							return Status;
						}
						//隐藏进程信息：这段代码可能用于防止外部工具或程序访问某些“隐藏”的进程的句柄追踪信息。
						//例如，某些进程可能是系统关键进程或被保护的进程，禁止普通用户或监视工具查询其句柄活动。
						//进程调试或安全监控：在某些场景下，操作系统或内核驱动程序可能允许对某些进程启用句柄追踪功能，以便进行调试、监控或安全审计。
						//这段代码则负责确定哪些进程可以被查询句柄追踪状态。
						else if (ProcessInformationClass == ProcessHandleTracing)
						{
							return HiddenProcess->ProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
						}
					}
				}
			}
		}
		return Status;
	}
	return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}
NTSTATUS(NTAPI* OriginalNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProxNtQueryObject(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
)
{
	NTSTATUS Status = OriginalNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_QUERY_OBJECT) == TRUE &&
		NT_SUCCESS(Status) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		ObjectInformation != NULL)
	{

		if (ObjectInformationClass == ObjectTypeInformation)
		{
			UNICODE_STRING DebugObject;
			RtlInitUnicodeString(&DebugObject, L"DebugObject");
			POBJECT_TYPE_INFORMATION Type = (POBJECT_TYPE_INFORMATION)ObjectInformation;

			if (RtlEqualUnicodeString(&Type->TypeName, &DebugObject, FALSE) == TRUE)
			{
				BACKUP_RETURNLENGTH();

				Type->TotalNumberOfObjects -= GlobalConfig::Instance().NumberOfActiveDebuggers;
				Type->TotalNumberOfHandles -= GlobalConfig::Instance().NumberOfActiveDebuggers;
				RESTORE_RETURNLENGTH();
			}

			return Status;
		}

		else if (ObjectInformationClass == ObjectTypesInformation)
		{
			UNICODE_STRING DebugObject;
			RtlInitUnicodeString(&DebugObject, L"DebugObject");
			POBJECT_ALL_INFORMATION ObjectAllInfo = (POBJECT_ALL_INFORMATION)ObjectInformation;
			UCHAR* ObjInfoLocation = (UCHAR*)ObjectAllInfo->ObjectTypeInformation;
			ULONG TotalObjects = ObjectAllInfo->NumberOfObjectsTypes;

			BACKUP_RETURNLENGTH();
			for (ULONG i = 0; i < TotalObjects; i++)
			{
				POBJECT_TYPE_INFORMATION ObjectTypeInfo = (POBJECT_TYPE_INFORMATION)ObjInfoLocation;
				if (RtlEqualUnicodeString(&ObjectTypeInfo->TypeName, &DebugObject, FALSE) == TRUE)
				{
					ObjectTypeInfo->TotalNumberOfObjects = 0;
					ObjectTypeInfo->TotalNumberOfHandles = 0;
				}
				ObjInfoLocation = (UCHAR*)ObjectTypeInfo->TypeName.Buffer;
				ObjInfoLocation += ObjectTypeInfo->TypeName.MaximumLength;
				ULONG64 Tmp = ((ULONG64)ObjInfoLocation) & -(LONG64)sizeof(PVOID);
				if ((ULONG64)Tmp != (ULONG64)ObjInfoLocation)
					Tmp += sizeof(PVOID);
				ObjInfoLocation = ((UCHAR*)Tmp);
			}
			RESTORE_RETURNLENGTH();
			return Status;
		}
	}
	return Status;
}

//第一个参数的长度可能有问题
NTSTATUS(NTAPI* OriginalNtSystemDebugControl)(INT32 Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
NTSTATUS NTAPI ProxNtSystemDebugControl(
	INT32       Command,
	PVOID                InputBuffer,
	ULONG                InputBufferLength,
	PVOID               OutputBuffer,
	ULONG                OutputBufferLength,
	PULONG              ReturnLength)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_SYSTEM_DEBUG_CONTROL) == TRUE)
	{
		if (Command == SysDbgGetTriageDump)
			return STATUS_INFO_LENGTH_MISMATCH;
		return STATUS_DEBUGGER_INACTIVE;
	}
	return OriginalNtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

NTSTATUS(NTAPI* OriginalNtClose)(HANDLE Handle);
NTSTATUS NTAPI ProxNtClose(HANDLE Handle)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_CLOSE) == TRUE)
	{

		KeWaitForSingleObject(&GlobalConfig::Instance().NtCloseMutex, Executive, KernelMode, FALSE, NULL);

		OBJECT_HANDLE_ATTRIBUTE_INFORMATION ObjAttributeInfo;

		NTSTATUS Status = ZwQueryObject(Handle, (OBJECT_INFORMATION_CLASS)4 /*ObjectDataInformation*/, &ObjAttributeInfo, sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION), NULL);

		if (Status == STATUS_INVALID_HANDLE)
		{
			KeReleaseMutex(&GlobalConfig::Instance().NtCloseMutex, FALSE);
			return STATUS_INVALID_HANDLE;
		}

		if (NT_SUCCESS(Status) == TRUE)
		{
			if (ObjAttributeInfo.ProtectFromClose == TRUE)
			{
				KeReleaseMutex(&GlobalConfig::Instance().NtCloseMutex, FALSE);
				return STATUS_HANDLE_NOT_CLOSABLE;
			}
		}

		KeReleaseMutex(&GlobalConfig::Instance().NtCloseMutex, FALSE);
	}
	return OriginalNtClose(Handle);
}

NTSTATUS(NTAPI* OriginalNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProxNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_SET_CONTEXT_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		PETHREAD TargethThread;
		NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&TargethThread, 0);
		if (NT_SUCCESS(Status) == TRUE)
		{
			PEPROCESS TargetProcess = IoThreadToProcess(TargethThread);
			if (IsHidden(TargetProcess, HIDE_NT_SET_CONTEXT_THREAD) == TRUE)
			{
				if (IsSetThreadContextRestricted(TargetProcess) == TRUE && IoThreadToProcess(PsGetCurrentThread()) == TargetProcess)
				{
					ObDereferenceObject(TargethThread);
					return STATUS_SET_CONTEXT_DENIED;
				}

				// If it is a system thread or pico process thread return STATUS_INVALID_HANDLE
				if (IoIsSystemThread(TargethThread) == TRUE || IsPicoContextNull(TargethThread) == FALSE)
				{
					ObDereferenceObject(TargethThread);
					return STATUS_INVALID_HANDLE;
				}

				__try
				{
					ULONG OriginalFlags = Context->ContextFlags;

					Context->ContextFlags &= ~0x10;

					Status = OriginalNtSetContextThread(ThreadHandle, Context);

					if (OriginalFlags & 0x10)
					{
						Context->ContextFlags |= 0x10;

						PHIDDEN_THREAD HiddenThread = AppendThreadList(TargetProcess, TargethThread);
						if (HiddenThread != 0)
						{
							RtlCopyBytes(&HiddenThread->FakeDebugContext.DR0, &Context->Dr0, sizeof(ULONG64) * 6);
							RtlCopyBytes(&HiddenThread->FakeDebugContext.DebugControl, &Context->DebugControl, sizeof(ULONG64) * 5);
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargethThread);
				return Status;
			}

			ObDereferenceObject(TargethThread);
			return OriginalNtSetContextThread(ThreadHandle, Context);
		}

		return Status;
	}
	return OriginalNtSetContextThread(ThreadHandle, Context);
}

NTSTATUS(NTAPI* OriginalNtGetContextThread)(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context);
NTSTATUS NTAPI ProxNtGetContextThread(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_GET_CONTEXT_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode
		)
	{
		PETHREAD ThreadObject;
		NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&ThreadObject, 0);
		if (NT_SUCCESS(Status) == TRUE)
		{
			// If it is a system thread return STATUS_INVALID_HANDLE
			if (IoIsSystemThread(ThreadObject) == TRUE)
			{
				ObDereferenceObject(ThreadObject);
				return STATUS_INVALID_HANDLE;
			}

			// Check if thread object belongs to any hidden process
			if (IsHidden(IoThreadToProcess(ThreadObject), HIDE_NT_SET_CONTEXT_THREAD) == TRUE)
			{
				__try
				{
					ULONG OriginalFlags = Context->ContextFlags;

					Context->ContextFlags &= ~0x10;

					Status = OriginalNtGetContextThread(ThreadHandle, Context);

					if (OriginalFlags & 0x10)
					{
						Context->ContextFlags |= 0x10;

						PHIDDEN_THREAD HiddenThread = AppendThreadList(IoThreadToProcess(ThreadObject), ThreadObject);
						if (HiddenThread != NULL)
						{
							RtlCopyBytes(&Context->Dr0, &HiddenThread->FakeDebugContext.DR0, sizeof(ULONG64) * 6);
							RtlCopyBytes(&Context->DebugControl, &HiddenThread->FakeDebugContext.DebugControl, sizeof(ULONG64) * 5);
						}
						else
						{
							RtlSecureZeroMemory(&Context->Dr0, sizeof(ULONG64) * 6);
							RtlSecureZeroMemory(&Context->DebugControl, sizeof(ULONG64) * 5);
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(ThreadObject);
				return Status;
			}

			ObDereferenceObject(ThreadObject);
			return OriginalNtGetContextThread(ThreadHandle, Context);
		}

		return Status;
	}

	return OriginalNtGetContextThread(ThreadHandle, Context);
}

NTSTATUS(NTAPI* OriginalNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProxNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (IsHidden(CurrentProcess, HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode && (ThreadInformationClass == ThreadHideFromDebugger ||
			ThreadInformationClass == ThreadBreakOnTermination || ThreadInformationClass == ThreadWow64Context))
	{
		if (ThreadInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ThreadInformation, ThreadInformationLength, 4);
				if (ReturnLength != 0)
					ProbeForWrite(ReturnLength, 4, 1);

			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ThreadInformationClass == ThreadHideFromDebugger)
		{
			if (ThreadInformationLength != 1)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, 0x40, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (IsHidden(IoThreadToProcess(TargetThread), HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE)
				{
					__try
					{
						*(BOOLEAN*)ThreadInformation = AppendThreadList(IoThreadToProcess(TargetThread), TargetThread)->IsThreadHidden;

						if (ReturnLength != 0) *ReturnLength = 1;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
			}

			return Status;
		}

		if (ThreadInformationClass == ThreadBreakOnTermination)
		{
			if (ThreadInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, 0x40, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (IsHidden(IoThreadToProcess(TargetThread), HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE)
				{
					__try
					{
						*(ULONG*)ThreadInformation = AppendThreadList(IoThreadToProcess(TargetThread), TargetThread)->BreakOnTermination;

						if (ReturnLength != NULL) *ReturnLength = 4;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
			}

			return Status;
		}

		if (ThreadInformationClass == ThreadWow64Context)
		{
			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (IsHidden(IoThreadToProcess(TargetThread), HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE)
				{
					if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INFO_LENGTH_MISMATCH;
					}

					PVOID WoW64Process = PsGetCurrentProcessWow64Process();
					if (WoW64Process == 0)
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INVALID_PARAMETER;
					}

					__try
					{
						PWOW64_CONTEXT Context = (PWOW64_CONTEXT)ThreadInformation;
						ULONG OriginalFlags = Context->ContextFlags;

						Context->ContextFlags &= ~0x10;

						Status = OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

						if (OriginalFlags & 0x10)
						{
							Context->ContextFlags |= 0x10;

							PHIDDEN_THREAD HiddenThread = AppendThreadList(IoThreadToProcess(TargetThread), TargetThread);

							if (HiddenThread != NULL)
								RtlCopyBytes(&Context->Dr0, &HiddenThread->FakeWow64DebugContext, sizeof(ULONG) * 6);

							else
								RtlSecureZeroMemory(&Context->Dr0, sizeof(ULONG) * 6);
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
			}

			return Status;
		}
	}
	return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

}

NTSTATUS(NTAPI* OriginalNtCreateThreadEx)
(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
	);
NTSTATUS NTAPI ProxNtCreateThreadEx
(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_CREATE_THREAD_EX) == TRUE &&
		(CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER ||
			CreateFlags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE))
	{
		NTSTATUS Status;
		ULONG OriginalFlags = CreateFlags;

		if (GlobalConfig::Instance().CurrentWindowsBuildNumber >= WINDOWS_10_VERSION_19H1)
			Status = OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE), ZeroBits, StackSize, MaximumStackSize, AttributeList);

		else
			Status = OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER), ZeroBits, StackSize, MaximumStackSize, AttributeList);

		if (NT_SUCCESS(Status) == TRUE)
		{
			PETHREAD NewThread;
			NTSTATUS ObStatus = ObReferenceObjectByHandle(*ThreadHandle, NULL, *PsThreadType, KernelMode, (PVOID*)&NewThread, NULL);

			if (NT_SUCCESS(ObStatus) == TRUE)
			{
				PEPROCESS TargetProcess;
				ObStatus = ObReferenceObjectByHandle(ProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&TargetProcess, NULL);

				if (NT_SUCCESS(ObStatus) == TRUE)
				{
					if (IsHidden(TargetProcess, HIDE_NT_CREATE_THREAD_EX) == TRUE)
					{
						PHIDDEN_THREAD HiddenThread = AppendThreadList(TargetProcess, NewThread);
						if (HiddenThread != NULL)
							HiddenThread->IsThreadHidden = OriginalFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
					}
					ObDereferenceObject(TargetProcess);
				}
				ObDereferenceObject(NewThread);
			}
		}

		return Status;
	}


	return OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);

}

NTSTATUS(NTAPI* OriginalNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS NTAPI ProxNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_CREATE_FILE) == TRUE &&
		ExGetPreviousMode() == UserMode
		)
	{
		NTSTATUS Status = OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		if (NT_SUCCESS(Status) == TRUE)
		{
			__try
			{
				UNICODE_STRING SymLink;
				RtlInitUnicodeString(&SymLink, ObjectAttributes->ObjectName->Buffer);

				if (IsDriverHandleHidden(&SymLink) == TRUE)
				{
					ObCloseHandle(*FileHandle, UserMode);
					*FileHandle = INVALID_HANDLE_VALUE;
					Status = STATUS_OBJECT_NAME_NOT_FOUND;
				}
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		}

		return Status;
	}
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

}


NTSTATUS(NTAPI* OriginalNtCreateUserProcess)
(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID CreateInfo, // PPS_CREATE_INFO
	PVOID AttributeList // PPS_ATTRIBUTE_LIST
	);

NTSTATUS NTAPI ProxNtCreateUserProcess
(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID CreateInfo, // PPS_CREATE_INFO
	PVOID AttributeList // PPS_ATTRIBUTE_LIST
)
{

	NTSTATUS Status = OriginalNtCreateUserProcess
	(
		ProcessHandle, ThreadHandle,
		ProcessDesiredAccess, ThreadDesiredAccess,
		ProcessObjectAttributes, ThreadObjectAttributes,
		ProcessFlags, ThreadFlags,
		ProcessParameters, CreateInfo, AttributeList
	);
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (IsHidden(CurrentProcess, HIDE_NT_CREATE_PROCESS_EX) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		NT_SUCCESS(Status) == TRUE)
	{
		PEPROCESS NewProcess;
		NTSTATUS ObStatus = ObReferenceObjectByHandle(*ProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&NewProcess, NULL);
		if (NT_SUCCESS(ObStatus) == TRUE)
		{
			PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(CurrentProcess);
			if (HiddenProcess != NULL)
			{
				HIDE_INFO HideInfo = { 0 };

				CreateEntry(HiddenProcess->DebuggerProcess, NewProcess);

				RtlFillBytes(&HideInfo.HookNtQueryInformationProcess, 1, sizeof(HideInfo) - 4);
				HideInfo.Pid = HandleToUlong(PsGetProcessId(NewProcess));

				Hide(&HideInfo);
			}

			ObDereferenceObject(NewProcess);
		}
	}


	return Status;
}


NTSTATUS(NTAPI* OriginalNtCreateProcessEx)
(
	OUT PHANDLE     ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN HANDLE   ParentProcess,
	IN ULONG    Flags,
	IN HANDLE SectionHandle     OPTIONAL,
	IN HANDLE DebugPort     OPTIONAL,
	IN HANDLE ExceptionPort     OPTIONAL,
	IN ULONG  JobMemberLevel
	);
NTSTATUS NTAPI ProxNtCreateProcessEx
(
	OUT PHANDLE     ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN HANDLE   ParentProcess,
	IN ULONG    Flags,
	IN HANDLE SectionHandle     OPTIONAL,
	IN HANDLE DebugPort     OPTIONAL,
	IN HANDLE ExceptionPort     OPTIONAL,
	IN ULONG  JobMemberLevel
)
{
	NTSTATUS Status = OriginalNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel);
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_CREATE_PROCESS_EX) == TRUE &&
		NT_SUCCESS(Status) == TRUE)
	{
		PEPROCESS NewProcess;
		NTSTATUS ObStatus = ObReferenceObjectByHandle(*ProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&NewProcess, NULL);
		if (NT_SUCCESS(ObStatus) == TRUE)
		{
			PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(IoGetCurrentProcess());
			CreateEntry(HiddenProcess->DebuggerProcess, NewProcess);

			HIDE_INFO HideInfo = { 0 };

			RtlFillBytes(&HideInfo.HookNtQueryInformationProcess, 1, sizeof(HideInfo) - 4);
			HideInfo.Pid = HandleToUlong(PsGetProcessId(NewProcess));

			Hide(&HideInfo);
			ObDereferenceObject(NewProcess);
		}
	}
	return Status;
}


NTSTATUS(NTAPI* OriginalNtYieldExecution)();
NTSTATUS NTAPI ProxNtYieldExecution()
{

	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_YIELD_EXECUTION) == TRUE)
	{
		OriginalNtYieldExecution();
		return STATUS_SUCCESS;
	}

	return OriginalNtYieldExecution();
}

NTSTATUS(NTAPI* OriginalNtQuerySystemTime)(PLARGE_INTEGER SystemTime);
NTSTATUS NTAPI ProxNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
	PEPROCESS Current = IoGetCurrentProcess();

	if (IsHidden(Current, HIDE_NT_QUERY_SYSTEM_TIME) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForWrite(SystemTime, sizeof(ULONG64), 4);

			PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(Current);
			if (HiddenProcess != NULL)
			{
				if (IsHidden(Current, HIDE_KUSER_SHARED_DATA) == TRUE)
					SystemTime->QuadPart = *(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->SystemTime;

				else
				{
					if (HiddenProcess->FakeSystemTime.QuadPart == NULL)
						KeQuerySystemTime(&HiddenProcess->FakeSystemTime);

					SystemTime->QuadPart = HiddenProcess->FakeSystemTime.QuadPart;
					HiddenProcess->FakeSystemTime.QuadPart += 1;
				}

				return STATUS_SUCCESS;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}

	return OriginalNtQuerySystemTime(SystemTime);
}

NTSTATUS(NTAPI* OriginalNtQueryPerformanceCounter)(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);
NTSTATUS NTAPI ProxNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency)
{
	PEPROCESS Current = IoGetCurrentProcess();

	if (IsHidden(Current, HIDE_NT_QUERY_SYSTEM_TIME) == TRUE &&
		ExGetPreviousMode() == UserMode
		)
	{
		__try
		{
			ProbeForWrite(PerformanceCounter, sizeof(ULONG64), 4);
			if (PerformanceFrequency != NULL)
			{
				ProbeForWrite(PerformanceFrequency, sizeof(ULONG64), 4);
			}

			PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(Current);
			if (HiddenProcess != NULL)
			{
				if (IsHidden(Current, HIDE_KUSER_SHARED_DATA) == TRUE)
					PerformanceCounter->QuadPart = HiddenProcess->Kusd.KuserSharedData->BaselineSystemTimeQpc;

				else
				{
					if (HiddenProcess->FakePerformanceCounter.QuadPart == NULL)
						HiddenProcess->FakePerformanceCounter = KeQueryPerformanceCounter(NULL);

					PerformanceCounter->QuadPart = HiddenProcess->FakePerformanceCounter.QuadPart;
					HiddenProcess->FakePerformanceCounter.QuadPart += 1;
				}

				if (PerformanceFrequency != NULL)
					PerformanceFrequency->QuadPart = GlobalConfig::Instance().KernelKuserSharedDataAddress->QpcFrequency;

				return STATUS_SUCCESS;
			}
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	return OriginalNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);
}
//第二个参数大小可能有问题
NTSTATUS(NTAPI* OriginalNtQueryInformationJobObject)(HANDLE JobHandle, INT32 JobInformationClass, PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProxNtQueryInformationJobObject(HANDLE JobHandle, INT32 JobInformationClass, PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength)
{
	NTSTATUS Status = OriginalNtQueryInformationJobObject(JobHandle, JobInformationClass, JobInformation, JobInformationLength, ReturnLength);
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_QUERY_INFORMATION_JOB_OBJECT) == TRUE &&
		JobInformationClass == JobObjectBasicProcessIdList &&
		NT_SUCCESS(Status) == TRUE)
	{
		BACKUP_RETURNLENGTH();

		PJOBOBJECT_BASIC_PROCESS_ID_LIST JobProcessIdList = (PJOBOBJECT_BASIC_PROCESS_ID_LIST)JobInformation;
		for (size_t i = 0; i < JobProcessIdList->NumberOfAssignedProcesses; i++)
		{
			if (IsDebuggerProcess(PidToProcess((HANDLE)JobProcessIdList->ProcessIdList[i])) == TRUE)
			{
				if (i == JobProcessIdList->NumberOfAssignedProcesses - 1)
					JobProcessIdList->ProcessIdList[i] = NULL;

				else
				{
					for (size_t j = i + 1; j < JobProcessIdList->NumberOfAssignedProcesses; j++)
					{
						JobProcessIdList->ProcessIdList[j - 1] = JobProcessIdList->ProcessIdList[j];
						JobProcessIdList->ProcessIdList[j] = 0;
					}
				}

				JobProcessIdList->NumberOfAssignedProcesses--;
				JobProcessIdList->NumberOfProcessIdsInList--;
			}
		}

		RESTORE_RETURNLENGTH();
	}
	return Status;

}

NTSTATUS(NTAPI* OriginalNtOpenThread)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI ProxNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_OPEN_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForWrite(ProcessHandle, 4, 1);
			ProbeForWrite(ObjectAttributes, 28, 4);
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}

		if (ClientId != NULL)
		{
			__try
			{
				ProbeForRead(ClientId, 1, 4);
				volatile ULONG64 Touch = (ULONG64)ClientId->UniqueProcess;
				Touch = (ULONG64)ClientId->UniqueThread;
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			if (ClientId->UniqueThread == NULL)
				return OriginalNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

			PETHREAD TargetThread;
			PsLookupThreadByThreadId(ClientId->UniqueThread, &TargetThread);
			if (TargetThread != NULL)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
				UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(TargetProcess);

				if (IsProcessNameBad(&ProcessImageName) == TRUE)
				{
					HANDLE OriginalTID = ClientId->UniqueThread;
					ClientId->UniqueThread = UlongToHandle(0xFFFFFFFC);

					NTSTATUS Status = OriginalNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

					ClientId->UniqueThread = OriginalTID;

					return Status;
				}
			}
		}
	}
	return OriginalNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS(NTAPI* OriginalNtSetInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSTATUS NTAPI ProxNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	if (ExGetPreviousMode() == UserMode &&
		IsHidden(IoGetCurrentProcess(), HIDE_NT_SET_INFORMATION_PROCESS) == TRUE &&
		(ProcessInformationClass == ProcessBreakOnTermination || ProcessInformationClass == ProcessDebugFlags ||
			ProcessInformationClass == ProcessHandleTracing))
	{
		if (ProcessInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ProcessInformationClass == ProcessBreakOnTermination)
		{
			if (ProcessInformationLength != sizeof(ULONG))
				return STATUS_INFO_LENGTH_MISMATCH;

			__try
			{
				volatile ULONG Touch = *(ULONG*)ProcessInformation;
				UNREFERENCED_PARAMETER(Touch);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			LUID PrivilageValue;
			PrivilageValue.LowPart = SE_DEBUG_PRIVILEGE;
			if (SeSinglePrivilegeCheck(PrivilageValue, UserMode) == FALSE)
				return STATUS_PRIVILEGE_NOT_HELD;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x200, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_PROCESS) == TRUE)
				{
					PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(TargetProcess);
					if (HiddenProcess != NULL)
						HiddenProcess->ValueProcessBreakOnTermination = *(ULONG*)ProcessInformation & 1;

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
			}
			return Status;
		}

		else if (ProcessInformationClass == ProcessDebugFlags)
		{
			if (ProcessInformationLength != sizeof(ULONG))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x200, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						ULONG Flags = *(ULONG*)ProcessInformation;
						if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
						{
							ObDereferenceObject(TargetProcess);
							return STATUS_INVALID_PARAMETER;
						}

						PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(TargetProcess);

						if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
							HiddenProcess->ValueProcessDebugFlags = 0;

						else
							HiddenProcess->ValueProcessDebugFlags = TRUE;

						Status = STATUS_SUCCESS;
					}

					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
			}

			return Status;
		}

		else if (ProcessInformationClass == ProcessHandleTracing)
		{
			BOOLEAN Enable = ProcessInformationLength != 0;
			if (Enable == TRUE)
			{
				if (ProcessInformationLength != sizeof(ULONG) && ProcessInformationLength != sizeof(ULONG64))
					return STATUS_INFO_LENGTH_MISMATCH;

				__try
				{
					PPROCESS_HANDLE_TRACING_ENABLE_EX ProcessHandleTracing = (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;
					if (ProcessHandleTracing->Flags != 0)
						return STATUS_INVALID_PARAMETER;
				}

				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					return GetExceptionCode();
				}
			}

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x200, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_PROCESS) == TRUE)
				{
					PHIDDEN_PROCESS HiddenProcess = QueryHiddenProcess(TargetProcess);
					if (HiddenProcess != NULL)
						HiddenProcess->ProcessHandleTracingEnabled = Enable;

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
			}

			return Status;
		}
	}
	return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);

}

NTSTATUS(NTAPI* OriginalNtGetNextProcess)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);
NTSTATUS NTAPI ProxNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
	NTSTATUS Status = OriginalNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
	if (IsHidden(IoGetCurrentProcess(), HIDE_NT_GET_NEXT_PROCESS) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		NT_SUCCESS(Status) == TRUE)
	{
		PEPROCESS NewProcess;
		NTSTATUS ObStatus = ObReferenceObjectByHandle(*NewProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&NewProcess, NULL);
		if (NT_SUCCESS(ObStatus) == TRUE)
		{
			UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(NewProcess);
			if (IsProcessNameBad(&ProcessImageName) == TRUE)
			{
				HANDLE OldHandleValue = *NewProcessHandle;

				Status = ProxNtGetNextProcess(*NewProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
				ObCloseHandle(OldHandleValue, UserMode);
			}

			ObDereferenceObject(NewProcess);
			return Status;
		}

		return Status;
	}
	return Status;

}


BOOLEAN HookSyscalls()
{



	//未hook的代码
	//NtUserGetClassName
	//NtUserInternalGetWindowText
	//NtWriteVirtualMemory
	//NtReadVirtualMemory
	//NtDebugActiveProcess
	//NtCreateDebugObject
	//NtRemoveProcessDebug
	//NtWaitForDebugEvent
	//NtDebugContinue

	//KeInitializeMutex(&GlobalConfig::Instance().NtCloseMutex, 0);


	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().KiDispatchException, (PVOID)&ProxKiDispatchException, (PVOID*)&OriginalKiDispatchException) == FALSE)
	//{
		//ShvOsDebugPrint("KiUserException hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtContinueEx, (PVOID)&ProxNtContinueEx, (PVOID*)&OriginalNtContinueEx) == FALSE)
	//{
	//	ShvOsDebugPrint("NtContinueEx hook failed\n");
	//	return FALSE;
	//}
	//
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtSetInformationThread, (PVOID)&ProxNtSetInformationThread, (PVOID*)&OriginalNtSetInformationThread) == FALSE)
	//{
	//	ShvOsDebugPrint("NtSetInformationThread hook failed\n");

	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQueryInformationProcess, (PVOID)&ProxNtQueryInformationProcess, (PVOID*)&OriginalNtQueryInformationProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQueryInformationProcess hook failed\n");

	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQueryObject, (PVOID)&ProxNtQueryObject, (PVOID*)&OriginalNtQueryObject) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQueryObject hook failed\n");

	//	return FALSE;
	//}


	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtSystemDebugControl, (PVOID)&ProxNtSystemDebugControl, (PVOID*)&OriginalNtSystemDebugControl) == FALSE)
	//{
	//	ShvOsDebugPrint("NtSystemDebugControl hook failed\n");

	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtClose, (PVOID)&ProxNtClose, (PVOID*)&OriginalNtClose) == FALSE)
	//{
	//	ShvOsDebugPrint("NtClose hook failed\n");

	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtSetContextThread, (PVOID)&ProxNtSetContextThread, (PVOID*)&OriginalNtSetContextThread) == FALSE)
	//{
	//	ShvOsDebugPrint("NtSetContextThread hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQuerySystemInformation, (PVOID)&ProxNtQuerySystemInformation, (PVOID*)&OriginalNtQuerySystemInformation) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQuerySystemInformation hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtGetContextThread, (PVOID)&ProxNtGetContextThread, (PVOID*)&OriginalNtGetContextThread) == FALSE)
	//{
	//	ShvOsDebugPrint("NtGetContextThread hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQueryInformationThread, (PVOID)&ProxNtQueryInformationThread, (PVOID*)&OriginalNtQueryInformationThread) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQueryInformationThread hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtCreateThreadEx, (PVOID)&ProxNtCreateThreadEx, (PVOID*)&OriginalNtCreateThreadEx) == FALSE)
	//{
	//	ShvOsDebugPrint("NtCreateThreadEx hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtCreateFile, (PVOID)&ProxNtCreateFile, (PVOID*)&OriginalNtCreateFile) == FALSE)
	//{
	//	ShvOsDebugPrint("NtCreateFile hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtCreateUserProcess, (PVOID)&ProxNtCreateUserProcess, (PVOID*)&OriginalNtCreateUserProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("NtCreateUserProcess hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtCreateProcessEx, (PVOID)&ProxNtCreateProcessEx, (PVOID*)&OriginalNtCreateProcessEx) == FALSE)
	//{
	//	ShvOsDebugPrint("NtCreateProcessEx hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtYieldExecution, (PVOID)&ProxNtYieldExecution, (PVOID*)&OriginalNtYieldExecution) == FALSE)
	//{
	//	ShvOsDebugPrint("NtYieldExecution hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQuerySystemTime, (PVOID)&ProxNtQuerySystemTime, (PVOID*)&OriginalNtQuerySystemTime) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQuerySystemTime hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQueryPerformanceCounter, (PVOID)&ProxNtQueryPerformanceCounter, (PVOID*)&OriginalNtQueryPerformanceCounter) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQueryPerformanceCounter hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtQueryInformationJobObject, (PVOID)&ProxNtQueryInformationJobObject, (PVOID*)&OriginalNtQueryInformationJobObject) == FALSE)
	//{
	//	ShvOsDebugPrint("NtQueryInformationJobObject hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtGetNextProcess, (PVOID)&ProxNtGetNextProcess, (PVOID*)&OriginalNtGetNextProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("NtGetNextProcess hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtOpenProcess, (PVOID)&ProxNtOpenProcess, (PVOID*)&OriginalNtOpenProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("NtOpenProcess hook failed\n");
	//	return FALSE;
	//}

	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtOpenThread, (PVOID)&ProxNtOpenThread, (PVOID*)&OriginalNtOpenThread) == FALSE)
	//{
	//	ShvOsDebugPrint("NtOpenThread hook failed\n");
	//	return FALSE;
	//}
	//if (HookSsdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtSetInformationProcess, (PVOID)&ProxNtSetInformationProcess, (PVOID*)&OriginalNtSetInformationProcess) == FALSE)
	//{
	//	ShvOsDebugPrint("NtSetInformationProcess hook failed\n");
	//	return FALSE;
	//}


	//if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserFindWindowEx, (PVOID)&ProxNtUserFindWindowEx, (PVOID*)&OriginalNtUserFindWindowEx) == FALSE)
	//{
	//	ShvOsDebugPrint("NtUserFindWindowEx hook failed\n");
	//	return FALSE;
	//}
	//ShvOsDebugPrint("OriginalNtUserFindWindowEx [%p]\n", OriginalNtUserFindWindowEx);

	//if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserGetForegroundWindow, (PVOID)&ProxNtUserGetForegroundWindow, (PVOID*)&OriginalNtUserGetForegroundWindow) == FALSE)
	//{
	//	ShvOsDebugPrint("NtUserGetForegroundWindow hook failed\n");
	//	return FALSE;
	//}
	//ShvOsDebugPrint("OriginalNtUserGetForegroundWindow [%p]\n", OriginalNtUserGetForegroundWindow);
	//if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserQueryWindow, (PVOID)&ProxNtUserQueryWindow, (PVOID*)&OriginalNtUserQueryWindow) == FALSE)
	//{
	//	ShvOsDebugPrint("NtUserQueryWindow hook failed\n");

	//	return FALSE;
	//}
	//GlobalConfig::Instance().OriginalNtUserQueryWindow = OriginalNtUserQueryWindow;

	//ShvOsDebugPrint("OriginalNtUserQueryWindow [%p]\n", OriginalNtUserQueryWindow);

	//if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserBuildHwndList, (PVOID)&ProxNtUserBuildHwndList, (PVOID*)&OriginalNtUserBuildHwndList) == FALSE)
	//{
	//	ShvOsDebugPrint("NtUserBuildHwndList hook failed\n");

	//	return FALSE;
	//}
	//ShvOsDebugPrint("OriginalNtUserBuildHwndList [%p]\n", OriginalNtUserBuildHwndList);


	return TRUE;
}

BOOLEAN EptSetPageNoReadWriteAttribute(PVOID VirtualAddress)
{
	UINT64 OrignalPagePhy = MmGetPhysicalAddress(VirtualAddress).QuadPart;
	KAFFINITY AffinityMask;

	for (size_t i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);

		KeSetSystemAffinityThread(AffinityMask);

		ShvVmCallEx((UINT64)VMCALL_EPT_CHANGE_PAGE_NO_RW, OrignalPagePhy, 0, 0, 0, 0, 0, 0, 0, 0);

	}
	return TRUE;
}


BOOLEAN EptPageRecoverAttribute(PVOID VirtualAddress)
{
	UINT64 OrignalPagePhy = MmGetPhysicalAddress(VirtualAddress).QuadPart;
	KAFFINITY AffinityMask;

	for (size_t i = 0; i < (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
		AffinityMask = MathPower(2, (int)i);

		KeSetSystemAffinityThread(AffinityMask);

		ShvVmCallEx((UINT64)VMCALL_EPT_RECOVER_PAGE_ATTRIBUTE, OrignalPagePhy, 0, 0, 0, 0, 0, 0, 0, 0);

	}
	return TRUE;
}


VOID UnHookSyscalls()
{
	//UnHookSsdt(GlobalConfig::Instance().NtContinueEx);
	//UnHookSsdt(GlobalConfig::Instance().NtSetInformationThread);
	//UnHookSsdt(GlobalConfig::Instance().NtQueryInformationProcess);
	//UnHookSsdt(GlobalConfig::Instance().NtQueryObject);
	//UnHookSsdt(GlobalConfig::Instance().NtSystemDebugControl);
	//UnHookSsdt(GlobalConfig::Instance().NtClose);
	//UnHookSsdt(GlobalConfig::Instance().NtSetContextThread);
	//UnHookSsdt(GlobalConfig::Instance().NtQuerySystemInformation);
	//UnHookSsdt(GlobalConfig::Instance().NtGetContextThread);
	//UnHookSsdt(GlobalConfig::Instance().NtQueryInformationThread);
	//UnHookSsdt(GlobalConfig::Instance().NtCreateThreadEx);
	//UnHookSsdt(GlobalConfig::Instance().NtCreateFile);
	//UnHookSsdt(GlobalConfig::Instance().NtCreateUserProcess);
	//UnHookSsdt(GlobalConfig::Instance().NtCreateProcessEx);
	//UnHookSsdt(GlobalConfig::Instance().NtYieldExecution);
	//UnHookSsdt(GlobalConfig::Instance().NtQuerySystemTime);
	//UnHookSsdt(GlobalConfig::Instance().NtQueryPerformanceCounter);
	//UnHookSsdt(GlobalConfig::Instance().NtQueryInformationJobObject);
	//UnHookSsdt(GlobalConfig::Instance().NtGetNextProcess);
	//UnHookSsdt(GlobalConfig::Instance().NtOpenProcess);
	//UnHookSsdt(GlobalConfig::Instance().NtOpenThread);
	//UnHookSsdt(GlobalConfig::Instance().NtSetInformationProcess);


	//UnHookSssdt(GlobalConfig::Instance().NtUserFindWindowEx);
	//UnHookSssdt(GlobalConfig::Instance().NtUserGetForegroundWindow);
	//UnHookSssdt(GlobalConfig::Instance().NtUserQueryWindow);
	//UnHookSssdt(GlobalConfig::Instance().NtUserBuildHwndList);
	//UnHookSssdt(GlobalConfig::Instance().ComunicateFunctionAddress);

}
