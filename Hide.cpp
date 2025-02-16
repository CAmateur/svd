#include "Hide.h"
#include "EptHook.h"
typedef enum _THREAD_STATE_ROUTINE
{
	THREADSTATE_GETTHREADINFO,
	THREADSTATE_ACTIVEWINDOW
} THREAD_STATE_ROUTINE;

//同时他的作用也有白名单的作用
CONST unsigned short* HideApplicationNames[] =
{
	L"xtlh32.exe",//虚途
	L"Scann Toolss.exe",//虚途
};

CONST unsigned short* HideWindowNames[] =
{
	L"HyperHide",
	L"disassembly",
	L"Sysinternals",
	L"虚途", //虚途
	L"Scann Toolss (Admin)",
	L"Scann Toolss",
};
CONST unsigned short* HideWindowClassNames[] =
{
	L"Qt5QWindowIcon" // Ida and x64dbg ClassNames
	L"ObsidianGUI",
	L"idawindow",
	L"tnavbox",
	L"idaview",
	L"tgrzoom",
	L"Qt672dQWindowIcon", //虚途
	L"SysTabControl32",
	L"SysListView32",
};


HANDLE(NTAPI* Hide::OriginalNtUserFindWindowEx)(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type) = nullptr;
HANDLE(NTAPI* Hide::OriginalNtUserGetForegroundWindow)() = nullptr;
HANDLE(NTAPI* Hide::OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo) = nullptr;
NTSTATUS(NTAPI* Hide::OriginalNtUserBuildHwndList)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize) = nullptr;
NTSTATUS(__fastcall* Hide::OriginalNtGdiExtTextOutW)(__int64 a1, unsigned int a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, int a7, __int64 a8, int a9) = nullptr;

HANDLE NTAPI Hide::ProxNtUserFindWindowEx(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type)
{

	HANDLE hWnd = OriginalNtUserFindWindowEx(hwndParent, hwndChild, ClassName, WindowName, Type);

	UNICODE_STRING WindowProcessName = PsQueryFullProcessImageName(IoGetCurrentProcess());

	//如果进程名不在白名单中，且窗口名或窗口类名在黑名单中，则返回0
	if (IsProcessNameWhiteList(&WindowProcessName) == FALSE && (IsProcessWindowBad(WindowName) == TRUE || IsProcessWindowClassBad(ClassName) == TRUE))
	{
		//ShvOsDebugPrint("ProxNtUserFindWindowEx:[%p] ClassName:[%wZ] WindowName:[%wZ]\n", hWnd, ClassName, WindowName);
		return 0;
	}

	return hWnd;
}
HANDLE NTAPI Hide::ProxNtUserGetForegroundWindow()
{
	HANDLE hWnd = OriginalNtUserGetForegroundWindow();
	if (hWnd != NULL && IsWindowBad(hWnd) == TRUE)
	{
		if (GlobalConfig::Instance().NtUserGetThreadState)
		{
			hWnd = GlobalConfig::Instance().NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
			//ShvOsDebugPrint("ProxNtUserGetForegroundWindow:[%p]\n", hWnd);
		}
		else
		{
			ShvOsDebugPrint("GlobalConfig::Instance().NtUserGetThreadState is NULL\n");
		}
	}
	return hWnd;
}

NTSTATUS NTAPI Hide::ProxNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize)
{
	NTSTATUS Status = OriginalNtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

	if (NT_SUCCESS(Status) == TRUE && pWnd != NULL && pBufSize != NULL)
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


NTSTATUS __fastcall Hide::ProxNtGdiExtTextOutW(__int64 a1, unsigned int a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, int a7, __int64 a8, int a9)
{
	NTSTATUS Status = STATUS_SUCCESS;
	//ULONG StringSize = 0;

	if ((a7 > 0xFFFF) || (a7 > 0 && a6 == NULL))
	{
		Status = OriginalNtGdiExtTextOutW(a1, a2, a3, a4, a5, a6, a7, a8, a9);
		return Status;
	}

	//if (a7 > 0)
	//{

		//StringSize = a7 * sizeof(WCHAR);
		//ProbeForRead((volatile void*)a6, StringSize, 1);

		// 用一个缓冲区初始化字符串
		//UNICODE_STRING dst;
		//WCHAR dst_buf[256];
		//RtlCopyMemory((PVOID)dst_buf, (PVOID)a6, (USHORT)StringSize);
		//RtlInitEmptyUnicodeString(&dst, dst_buf, (USHORT)StringSize);
		//ShvOsDebugPrint("%wZ\n", &dst);
	//}

	Status = OriginalNtGdiExtTextOutW(a1, a2, a3, a4, a5, a6, a7, a8, a9);

	return Status;
}


HANDLE NTAPI Hide::ProxNtUserQueryWindow(HANDLE hWnd, WINDOWINFOCLASS WindowInfo)
{
	if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hWnd))
	{
		if (WindowInfo == WindowProcess)
			return PsGetCurrentProcessId();

		if (WindowInfo == WindowThread)
			return PsGetCurrentProcessId();
	}
	return OriginalNtUserQueryWindow(hWnd, WindowInfo);
}



BOOLEAN Hide::Initialize()
{
	return HookSyscalls();
}

VOID Hide::Destory()
{
	UnHookSyscalls();
}

BOOLEAN Hide::HookSyscalls()
{
	//未hook的代码
	//NtUserGetClassName
	//NtUserInternalGetWindowText
	if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserQueryWindow, (PVOID)&ProxNtUserQueryWindow, (PVOID*)&OriginalNtUserQueryWindow) == FALSE)
	{
		ShvOsDebugPrint("NtUserQueryWindow hook failed\n");

		return FALSE;
	}

	GlobalConfig::Instance().OriginalNtUserQueryWindow = OriginalNtUserQueryWindow;

	if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserFindWindowEx, (PVOID)&ProxNtUserFindWindowEx, (PVOID*)&OriginalNtUserFindWindowEx) == FALSE)
	{
		ShvOsDebugPrint("NtUserFindWindowEx hook failed\n");
		return FALSE;
	}
	//ShvOsDebugPrint("OriginalNtUserFindWindowEx [%p]\n", OriginalNtUserFindWindowEx);

	if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserGetForegroundWindow, (PVOID)&ProxNtUserGetForegroundWindow, (PVOID*)&OriginalNtUserGetForegroundWindow) == FALSE)
	{
		ShvOsDebugPrint("NtUserGetForegroundWindow hook failed\n");
		return FALSE;
	}
	//ShvOsDebugPrint("OriginalNtUserGetForegroundWindow [%p]\n", OriginalNtUserGetForegroundWindow);


	//ShvOsDebugPrint("OriginalNtUserQueryWindow [%p]\n", OriginalNtUserQueryWindow);

	if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtUserBuildHwndList, (PVOID)&ProxNtUserBuildHwndList, (PVOID*)&OriginalNtUserBuildHwndList) == FALSE)
	{
		ShvOsDebugPrint("NtUserBuildHwndList hook failed\n");

		return FALSE;
	}
	//ShvOsDebugPrint("OriginalNtUserBuildHwndList [%p]\n", OriginalNtUserBuildHwndList);

	if (HookSssdtTwoTrampoline((PVOID)GlobalConfig::Instance().NtGdiExtTextOutW, (PVOID)&ProxNtGdiExtTextOutW, (PVOID*)&OriginalNtGdiExtTextOutW) == FALSE)
	{
		ShvOsDebugPrint("NtGdiExtTextOutW hook failed\n");

		return FALSE;
	}
	return TRUE;
}

VOID Hide::UnHookSyscalls()
{

	UnHookSssdt(GlobalConfig::Instance().NtUserFindWindowEx);
	UnHookSssdt(GlobalConfig::Instance().NtUserGetForegroundWindow);
	UnHookSssdt(GlobalConfig::Instance().NtUserQueryWindow);
	UnHookSssdt(GlobalConfig::Instance().NtUserBuildHwndList);
	UnHookSssdt(GlobalConfig::Instance().NtGdiExtTextOutW);
}


BOOLEAN Hide::IsWindowBad(HANDLE hWnd)
{
	if (!GlobalConfig::Instance().OriginalNtUserQueryWindow)
	{
		ShvOsDebugPrint("GlobalConfig::Instance().OriginalNtUserQueryWindow is NULL\n");
		return FALSE;
	}

	PEPROCESS WindProcess = PidToProcess(GlobalConfig::Instance().OriginalNtUserQueryWindow(hWnd, WindowProcess));
	if (WindProcess && WindProcess == IoGetCurrentProcess())
		return FALSE;

	UNICODE_STRING WindowProcessName = PsQueryFullProcessImageName(WindProcess);

	return IsProcessNameBad(&WindowProcessName);
}


BOOLEAN Hide::IsProcessNameBad(PUNICODE_STRING ProcessName)
{
	if (ProcessName->Buffer == NULL || ProcessName->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbiddenProcessName;
	for (ULONG64 i = 0; i < sizeof(HideApplicationNames) / sizeof(HideApplicationNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbiddenProcessName, HideApplicationNames[i]);
		if (RtlCompareUnicodeString(&ForbiddenProcessName, ProcessName, TRUE) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN Hide::IsProcessNameWhiteList(PUNICODE_STRING ProcessName)
{
	if (ProcessName->Buffer == NULL || ProcessName->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbiddenProcessName;
	for (ULONG64 i = 0; i < sizeof(HideApplicationNames) / sizeof(HideApplicationNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbiddenProcessName, HideApplicationNames[i]);
		if (RtlCompareUnicodeString(&ForbiddenProcessName, ProcessName, TRUE) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}
BOOLEAN Hide::IsProcessWindowBad(PUNICODE_STRING WindowName)
{
	if (WindowName->Buffer == NULL || WindowName->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbiddenWindowName;
	for (ULONG64 i = 0; i < sizeof(HideWindowNames) / sizeof(HideWindowNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbiddenWindowName, HideWindowNames[i]);
		if (RtlCompareUnicodeString(WindowName, &ForbiddenWindowName, FALSE) == 0)
			return TRUE;
	}

	return FALSE;
}

BOOLEAN Hide::IsProcessWindowClassBad(PUNICODE_STRING WindowClassName)
{
	if (WindowClassName->Buffer == NULL || WindowClassName->Length == NULL)
		return FALSE;

	UNICODE_STRING ForbbidenWindowClassName;

	for (ULONG64 i = 0; i < sizeof(HideWindowClassNames) / sizeof(HideWindowClassNames[0]); i++)
	{
		RtlInitUnicodeString(&ForbbidenWindowClassName, HideWindowClassNames[i]);
		if (RtlCompareUnicodeString(WindowClassName, &ForbbidenWindowClassName, FALSE) == 0)
			return TRUE;
	}

	return FALSE;
}