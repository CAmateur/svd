#pragma once
#include "GlobalConfig.h"

class Hide
{
public:
	static BOOLEAN Initialize();
	static VOID Destory();
	static BOOLEAN IsProcessNameBad(PUNICODE_STRING ProcessName);
	static BOOLEAN IsProcessNameWhiteList(PUNICODE_STRING ProcessName);
	static BOOLEAN IsWindowBad(HANDLE hWnd);
	static BOOLEAN IsProcessWindowBad(PUNICODE_STRING WindowName);
	static BOOLEAN IsProcessWindowClassBad(PUNICODE_STRING WindowClassName);
private:
	static BOOLEAN HookSyscalls();
	static VOID UnHookSyscalls();
private:
	static HANDLE(NTAPI* OriginalNtUserFindWindowEx)(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type);
	static HANDLE(NTAPI* OriginalNtUserGetForegroundWindow)();
	static HANDLE(NTAPI* OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);
	static NTSTATUS(NTAPI* OriginalNtUserBuildHwndList)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	static NTSTATUS(__fastcall* OriginalNtGdiExtTextOutW)(__int64 a1, unsigned int a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, int a7, __int64 a8, int a9);
	static HANDLE NTAPI ProxNtUserFindWindowEx(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type);
	static HANDLE NTAPI ProxNtUserGetForegroundWindow();
	static HANDLE NTAPI ProxNtUserQueryWindow(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);
	static NTSTATUS NTAPI ProxNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	static NTSTATUS __fastcall ProxNtGdiExtTextOutW(__int64 a1, unsigned int a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, int a7, __int64 a8, int a9);
};	