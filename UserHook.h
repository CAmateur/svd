#pragma once
#include"GlobalConfig.h"

typedef struct _EPT_HOOK_USER_PARAM
{
	UINT64 Type;
	UINT64 ProcessId;
	UINT64 TargetVirtualAddress;
	UINT64 TargetPhysicalAddress;
	UINT64 TargetPageVirtualAddress;
	UINT64 TargetPagePhysicalAddress;
	UINT64 FakePageVirtualAddress;
	UINT64 FakePagePhysicalAddress;
	PMDL   PMdl;
}EPT_HOOK_USER_PARAM, * PEPT_HOOK_USER_PARAM;

typedef struct _EPT_HOOK_USER_LIST
{
	LIST_ENTRY EptHookR3List;
	EPT_HOOK_USER_PARAM	Param;
}EPT_HOOK_USER_LIST, * PEPT_HOOK_USER_LIST;

typedef struct _EPT_USER_PAGE_MONITOR
{
	UINT32 Pid;
	UINT64 VirtualAddress;
	UINT64 Buffer;
	SIZE_T BufferSize;
	BOOLEAN Status;
}EPT_USER_PAGE_MONITOR, * PEPT_USER_PAGE_MONITOR;




class UserHook
{
private:
	static LIST_ENTRY EptHookUserListHead;
	static KSPIN_LOCK EptHookUserListLock;
public:
	static BOOLEAN AddEptHookUserListNode(UINT64 ProcessId, PEPT_HOOK_USER_PARAM Param);
	static BOOLEAN GetEptHookUserListNode(UINT64 ProcessId, PVOID TargetVirtualAddress, PEPT_HOOK_USER_PARAM Param);
	static BOOLEAN GetEptHookUserListNodeByPid(UINT64 ProcessId, PEPT_HOOK_USER_PARAM Param);
	static BOOLEAN RemoveEptHookUserListNode(UINT64 ProcessId, PVOID TargetVirtualAddress);
	static BOOLEAN RemoveALLEptHookUserListNodeByPid(UINT64 ProcessId);
	static BOOLEAN GetEptHookUserProcessId(UINT64* ProcessId);
	static BOOLEAN IsExistUserEptBreakPint(UINT64 ProcessId, PVOID TargetVirtualAddress, PEPT_HOOK_USER_PARAM PParam);

public:
	static VOID Initialize();
	static VOID Destory();

	static BOOLEAN HookUser(UINT64 ProcessId, PVOID TargetVirtualAddress);
	static BOOLEAN HookUserFreely(UINT64 ProcessId, PVOID TargetVirtualAddress, PVOID Buffer);
	static BOOLEAN UnHookUser(UINT64 ProcessId, PVOID TargetVirtualAddress);
	static BOOLEAN MonitorUserPageAccessFreely(UINT64 ProcessId, PVOID TargetVirtualAddress);
	static BOOLEAN AntiHookAndMonitorUserPageAccessFreely(UINT64 ProcessId, PVOID TargetVirtualAddress);
	static BOOLEAN UserEptBreakPoint(UINT64 ProcessId, PVOID TargetVirtualAddress, SIZE_T TargetVirtualAddressInstructionLength, INT32 RegisterIndex, PBREAKPOINT_FILTER_DATA PFilterData);
	static BOOLEAN UserEptUnBreakPoint(UINT64 ProcessId, PVOID TargetVirtualAddress, UCHAR OldValue);
};
