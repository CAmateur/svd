#pragma once
#include "GlobalConfig.h"

class Handle
{
public:
	static VOID Initialize();
	static VOID Destory();

	//��һ����Ȩ��ʽ
	static VOID HandleGrantAccess(HANDLE_INFORMATION HandleInfo);


	//�ڶ�����Ȩ��ʽ
	static BOOLEAN AddProcessIdAndThreadId(CLIENT_ID ClientId);
	static BOOLEAN AddObjectByProcessId(HANDLE ProcessId,PVOID PObject);
	static BOOLEAN AddObjectByThreadId(HANDLE ThreadId, PVOID PObject);
	static BOOLEAN IsExistProcessId(UINT64 ProcessId);
	static BOOLEAN IsExistThreadId(UINT64 ThreadId);
	static BOOLEAN ISExistObject(PVOID PObject);
	static BOOLEAN RemoveProcessIdAndThreadId(CLIENT_ID ClientId);
	static BOOLEAN RemoveProcessId(UINT64 ProcessId);
	static BOOLEAN RemoveThreadId(UINT64 ThreadId);
	static UINT64  GetProcessIdAndThreadIdListNodeCount();
private:

	static LIST_ENTRY ProcessIdAndThreadIdListHead;
	static KSPIN_LOCK ProcessIdAndThreadIdListLock;
};