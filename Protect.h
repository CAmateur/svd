#pragma once
#include "GlobalConfig.h"

class Protect
{
public:
	static VOID Initialize();
	static VOID Destory();

	//第二种提权方式
	static BOOLEAN AddProcessIdAndThreadId(CLIENT_ID ClientId);
	static BOOLEAN AddProcessId(UINT64 ProcessId);
	static BOOLEAN AddThreadId(UINT64 ThreadId);
	static BOOLEAN RemoveProcessIdAndThreadId(CLIENT_ID ClientId);
	static BOOLEAN RemoveProcessId(UINT64 ProcessId);
	static BOOLEAN RemoveThreadId(UINT64 ThreadId);
	static UINT64  GetProcessIdAndThreadIdListNodeCount();
	static BOOLEAN IsExistProcessId(UINT64 ProcessId);
	static BOOLEAN IsExistThreadId(UINT64 ThreadId);
private:

	static LIST_ENTRY ProcessIdAndThreadIdListHead;
	static KSPIN_LOCK ProcessIdAndThreadIdListLock;
};