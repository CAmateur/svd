#pragma once
#include "GlobalConfig.h"

class Memory
{
public:
	static NTSTATUS LockMemory(UINT64 ProcessId, PVOID Address, SIZE_T Size, OUT PMDL* PMdl);

	static VOID UnlockMemory(PMDL PMdl);
};
