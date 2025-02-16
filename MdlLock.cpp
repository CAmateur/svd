#include"MdlLock.h"



NTSTATUS Memory::LockMemory(UINT64 ProcessId, PVOID Address, SIZE_T Size, OUT PMDL* SavePMdl)
{
	NTSTATUS Status;

	PEPROCESS Process;
	KAPC_STATE ApcState;

	Status = PsLookupProcessByProcessId((PVOID)(ProcessId), (PEPROCESS*)&Process);

	if (!NT_SUCCESS(Status))
		return Status;

	PMDL PMdl = NULL;

	__try
	{
		KeStackAttachProcess((PEPROCESS)Process, &ApcState);

		PMdl = IoAllocateMdl((PVOID)Address, (ULONG)Size, FALSE, FALSE, NULL);
		if (PMdl)
		{
			__try
			{
				MmProbeAndLockPages(PMdl, UserMode, IoReadAccess);
			}
			__except (1)
			{
				IoFreeMdl(PMdl);
				Status = STATUS_UNSUCCESSFUL;
				DbgBreakPoint();

				return Status;
			}
		}
	}
	__finally
	{
		KeUnstackDetachProcess(&ApcState);
	}

	ObDereferenceObject(Process);
	*SavePMdl = PMdl;
	Status = STATUS_SUCCESS;

	return Status;
}

VOID Memory::UnlockMemory(PMDL PMdl)
{
	MmUnlockPages(PMdl);
	IoFreeMdl(PMdl);
}