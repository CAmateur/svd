#pragma once
#include <ntifs.h>
BOOLEAN
IsFile(
	PVOID Object);


NTSTATUS
IrpSetInformationFileCompletionRoutine(
	PDEVICE_OBJECT device,
	PIRP aIrp,
	PVOID context);


NTSTATUS
IrpSetInformationFile(
	PFILE_OBJECT            aFileObject,
	PIO_STATUS_BLOCK        aIoStatusBlock,
	PVOID                   aFileInformation,
	ULONG                   aLength,
	FILE_INFORMATION_CLASS  aFileInformationClass);


NTSTATUS
FixFilePath(
	PWCHAR* aFixedPath,
	PWCHAR aFilePath);


NTSTATUS
DeleteFileWithIrp(
	PWCHAR aFilePath);


NTSTATUS
GetFullPathName(
	PFILE_OBJECT fileObject,
	POBJECT_NAME_INFORMATION* objectNameInformation);




NTSTATUS
DeleteMySelf(
	PUNICODE_STRING reg_path);


NTSTATUS DelFile(CHAR* FilePath);