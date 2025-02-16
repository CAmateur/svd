#include "File.h"
#include <ntstrsafe.h>
EXTERN_C NTKERNELAPI PVOID NTAPI ObGetObjectType(IN PVOID pObject);

/**
删除物理文件
*/
NTSTATUS DeleteMySelf(PUNICODE_STRING reg_path)
{
	HANDLE Mykey = 0;
	NTSTATUS status = 0;
	ULONG Uclength = 512;
	PVOID Key_info = NULL;


	LARGE_INTEGER number = { 0 };
	number.QuadPart = 0i64;
	Key_info = ExAllocatePool(NonPagedPool, 512);

	OBJECT_ATTRIBUTES Myobject = { 0 };
	InitializeObjectAttributes(
		&Myobject,
		reg_path,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);
	status = ZwOpenKey(&Mykey, KEY_READ, &Myobject);
	if (!NT_SUCCESS(status))
	{
		////DbgPrint("打开注册表失败\n");
		return status;//ImagePath
	}
	UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"ImagePath");
	if (Key_info != NULL)
	{
		memset(Key_info, 0x00, 512);
		status = ZwQueryValueKey(Mykey,
			&KeyName,
			KeyValuePartialInformation,
			(PKEY_VALUE_PARTIAL_INFORMATION)Key_info,
			Uclength,
			&Uclength);
		if (!NT_SUCCESS(status))
			return status;
	}
	ZwClose(Mykey);
	if (Key_info != NULL)
	{
		PKEY_VALUE_PARTIAL_INFORMATION tempkeyinfo = (PKEY_VALUE_PARTIAL_INFORMATION)Key_info;
		PWCHAR FilePath = (PWCHAR)tempkeyinfo->Data;
		////DbgPrint("%ws", FilePath);
		status = DeleteFileWithIrp(FilePath);
		if (!NT_SUCCESS(status)) {
			if (!Key_info) {
				ExFreePool(Key_info);
			}
			return status;
		}
	}
	/*
	RtlInitUnicodeString(&MyFilePath, FilePath);
	InitializeObjectAttributes(
		&MyFileobject,
		&MyFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	status = ZwCreateFile(&hfile,
		GENERIC_WRITE,
		&MyFileobject,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_SUPERSEDE,//如果文件存在，则替换，不存在 则创建
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		////DbgPrint("create file failed..--%x/n,ntStatus", status);
		ZwClose(hfile);
		if (!Key_info) {
			ExFreePool(Key_info);
		}
		return status;
	}
	status = ZwWriteFile(hfile, NULL, NULL, NULL, &iostatus, drmkaud, sizeof(drmkaud), &number, NULL);
	if (!NT_SUCCESS(status)) {
		////DbgPrint("Wrice file failed../n");
	}
	ZwClose(hfile);
	if (!Key_info) {
		ExFreePool(Key_info);
	}*/
	return status;
}
NTSTATUS IrpSetInformationFileCompletionRoutine(PDEVICE_OBJECT  device, PIRP aIrp, PVOID context)
{
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(context);
	*aIrp->UserIosb = aIrp->IoStatus;
	if (aIrp->UserEvent)
		KeSetEvent(aIrp->UserEvent, IO_NO_INCREMENT, 0);

	if (aIrp->MdlAddress)
	{
		IoFreeMdl(aIrp->MdlAddress);
		aIrp->MdlAddress = NULL;
	}

	IoFreeIrp(aIrp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}
NTSTATUS IrpSetInformationFile(PFILE_OBJECT aFileObject, PIO_STATUS_BLOCK aIoStatusBlock, PVOID aFileInformation, ULONG aLength, FILE_INFORMATION_CLASS aFileInformationClass)
{
	NTSTATUS vStatus = STATUS_SUCCESS;

	for (;;)
	{
		PDEVICE_OBJECT vDeviceObject = IoGetRelatedDeviceObject(aFileObject);

		PIRP vIrp = IoAllocateIrp(vDeviceObject->StackSize, FALSE);
		if (NULL == vIrp)
		{
			vStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		KEVENT vIrpEvent = { 0 };
		KeInitializeEvent(&vIrpEvent, SynchronizationEvent, FALSE);

		vIrp->UserEvent = &vIrpEvent;
		vIrp->UserIosb = aIoStatusBlock;
		vIrp->RequestorMode = KernelMode;
		vIrp->AssociatedIrp.SystemBuffer = aFileInformation;
		vIrp->Tail.Overlay.OriginalFileObject = aFileObject;
		vIrp->Tail.Overlay.Thread = PsGetCurrentThread();

		PIO_STACK_LOCATION vIrpSP = IoGetNextIrpStackLocation(vIrp);
		vIrpSP->MajorFunction = IRP_MJ_SET_INFORMATION;
		vIrpSP->DeviceObject = vDeviceObject;
		vIrpSP->FileObject = aFileObject;
		vIrpSP->Parameters.SetFile.FileObject = aFileObject;
		vIrpSP->Parameters.SetFile.Length = aLength;
		vIrpSP->Parameters.SetFile.FileInformationClass = aFileInformationClass;

		if (FileLinkInformation == aFileInformationClass)
		{
			PFILE_LINK_INFORMATION vArgs = (PFILE_LINK_INFORMATION)(aFileInformation);
			vIrpSP->Parameters.SetFile.ReplaceIfExists = vArgs->ReplaceIfExists;
		}
		else if (FileRenameInformation == aFileInformationClass)
		{
			PFILE_RENAME_INFORMATION vArgs = (PFILE_RENAME_INFORMATION)(aFileInformation);
			vIrpSP->Parameters.SetFile.ReplaceIfExists = vArgs->ReplaceIfExists;
		}

		vStatus = IoSetCompletionRoutineEx(
			vDeviceObject,
			vIrp,
			IrpSetInformationFileCompletionRoutine,
			NULL,
			TRUE, TRUE, TRUE);
		if (!NT_SUCCESS(vStatus))
		{
			IoFreeIrp(vIrp), vIrp = NULL;
			break;
		}

		vStatus = IoCallDriver(vDeviceObject, vIrp);
		if (!NT_SUCCESS(vStatus))
		{
			break;
		}

		vStatus = KeWaitForSingleObject(&vIrpEvent, Executive, KernelMode, TRUE, NULL);
		break;
	}

	return vStatus;
}
NTSTATUS FixFilePath(PWCHAR* aFixedPath, PWCHAR aFilePath)
{
	NTSTATUS    vStatus = STATUS_SUCCESS;
	LPWSTR      vPath = NULL;

	for (;;)
	{
		if (NULL == aFilePath)
		{
			vStatus = STATUS_NOT_FOUND;
			break;
		}

		WCHAR cNtPrefix[] = L"\\??\\";
		if (wcsstr(aFilePath, cNtPrefix))
		{
			size_t vPathBytes = wcslen(aFilePath) * sizeof(aFilePath[0]) + sizeof(UNICODE_NULL);
			vPath = (LPWSTR)ExAllocatePool(NonPagedPool, vPathBytes);
			if (NULL == vPath)
			{
				vStatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			vStatus = RtlStringCbCopyW(vPath, vPathBytes, aFilePath);
		}
		else
		{
			size_t vPathBytes = wcslen(aFilePath) * sizeof(aFilePath[0]) + sizeof(cNtPrefix);
			vPath = (LPWSTR)ExAllocatePool(NonPagedPool, vPathBytes);
			if (NULL == vPath)
			{
				vStatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			vStatus = RtlStringCbCopyW(vPath, vPathBytes, cNtPrefix);
			if (!NT_SUCCESS(vStatus))
			{
				break;
			}

			vStatus = RtlStringCbCatW(vPath, vPathBytes, aFilePath);
		}
		if (!NT_SUCCESS(vStatus))
		{
			break;
		}

		*aFixedPath = vPath;
		break;
	}
	if (!NT_SUCCESS(vStatus))
	{
		if (vPath) ExFreePool(vPath), vPath = NULL;
	}

	return vStatus;
}
NTSTATUS DeleteFileWithIrp(PWCHAR aFilePath)
{

	NTSTATUS    vStatus = STATUS_SUCCESS;
	PWCHAR      vFixedPath = NULL;
	HANDLE      vFileHandle = NULL;

	KAPC_STATE  vAttachContext = { 0 };
	KeStackAttachProcess(PsGetCurrentProcess(), &vAttachContext);
	for (;;)
	{
		vStatus = FixFilePath(&vFixedPath, aFilePath);
		if (!NT_SUCCESS(vStatus)) {
			break;
		}
		UNICODE_STRING vPath = { 0 };
		RtlInitUnicodeString(&vPath, vFixedPath);

		IO_STATUS_BLOCK     vStatusBlock = { 0 };
		OBJECT_ATTRIBUTES   vObjAttr = { 0 };
		InitializeObjectAttributes(&vObjAttr, &vPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		vStatus = ZwOpenFile(
			&vFileHandle,
			SYNCHRONIZE,
			&vObjAttr,
			&vStatusBlock,
			FILE_SHARE_READ,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
		if (!NT_SUCCESS(vStatus))
		{
			break;
		}

		PFILE_OBJECT vFileObject = NULL;
		vStatus = ObReferenceObjectByHandle(vFileHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&vFileObject, NULL);
		if (!NT_SUCCESS(vStatus))
		{
			break;
		}

		PVOID vImageSection = NULL;
		PVOID vDataSection = NULL;
		if (MmIsAddressValid(vFileObject->SectionObjectPointer))
		{
			vImageSection = vFileObject->SectionObjectPointer->ImageSectionObject;
			vDataSection = vFileObject->SectionObjectPointer->DataSectionObject;

			vFileObject->SectionObjectPointer->ImageSectionObject = NULL;
			vFileObject->SectionObjectPointer->DataSectionObject = NULL;
		}
		vFileObject->DeleteAccess = TRUE;

		IO_STATUS_BLOCK vIoSb = { 0 };
		FILE_DISPOSITION_INFORMATION vArgs = { TRUE };
		vStatus = IrpSetInformationFile(vFileObject, &vIoSb, &vArgs, sizeof(vArgs), FileDispositionInformation);

		if (MmIsAddressValid(vFileObject->SectionObjectPointer))
		{
			if (vImageSection) vFileObject->SectionObjectPointer->ImageSectionObject = vImageSection;
			if (vDataSection)  vFileObject->SectionObjectPointer->DataSectionObject = vDataSection;
		}

		ObDereferenceObject(vFileObject), vFileObject = NULL;

		vStatus = vIoSb.Status;
		break;
	}
	if (vFileHandle) ZwClose(vFileHandle), vFileHandle = NULL;
	if (vFixedPath)  ExFreePool(vFixedPath), vFixedPath = NULL;
	KeUnstackDetachProcess(&vAttachContext);

	return vStatus;
}
BOOLEAN IsFile(PVOID Object)
{
	BOOLEAN result = TRUE;
	if (!MmIsAddressValid(Object))
		result = FALSE;
	PVOID vObType = ObGetObjectType(Object);
	if (*IoFileObjectType != vObType)
		result = FALSE;
	return result;
}
NTSTATUS GetFullPathName(PFILE_OBJECT fileObject, POBJECT_NAME_INFORMATION* objectNameInformation)
{

	return IoQueryFileDosDeviceName(fileObject,
		objectNameInformation
	);

}

/*
* 强制删除文件
*/
NTSTATUS DelFile(CHAR* FilePath) {
	NTSTATUS bRet = STATUS_UNSUCCESSFUL;
	if ((INT64)FilePath <= 0) return bRet;
	__try {
		ANSI_STRING AnsiBuffer = { 0 };
		UNICODE_STRING Path = { 0 };
		AnsiBuffer.Buffer = FilePath;
		AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(FilePath);
		RtlAnsiStringToUnicodeString(&Path, &AnsiBuffer, TRUE);//转换

		if (NT_SUCCESS(DeleteFileWithIrp(Path.Buffer))) {
			bRet = STATUS_SUCCESS;
		}
		RtlFreeUnicodeString(&Path);// 释放内存
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		bRet = STATUS_UNSUCCESSFUL;
	}
	return bRet;
}