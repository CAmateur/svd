#pragma once
#include <ntifs.h>
#include "StructForGlobalConfig.h"

class GlobalConfig {
public:
	static GlobalConfig& Instance() {
		static GlobalConfig instance;  // 饿汉式单例，在程序启动时创建
		return instance;
	}
	INT64(__fastcall* MiGetPteAddress)(UINT64) = NULL;
	HANDLE(NTAPI* OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo) = NULL;
	HANDLE(NTAPI* NtUserGetThreadState)(ULONG Routine);

	ULONG   CurrentWindowsBuildNumber = 0;
	PMMPFN  pMmPfnDatabase = { 0 };
	UCHAR   KernelAlignIndex = 0;
	UCHAR   Win32kAlignIndex = 0;
	UCHAR   volmgrAlignIndex = 0;
	UINT64  Win32kCodeCaves[200] = { 0 };
	UINT64  KernelCodeCaves[200] = { 0 };
	UINT64  volmgrCodeCaves[1] = { 0 };
	UINT64  volmgrAddress = 0;
	UINT64  NtoskrnlAddress = 0;
	UINT64  Win32kAddress = 0;
	UINT64  NtdllAddress = 0;
	UINT64  SysdiagDriverAddress = 0;
	UINT64  ACEBASEDriverAddress = 0;
	UINT64  SysdiagDriverSize = 0;
	UINT64  ACEBASEDriverSize = 0;

	UINT64  LdrLoadDll = 0;

	UINT64	KiUserExceptionDispatcherAddress = 0;
	UINT64  MmPfnDatabaseAddress = 0;


	PKUSER_SHARED_DATA  KernelKuserSharedDataAddress = 0;


	UINT64 NtSetInformationThread = 0;
	UINT64 NtQueryInformationProcess = 0;
	UINT64 NtQueryObject = 0;
	UINT64 NtSystemDebugControl = 0;
	UINT64 NtSetContextThread = 0;
	UINT64 NtQuerySystemInformation = 0;
	UINT64 NtGetContextThread = 0;
	UINT64 NtClose;
	UINT64 NtQueryInformationThread = 0;
	UINT64 NtCreateThreadEx = 0;
	UINT64 NtCreateFile = 0;
	UINT64 NtCreateProcessEx = 0;
	UINT64 NtYieldExecution = 0;
	UINT64 NtQuerySystemTime = 0;
	UINT64 NtQueryPerformanceCounter = 0;
	UINT64 NtContinue = 0;
	UINT64 NtContinueEx = 0;
	UINT64 NtQueryInformationJobObject = 0;
	UINT64 NtCreateUserProcess = 0;
	UINT64 NtGetNextProcess = 0;
	UINT64 NtOpenProcess = 0;
	UINT64 NtOpenThread = 0;
	UINT64 NtSetInformationProcess = 0;
	UINT64 NtRemoveProcessDebug = 0;
	UINT64 NtReadVirtualMemory = 0;
	UINT64 NtWriteVirtualMemory = 0;
	UINT64 NtTerminateProcess = 0;
	UINT64 NtTerminateThread = 0;
	UINT64 ZwProtectVirtualMemory = 0;



	UINT64 ObpCallPostOperationCallbacks = 0;
	UINT64 ObpCallPreOperationCallbacks = 0;



	UINT64 NtUserFindWindowEx = 0;
	UINT64 NtUserBuildHwndList = 0;
	UINT64 NtUserQueryWindow = 0;
	UINT64 NtUserGetForegroundWindow = 0;
	UINT64 NtUserGetClassName = 0;
	UINT64 NtUserInternalGetWindowText = 0;
	UINT64 NtUserEnumDisplayDevices = 0;
	UINT64 NtGdiExtTextOutW = 0;

	UINT64 NtCreateDebugObject = 0;
	UINT64 NtDebugActiveProcess = 0;
	UINT64 DbgkCreateThread = 0;
	UINT64 DbgkExitThread = 0;
	UINT64 DbgkExitProcess = 0;
	UINT64 DbgkMapViewOfSection = 0;
	UINT64 DbgkUnMapViewOfSection = 0;
	UINT64 KiDispatchException = 0;
	UINT64 NtWaitForDebugEvent = 0;
	UINT64 DbgkpCloseObject = 0;
	UINT64 NtDebugContinue = 0;
	UINT64 DbgkpMarkProcessPeb = 0;
	UINT64 DbgkForwardException = 0;


	UINT64 ObCreateObjectType = 0;
	UINT64 DbgkDebugObjectType = 0;

	UINT64 ObTypeIndexTable = 0;
	UINT64 ObjectTable = 0;

	UINT64 PspLoadImageNotifyRoutine = 0;
	UINT64 CallbackListHead = 0;
	UINT64 PspCreateProcessNotifyRoutine = 0;
	UINT64 PspCreateThreadNotifyRoutine = 0;


	UINT64 PsTerminateProcess = 0;
	UINT64 DbgkpWakeTarget = 0;
	UINT64 PsGetNextProcess = 0;
	UINT64 PspCheckForInvalidAccessByProtection = 0;
	UINT64 PsGetNextProcessThread = 0;
	UINT64 PsSynchronizeWithThreadInsertion = 0;
	UINT64 PsSuspendThread = 0;
	UINT64 PsResumeThread = 0;
	UINT64 DbgkpSectionToFileHandle = 0;
	UINT64 PsQuerySystemDllInfo = 0;
	UINT64 DbgkpSuspendProcess = 0;
	UINT64 PsThawMultiProcess = 0;
	UINT64 MmGetFileNameForAddress = 0;
	UINT64 PsCallImageNotifyRoutines = 0;
	UINT64 PspReferenceSystemDll = 0;
	UINT64 MiSectionControlArea = 0;
	UINT64 MiReferenceControlAreaFile = 0;
	UINT64 ObFastDereferenceObject = 0;
	UINT64 DbgkpConvertKernelToUserStateChange = 0;
	UINT64 DbgkpOpenHandles = 0;
	UINT64 DbgkpSendApiMessageLpc = 0;
	UINT64 DbgkpSendErrorMessage = 0;
	UINT64 PsCaptureExceptionPort = 0;
	UINT64 ObpReferenceObjectByHandleWithTag = 0;





	LIST_ENTRY			HiddenProcessesHead;
	KGUARDED_MUTEX		HiderMutex;
	BOOLEAN				StopCounterThread = FALSE;
	HANDLE				CounterThreadHandle = 0;
	UINT32				NumberOfActiveDebuggers = 0;

	UINT64              ComunicateFunctionAddress = 0;

	ULONG SeAuditProcessCreationInfoOffset;
	ULONG BypassProcessFreezeFlagOffset;
	ULONG ThreadHideFromDebuggerFlagOffset;
	ULONG ThreadBreakOnTerminationFlagOffset;
	ULONG PicoContextOffset;
	ULONG RestrictSetThreadContextOffset;

	ULONG DebugPortOffset;
	ULONG WoW64ProcessOffset;
	ULONG ProtectionOffset;
	ULONG PcbSecureStateOffset;
	ULONG RundownProtectOffset;
	ULONG UniqueProcessIdOffset;
	ULONG SectionObjectOffset;
	ULONG MiscFlagsOffset;
	ULONG CrossThreadFlagsOffset;
	ULONG ThreadRundownProtectOffset;
	ULONG SectionBaseAddressOffset;
	ULONG Win32StartAddressOffset;
	ULONG CidOffset;
	ULONG ApcStateOffset;
	ULONG ApcStateProcessOffset;
	ULONG PebOffset;
	ULONG TebOffset;
	ULONG StaticUnicodeBufferOffset;
	ULONG NtTibArbitraryUserPointerOffset;
	ULONG FlagsOffset;
	ULONG SameThreadPassiveFlagsOffset;
	ULONG ExitTimeOffset;
	ULONG SameTebFlagsOffset;
	ULONG TcbPreviousModeOffset;
	ULONG TcbProcessOffset;
	ULONG MachineOffset;
	ULONG ActiveProcessLinksOffset;
	ULONG DirectoryTableBaseOffset;
	ULONG UserDirectoryTableBaseOffset;
	ULONG ThreadListHeadOffset;
	ULONG ThreadListEntryOffset;

	KMUTEX NtCloseMutex;



private:
	GlobalConfig() {};                                      // 构造函数私有
	GlobalConfig(const GlobalConfig&) = delete;             // 禁用拷贝构造
	GlobalConfig& operator=(const GlobalConfig&) = delete;  // 禁用赋值
};

#define POOLTAG 'vres'

#define CommandMemoryRead 0x76C3B4
#define CommandMemoryWrite 0x76C3B8

#define CommandAntiAceCallBack 0x76C3BC   
#define CommandUnHideFromSyscall 0x76C3C0

#define CommandUserEptHook 0x76C3C8
#define CommandUserEptHookFreely 0x76C3CC
#define CommandUserEptUnHook 0x76C3D0

#define CommandAddDebugger 0x76C3D4

#define CommandUpdateHanldeAccess 0x76C3D8
#define CommandUserEptBreakPoint 0x76C3DC
#define CommandProtect 0x76C3E0

#define HandleMethodOne 1
#define HandleMethodTwo 2

#define ReadProcessMemoryByHostMmCopyMemoryMethod 1
#define ReadProcessMemoryByMdlMethod 2
#define ReadProcessMemoryByMmCopyVirtualMemoryMethod 3
#define ReadProcessMemoryByHostCr3Method 4
#define ReadProcessMemoryByMmMapIoSpaceMethod 5
#define ReadProcessMemoryByInvlpgMethod 6


#define WriteProcessMemoryByHostMmMapIoSpaceMethod 1
#define WriteProcessMemoryByMdlMethod 2
#define WriteProcessMemoryByMmCopyVirtualMemoryMethod 3
#define WriteProcessMemoryByHostCr3Method 4
#define WriteProcessMemoryByMmMapIoSpaceMethod 5
#define WriteProcessMemoryByInvlpgMethod 6


#define MODE_COMMONEPT_HOOK 1

#define MODE_INT3_HOOK 2

#define BREAKPOINT_FILTER_DATA_SIZE 5

#define REGISTER_RAX                            0x00000000
#define REGISTER_RCX                            0x00000001
#define REGISTER_RDX                            0x00000002
#define REGISTER_RBX                            0x00000003
#define REGISTER_RSP                            0x00000004
#define REGISTER_RBP                            0x00000005
#define REGISTER_RSI                            0x00000006
#define REGISTER_RDI                            0x00000007
#define REGISTER_R8                             0x00000008
#define REGISTER_R9                             0x00000009
#define REGISTER_R10                            0x0000000A
#define REGISTER_R11                            0x0000000B
#define REGISTER_R12                            0x0000000C
#define REGISTER_R13                            0x0000000D
#define REGISTER_R14                            0x0000000E
#define REGISTER_R15                            0x0000000F


#define FileLogPath L"\\??\\C:\\serverdbg.log"

typedef struct _MEMORY_RW_DESC
{
	UINT32      Method;
	UINT32      Pid;
	PVOID       VirtualAddress;
	PVOID       Buffer;
	size_t      BufferSize;
	size_t*		NumberOfBytes;
	BOOLEAN		Status;
}MEMORY_RW_DESC, * PMEMORY_RW_DESC;

typedef struct _HANDLE_INFORMATION
{
	CLIENT_ID ClientId;
	UINT64 Handle;
	UINT32 Access;
	UINT32 Method;
	BOOLEAN IsAdd;
	BOOLEAN IsProcessId;
	BOOLEAN Status;
}HANDLE_INFORMATION, * PHANDLE_INFORMATION;

typedef struct _BREAKPOINT_FILTER_DATA
{
	UINT64 FilterProcessId;

	UINT64 FilterDataArry[BREAKPOINT_FILTER_DATA_SIZE];
	UINT64 ReplaceDataArry[BREAKPOINT_FILTER_DATA_SIZE];
}BREAKPOINT_FILTER_DATA, * PBREAKPOINT_FILTER_DATA;


typedef struct _USER_EPT_BREAKPOINT
{
	UINT64 ProcessId;
	UINT64 VirtualAddress;
	UINT64 TargetVirtualAddressInstructionLength;
	INT32 RegisterIndex;
	BREAKPOINT_FILTER_DATA FilterData;
	UCHAR OldValue;
	BOOLEAN IsAddBreakPoint;
	BOOLEAN Status;
}USER_EPT_BREAKPOINT, * PUSER_EPT_BREAKPOINT;


typedef struct _PROTECT_INFO
{
	CLIENT_ID ClientId;
	BOOLEAN IsAdd;
	BOOLEAN Status;
}PROTECT_INFO, * PPROTECT_INFO;


// 使用方式
// int value     = GlobalConfig::Instance().getGlobalInt();
