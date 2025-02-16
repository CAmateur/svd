#pragma once
#include"GlobalConfig.h"
#include "StructForEptHook.h"
#include "StructForUtils.h"
#include "StructForUtilsAndHide.h"
#define WINDOWS_7 7600
#define WINDOWS_7_SP1 7601
#define WINDOWS_8 9200
#define WINDOWS_8_1 9600
#define WINDOWS_10_VERSION_THRESHOLD1 10240
#define WINDOWS_10_VERSION_THRESHOLD2 10586
#define WINDOWS_10_VERSION_REDSTONE1 14393
#define WINDOWS_10_VERSION_REDSTONE2 15063
#define WINDOWS_10_VERSION_REDSTONE3 16299
#define WINDOWS_10_VERSION_REDSTONE4 17134
#define WINDOWS_10_VERSION_REDSTONE5 17763
#define WINDOWS_10_VERSION_19H1 18362
#define WINDOWS_10_VERSION_19H2 18363
#define WINDOWS_10_VERSION_20H1 19041
#define WINDOWS_10_VERSION_20H2 19042
#define WINDOWS_10_VERSION_21H1 19043
#define WINDOWS_10_VERSION_21H2 19044
#define WINDOWS_11 22621


#define DELAY_ONE_MICROSECOND         ( -10 )
#define DELAY_ONE_MILLISECOND        ( DELAY_ONE_MICROSECOND * 1000 )


//这个size必须大于等于4
#define RELATIVE_ADDRESS(address, size) ((UINT64)((UINT8*)(address) + *(INT32*)((UINT8*)(address) + ((size) - (INT32)sizeof(INT32))) + (size)))
//这个size必须大于等于1
#define RELATIVE_ADDRESS2(address, size) ((UINT64)((UINT8*)(address) + *(UINT8*)((UINT8*)(address) + ((size)- (UINT8)sizeof(UINT8))) + (size)))

BOOLEAN FindCodeCaves();

int MathPower(int Base, int Exponent);

PEPROCESS GetCsrssProcess();
PVOID GetUserModeModule(PEPROCESS TargetProcess, CONST WCHAR* ModuleName, BOOLEAN IsWow64);
PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName);
BOOLEAN GetProcessInfo(CONST CHAR* Name, UINT64* ImageSize, PVOID* ImageBase);
PEPROCESS PidToProcess(HANDLE Pid);
VOID ShvOsDebugPrint(_In_ PCCH Format,...);
PEPROCESS GetProcessByName(CONST unsigned short* ProcessName);


UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess);
NTSTATUS GetProcessModuleFunc(HANDLE Pid, PVOID Module, CHAR* Name, PVOID POutBuffer);
NTSTATUS GetProcessModule(HANDLE Pid, CHAR* Name, PVOID POutBuffer);
TIME_FIELDS GetTime();
VOID FileLog(CHAR* LogText);

BOOLEAN RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive);

VOID KeSleep(IN LONG lSeccond);
NTSTATUS CreateThread(PVOID TargetEP);

PEPROCESS GetProcessById(HANDLE ProcessId);
PETHREAD GetThreadByTid(HANDLE ThreadId);
UINT64 GetCr3(PEPROCESS PProcess);

PVOID GetProcAddress(WCHAR* FuncName);


NTSTATUS ReadProcessMemoryByMmCopyVirtualMemory(UINT32 pid, PVOID virtualAddress, PVOID destinationBuffer, size_t bufferSize, size_t* numberOfBytes);
NTSTATUS WriteProcessMemoryByMdl(UINT32 pid, PVOID virtualAddress, PVOID SourceBuffer, size_t bufferSize, size_t* numberOfBytes);

NTSTATUS ReadProcessMemoryByVtHostMmCopyMemory(UINT32 pid, PVOID virtualAddress, PVOID destinationBuffer, size_t bufferSize, size_t* numberOfBytes);
NTSTATUS WriteProcessMemoryByVtHostMmMapIoSpace(UINT32 pid, PVOID virtualAddress, PVOID sourceBuffer, size_t bufferSize, size_t* numberOfBytes);

NTSTATUS ReadProcessMemoryByVtCr3(UINT32 pid, PVOID virtualAddress, PVOID destinationBuffer, size_t bufferSize, size_t* numberOfBytes);
NTSTATUS WriteProcessMemoryByVtCr3(UINT32 pid, PVOID virtualAddress, PVOID SourceBuffer, size_t bufferSize, size_t* numberOfBytes);