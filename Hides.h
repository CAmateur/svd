#pragma once
#include "GlobalConfig.h"
#include "StructForUtilsAndHide.h"

enum HIDE_TYPE
{
	HIDE_NT_QUERY_INFORMATION_PROCESS,
	HIDE_NT_QUERY_SYSTEM_INFORMATION,
	HIDE_NT_QUERY_INFORMATION_THREAD,
	HIDE_NT_QUERY_INFORMATION_JOB_OBJECT,
	HIDE_NT_QUERY_OBJECT,
	HIDE_NT_QUERY_SYSTEM_TIME,
	HIDE_NT_QUERY_PERFORMANCE_COUNTER,
	HIDE_NT_CREATE_USER_PROCESS,
	HIDE_NT_CREATE_PROCESS_EX,
	HIDE_NT_CREATE_THREAD_EX,
	HIDE_NT_SET_CONTEXT_THREAD,
	HIDE_NT_GET_CONTEXT_THREAD,
	HIDE_NT_OPEN_PROCESS,
	HIDE_NT_OPEN_THREAD,
	HIDE_NT_SET_INFORMATION_THREAD,
	HIDE_NT_SYSTEM_DEBUG_CONTROL,
	HIDE_NT_GET_NEXT_PROCESS,
	HIDE_NT_YIELD_EXECUTION,
	HIDE_NT_CREATE_FILE,
	HIDE_NT_CONTINUE,
	HIDE_NT_CLOSE,
	HIDE_NT_USER_BUILD_HWND_LIST,
	HIDE_NT_USER_FIND_WINDOW_EX,
	HIDE_NT_USER_QUERY_WINDOW,
	HIDE_NT_USER_GET_FOREGROUND_WINDOW,
	HIDE_KUSER_SHARED_DATA,
	HIDE_KI_EXCEPTION_DISPATCH,
	HIDE_NT_SET_INFORMATION_PROCESS,
	HIDE_LAST
};
typedef struct _WOW64_DEBUG_CONTEXT
{
	ULONG DR0;
	ULONG DR1;
	ULONG DR2;
	ULONG DR3;
	ULONG DR6;
	ULONG DR7;
}WOW64_DEBUG_CONTEXT, * PWOW64_DEBUG_CONTEXT;

typedef struct _VMX_PTE
{
	union
	{
		struct {
			UINT64 Read : 1;
			UINT64 Write : 1;
			UINT64 Execute : 1;
			UINT64 Type : 3;
			UINT64 IgnorePat : 1;
			UINT64 Reserved1 : 1;
			UINT64 Accessed : 1;
			UINT64 Dirty : 1;
			UINT64 UserModeExecute : 1;
			UINT64 Reserved2 : 1;
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved3 : 15;
			UINT64 SuppressVe : 1;
		};
		UINT64 AsUlonglong;
	};
} VMX_PTE, * PVMX_PTE;

typedef struct _KUSD
{
	// Pointer to new KuserSharedData
	PKUSER_SHARED_DATA KuserSharedData;

	// Pte of virtual page number 7FFE0
	PVMX_PTE PteKuserSharedData;

	// Page frame number of original KuserSharedData
	ULONG OriginalKuserSharedDataPfn;

	// Begin
	ULONG64 BeginInterruptTime;
	ULONG64 BeginSystemTime;
	ULONG BeginLastSystemRITEventTickCount;
	ULONG64 BeginTickCount;
	ULONG64 BeginTimeUpdateLock;
	ULONG64 BeginBaselineSystemQpc;

	// Delta
	ULONG64 DeltaInterruptTime;
	ULONG64 DeltaSystemTime;
	ULONG DeltaLastSystemRITEventTickCount;
	ULONG64 DeltaTickCount;
	ULONG64 DeltaTimeUpdateLock;
	ULONG64 DeltaBaselineSystemQpc;
}KUSD, * PKUSD;
typedef struct _DEBUG_CONTEXT
{
	ULONG64 DR0;
	ULONG64 DR1;
	ULONG64 DR2;
	ULONG64 DR3;
	ULONG64 DR6;
	ULONG64 DR7;

	ULONG64 DebugControl;
	ULONG64 LastBranchFromRip;
	ULONG64 LastBranchToRip;
	ULONG64 LastExceptionFromRip;
	ULONG64 LastExceptionToRip;
}DEBUG_CONTEXT, * PDEBUG_CONTEXT;
typedef struct _HIDDEN_THREAD
{
	LIST_ENTRY HiddenThreadList;
	PETHREAD ThreadObject;
	WOW64_DEBUG_CONTEXT FakeWow64DebugContext;
	DEBUG_CONTEXT FakeDebugContext;
	BOOLEAN IsThreadHidden;
	BOOLEAN BreakOnTermination;
}HIDDEN_THREAD, * PHIDDEN_THREAD;
typedef struct _HIDDEN_PROCESS
{
	LIST_ENTRY HiddenProcessesList;

	HIDDEN_THREAD HiddenThreads;

	PEPROCESS DebuggerProcess;
	PEPROCESS DebuggedProcess;

	LARGE_INTEGER FakePerformanceCounter;
	LARGE_INTEGER FakeSystemTime;

	BOOLEAN HideTypes[HIDE_LAST];

	BOOLEAN ProcessPaused;

	BOOLEAN PebBeingDebuggedCleared;
	BOOLEAN HeapFlagsCleared;
	BOOLEAN PebNtGlobalFlagCleared;
	BOOLEAN KUserSharedDataCleared;
	BOOLEAN HideFromDebuggerFlagCleared;
	BOOLEAN BypassProcessFreezeFlagCleared;
	BOOLEAN ProcessHandleTracingEnabled;
	BOOLEAN ProcessBreakOnTerminationCleared;
	BOOLEAN ThreadBreakOnTerminationCleared;

	BOOLEAN ProcessDebugFlagsSaved;
	BOOLEAN ProcessHandleTracingSaved;

	BOOLEAN ValueProcessBreakOnTermination;
	BOOLEAN ValueProcessDebugFlags;
	KUSD Kusd;
}HIDDEN_PROCESS, * PHIDDEN_PROCESS;
typedef struct _HIDE_INFO
{
	ULONG Pid;
	BOOLEAN HookNtQueryInformationProcess;
	BOOLEAN HookNtQuerySystemInformation;
	BOOLEAN HookNtQueryInformationThread;
	BOOLEAN HookNtQueryInformationJobObject;
	BOOLEAN HookNtQueryObject;
	BOOLEAN HookNtQuerySystemTime;
	BOOLEAN HookNtQueryPerformanceCounter;
	BOOLEAN HookNtCreateUserProcess;
	BOOLEAN HookNtCreateProcessEx;
	BOOLEAN HookNtCreateThreadEx;
	BOOLEAN HookNtSetContextThread;
	BOOLEAN HookNtGetContextThread;
	BOOLEAN HookNtOpenProcess;
	BOOLEAN HookNtOpenThread;
	BOOLEAN HookNtSetInformationThread;
	BOOLEAN HookNtSystemDebugControl;
	BOOLEAN HookNtGetNextProcess;
	BOOLEAN HookNtYieldExecution;
	BOOLEAN HookNtCreateFile;
	BOOLEAN HookNtContinue;
	BOOLEAN HookNtClose;
	BOOLEAN HookNtUserBuildHwndList;
	BOOLEAN HookNtUserFindWindowEx;
	BOOLEAN HookNtUserQueryWindow;
	BOOLEAN HookNtUserGetForegroundWindow;
	BOOLEAN HookKuserSharedData;
	BOOLEAN HookKiDispatchException;
	BOOLEAN HookNtSetInformationProcess;
	BOOLEAN ClearPebBeingDebugged;
	BOOLEAN ClearPebNtGlobalFlag;
	BOOLEAN ClearHeapFlags;
	BOOLEAN ClearKuserSharedData;
	BOOLEAN ClearHideFromDebuggerFlag;
	BOOLEAN ClearBypassProcessFreeze;
	BOOLEAN ClearProcessBreakOnTerminationFlag;
	BOOLEAN ClearThreadBreakOnTerminationFlag;
	BOOLEAN SaveProcessDebugFlags;
	BOOLEAN SaveProcessHandleTracing;
}HIDE_INFO, * PHIDE_INFO;
typedef struct _HEAP_TUNING_PARAMETERS
{
	ULONG CommittThresholdShift;                                            //0x0
	ULONGLONG MaxPreCommittThreshold;                                       //0x8
}HEAP_TUNING_PARAMETERS, * PHEAP_TUNING_PARAMETERS;
typedef struct _HEAP_PSEUDO_TAG_ENTRY
{
	ULONG Allocs;                                                           //0x0
	ULONG Frees;                                                            //0x4
	ULONGLONG Size;                                                         //0x8
}HEAP_PSEUDO_TAG_ENTRY, * PHEAP_PSEUDO_TAG_ENTRY;
typedef struct _HEAP_COUNTERS
{
	ULONGLONG TotalMemoryReserved;                                          //0x0
	ULONGLONG TotalMemoryCommitted;                                         //0x8
	ULONGLONG TotalMemoryLargeUCR;                                          //0x10
	ULONGLONG TotalSizeInVirtualBlocks;                                     //0x18
	ULONG TotalSegments;                                                    //0x20
	ULONG TotalUCRs;                                                        //0x24
	ULONG CommittOps;                                                       //0x28
	ULONG DeCommitOps;                                                      //0x2c
	ULONG LockAcquires;                                                     //0x30
	ULONG LockCollisions;                                                   //0x34
	ULONG CommitRate;                                                       //0x38
	ULONG DecommittRate;                                                    //0x3c
	ULONG CommitFailures;                                                   //0x40
	ULONG InBlockCommitFailures;                                            //0x44
	ULONG PollIntervalCounter;                                              //0x48
	ULONG DecommitsSinceLastCheck;                                          //0x4c
	ULONG HeapPollInterval;                                                 //0x50
	ULONG AllocAndFreeOps;                                                  //0x54
	ULONG AllocationIndicesActive;                                          //0x58
	ULONG InBlockDeccommits;                                                //0x5c
	ULONGLONG InBlockDeccomitSize;                                          //0x60
	ULONGLONG HighWatermarkSize;                                            //0x68
	ULONGLONG LastPolledSize;                                               //0x70
}HEAP_COUNTERS, * PHEAP_COUNTERS;
typedef struct _HEAP_TAG_ENTRY
{
	ULONG Allocs;                                                           //0x0
	ULONG Frees;                                                            //0x4
	ULONGLONG Size;                                                         //0x8
	USHORT TagIndex;                                                        //0x10
	USHORT CreatorBackTraceIndex;                                           //0x12
	WCHAR TagName[24];                                                      //0x14
}HEAP_TAG_ENTRY, * PHEAP_TAG_ENTRY;
typedef struct _HEAP_UNPACKED_ENTRY
{
	VOID* PreviousBlockPrivateData;                                         //0x0
	union
	{
		struct
		{
			USHORT Size;                                                    //0x8
			UCHAR Flags;                                                    //0xa
			UCHAR SmallTagIndex;                                            //0xb
		}set1;
		struct
		{
			ULONG SubSegmentCode;                                           //0x8
			USHORT PreviousSize;                                            //0xc
			union
			{
				UCHAR SegmentOffset;                                        //0xe
				UCHAR LFHFlags;                                             //0xe
			};
			UCHAR UnusedBytes;                                              //0xf
		}set2;
		ULONGLONG CompactHeader;                                            //0x8
	};
}HEAP_UNPACKED_ENTRY, * PHEAP_UNPACKED_ENTRY;
typedef struct _HEAP_EXTENDED_ENTRY
{
	VOID* Reserved;                                                         //0x0
	union
	{
		struct
		{
			USHORT FunctionIndex;                                           //0x8
			USHORT ContextValue;                                            //0xa
		};
		ULONG InterceptorValue;                                             //0x8
	};
	USHORT UnusedBytesLength;                                               //0xc
	UCHAR EntryOffset;                                                      //0xe
	UCHAR ExtendedBlockSignature;                                           //0xf
}HEAP_EXTENDED_ENTRY, * PHEAP_EXTENDED_ENTRY;

typedef struct _HEAP_ENTRY
{
	union
	{
		HEAP_UNPACKED_ENTRY UnpackedEntry;                          //0x0
		struct
		{
			VOID* PreviousBlockPrivateData;                                 //0x0
			union
			{
				struct
				{
					USHORT Size;                                            //0x8
					UCHAR Flags;                                            //0xa
					UCHAR SmallTagIndex;                                    //0xb
				};
				struct
				{
					ULONG SubSegmentCode;                                   //0x8
					USHORT PreviousSize;                                    //0xc
					union
					{
						UCHAR SegmentOffset;                                //0xe
						UCHAR LFHFlags;                                     //0xe
					};
					UCHAR UnusedBytes;                                      //0xf
				};
				ULONGLONG CompactHeader;                                    //0x8
			};
		};
		HEAP_EXTENDED_ENTRY ExtendedEntry;                          //0x0
		struct
		{
			VOID* Reserved;                                                 //0x0
			union
			{
				struct
				{
					USHORT FunctionIndex;                                   //0x8
					USHORT ContextValue;                                    //0xa
				};
				ULONG InterceptorValue;                                     //0x8
			};
			USHORT UnusedBytesLength;                                       //0xc
			UCHAR EntryOffset;                                              //0xe
			UCHAR ExtendedBlockSignature;                                   //0xf
		};
		struct
		{
			VOID* ReservedForAlignment;                                     //0x0
			union
			{
				struct
				{
					ULONG Code1;                                            //0x8
					union
					{
						struct
						{
							USHORT Code2;                                   //0xc
							UCHAR Code3;                                    //0xe
							UCHAR Code4;                                    //0xf
						};
						ULONG Code234;                                      //0xc
					};
				};
				ULONGLONG AgregateCode;                                     //0x8
			};
		};
	};
}HEAP_ENTRY, * PHEAP_ENTRY;
typedef struct _HEAP_SEGMENT
{
	HEAP_ENTRY Entry;                                                       //0x0
	ULONG SegmentSignature;                                                 //0x10
	ULONG SegmentFlags;                                                     //0x14
	LIST_ENTRY SegmentListEntry;                                            //0x18
	VOID* Heap;                                                             //0x28
	VOID* BaseAddress;                                                      //0x30
	ULONG NumberOfPages;                                                    //0x38
	HEAP_ENTRY* FirstEntry;                                                 //0x40
	HEAP_ENTRY* LastValidEntry;                                             //0x48
	ULONG NumberOfUnCommittedPages;                                         //0x50
	ULONG NumberOfUnCommittedRanges;                                        //0x54
	USHORT SegmentAllocatorBackTraceIndex;                                  //0x58
	USHORT Reserved;                                                        //0x5a
	LIST_ENTRY UCRSegmentList;                                              //0x60
}HEAP_SEGMENT, * PHEAP_SEGMENT;
typedef struct _HEAP
{
	union
	{
		HEAP_SEGMENT Segment;                                       //0x0
		struct
		{
			HEAP_ENTRY Entry;                                       //0x0
			ULONG SegmentSignature;                                         //0x10 //0x8
			ULONG SegmentFlags;                                             //0x14 //0xC
			LIST_ENTRY SegmentListEntry;                                    //0x18  //0x10
			VOID* Heap;                                                     //0x28  //0x18
			VOID* BaseAddress;                                              //0x30  //0x1c
			ULONG NumberOfPages;                                            //0x38  //0x20
			HEAP_ENTRY* FirstEntry;                                         //0x40  //0x24
			HEAP_ENTRY* LastValidEntry;                                     //0x48  //0x28
			ULONG NumberOfUnCommittedPages;                                 //0x50  //0x2c
			ULONG NumberOfUnCommittedRanges;                                //0x54
			USHORT SegmentAllocatorBackTraceIndex;                          //0x58
			USHORT Reserved;                                                //0x5a
			LIST_ENTRY UCRSegmentList;                                      //0x60
		};
	};
	ULONG Flags;                                                            //0x70
	ULONG ForceFlags;                                                       //0x74
	ULONG CompatibilityFlags;                                               //0x78
	ULONG EncodeFlagMask;                                                   //0x7c
	HEAP_ENTRY Encoding;                                                    //0x80
	ULONG Interceptor;                                                      //0x90
	ULONG VirtualMemoryThreshold;                                           //0x94
	ULONG Signature;                                                        //0x98
	ULONGLONG SegmentReserve;                                               //0xa0
	ULONGLONG SegmentCommit;                                                //0xa8
	ULONGLONG DeCommitFreeBlockThreshold;                                   //0xb0
	ULONGLONG DeCommitTotalFreeThreshold;                                   //0xb8
	ULONGLONG TotalFreeSize;                                                //0xc0
	ULONGLONG MaximumAllocationSize;                                        //0xc8
	USHORT ProcessHeapsListIndex;                                           //0xd0
	USHORT HeaderValidateLength;                                            //0xd2
	VOID* HeaderValidateCopy;                                               //0xd8
	USHORT NextAvailableTagIndex;                                           //0xe0
	USHORT MaximumTagIndex;                                                 //0xe2
	PHEAP_TAG_ENTRY TagEntries;                                     //0xe8
	LIST_ENTRY UCRList;                                             //0xf0
	ULONGLONG AlignRound;                                                   //0x100
	ULONGLONG AlignMask;                                                    //0x108
	LIST_ENTRY VirtualAllocdBlocks;                                 //0x110
	LIST_ENTRY SegmentList;                                         //0x120
	USHORT AllocatorBackTraceIndex;                                         //0x130
	ULONG NonDedicatedListLength;                                           //0x134
	VOID* BlocksIndex;                                                      //0x138
	VOID* UCRIndex;                                                         //0x140
	PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;                        //0x148
	LIST_ENTRY FreeLists;                                           //0x150
	PVOID LockVariable;                                        //0x160
	LONG(*CommitRoutine)(VOID* arg1, VOID** arg2, ULONGLONG* arg3);        //0x168
	RTL_RUN_ONCE StackTraceInitVar;                                  //0x170
	VOID* CommitLimitData;                     //0x178
	VOID* FrontEndHeap;                                                     //0x198
	USHORT FrontHeapLockCount;                                              //0x1a0
	UCHAR FrontEndHeapType;                                                 //0x1a2
	UCHAR RequestedFrontEndHeapType;                                        //0x1a3
	WCHAR* FrontEndHeapUsageData;                                           //0x1a8
	USHORT FrontEndHeapMaximumIndex;                                        //0x1b0
	volatile UCHAR FrontEndHeapStatusBitmap[129];                           //0x1b2
	HEAP_COUNTERS Counters;                                         //0x238
	HEAP_TUNING_PARAMETERS TuningParameters;                        //0x2b0
}HEAP, * PHEAP;

typedef enum _THREAD_STATE_ROUTINE
{
	THREADSTATE_GETTHREADINFO,
	THREADSTATE_ACTIVEWINDOW
} THREAD_STATE_ROUTINE;
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer;
}SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
	ULONG Length;
	ULONG CodeIntegrityOptions;
}SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
	BOOLEAN DebuggerAllowed;
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerPresent;
}SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef struct _WOW64_FLOATING_SAVE_AREA
{
	ULONG ControlWord;
	ULONG StatusWord;
	ULONG TagWord;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	UCHAR RegisterArea[80];
	ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, * PWOW64_FLOATING_SAVE_AREA;
typedef struct _WOW64_CONTEXT
{
	ULONG ContextFlags;

	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;

	WOW64_FLOATING_SAVE_AREA FloatSave;

	ULONG SegGs;
	ULONG SegFs;
	ULONG SegEs;
	ULONG SegDs;

	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;

	ULONG Ebp;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG Esp;
	ULONG SegSs;

	UCHAR ExtendedRegisters[512];

} WOW64_CONTEXT, * PWOW64_CONTEXT;
//typedef struct _SYSTEM_PROCESS_INFO
//{
//	ULONG NextEntryOffset;
//	ULONG NumberOfThreads;
//	LARGE_INTEGER WorkingSetPrivateSize;
//	ULONG HardFaultCount;
//	ULONG NumberOfThreadsHighWatermark;
//	ULONGLONG CycleTime;
//	LARGE_INTEGER CreateTime;
//	LARGE_INTEGER UserTime;
//	LARGE_INTEGER KernelTime;
//	UNICODE_STRING ImageName;
//	ULONG BasePriority;
//	HANDLE ProcessId;
//	HANDLE InheritedFromProcessId;
//	ULONG HandleCount;
//	ULONG SessionId;
//	ULONG_PTR UniqueProcessKey;
//	ULONG_PTR PeakVirtualSize;
//	ULONG_PTR VirtualSize;
//	ULONG PageFaultCount;
//	ULONG_PTR PeakWorkingSetSize;
//	ULONG_PTR WorkingSetSize;
//	ULONG_PTR QuotaPeakPagedPoolUsage;
//	ULONG_PTR QuotaPagedPoolUsage;
//	ULONG_PTR QuotaPeakNonPagedPoolUsage;
//	ULONG_PTR QuotaNonPagedPoolUsage;
//	ULONG_PTR PagefileUsage;
//	ULONG_PTR PeakPagefileUsage;
//	ULONG_PTR PrivatePageCount;
//	LARGE_INTEGER ReadOperationCount;
//	LARGE_INTEGER WriteOperationCount;
//	LARGE_INTEGER OtherOperationCount;
//	LARGE_INTEGER ReadTransferCount;
//	LARGE_INTEGER WriteTransferCount;
//	LARGE_INTEGER OtherTransferCount;
//	SYSTEM_THREAD_INFORMATION Threads[1];
//}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG Reserved[40];
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
	ULONG                   NumberOfObjectsTypes;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;
enum SYSDBG_COMMAND
{
	SysDbgGetTriageDump = 29
};

typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
}OBJECT_HANDLE_ATTRIBUTE_INFORMATION, * POBJECT_HANDLE_ATTRIBUTE_INFORMATION;
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;                                         //0x0
	VOID* Handle;                                                           //0x10
}CURDIR, * PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	STRING DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	CURDIR CurrentDirectory;                                        //0x38
	UNICODE_STRING DllPath;                                         //0x50
	UNICODE_STRING ImagePathName;                                   //0x60
	UNICODE_STRING CommandLine;                                     //0x70
	VOID* Environment;                                                      //0x80
	ULONG StartingX;                                                        //0x88
	ULONG StartingY;                                                        //0x8c
	ULONG CountX;                                                           //0x90
	ULONG CountY;                                                           //0x94
	ULONG CountCharsX;                                                      //0x98
	ULONG CountCharsY;                                                      //0x9c
	ULONG FillAttribute;                                                    //0xa0
	ULONG WindowFlags;                                                      //0xa4
	ULONG ShowWindowFlags;                                                  //0xa8
	UNICODE_STRING WindowTitle;                                     //0xb0
	UNICODE_STRING DesktopInfo;                                     //0xc0
	UNICODE_STRING ShellInfo;                                       //0xd0
	UNICODE_STRING RuntimeData;                                     //0xe0
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
	ULONGLONG EnvironmentSize;                                              //0x3f0
	ULONGLONG EnvironmentVersion;                                           //0x3f8
	VOID* PackageDependencyData;                                            //0x400
	ULONG ProcessGroupId;                                                   //0x408
	ULONG LoaderThreads;                                                    //0x40c
	UNICODE_STRING RedirectionDllName;                              //0x410
	UNICODE_STRING HeapPartitionName;                               //0x420
	ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
enum JOBOBJECTINFOCLASS
{
	JobObjectBasicAccountingInformation = 1,
	JobObjectBasicLimitInformation = 2,
	JobObjectBasicProcessIdList = 3,
	JobObjectBasicUIRestrictions = 4,
	JobObjectSecurityLimitInformation = 5,
	JobObjectEndOfJobTimeInformation = 6,
	JobObjectAssociateCompletionPortInformation = 7,
	JobObjectBasicAndIoAccountingInformation = 8,
	JobObjectExtendedLimitInformation = 9,
	JobObjectJobSetInformation = 10,
	JobObjectGroupInformation = 11,
	JobObjectNotificationLimitInformation = 12,
	JobObjectLimitViolationInformation = 13,
	JobObjectGroupInformationEx = 14,
	JobObjectCpuRateControlInformation = 15,
	JobObjectCompletionFilter = 16,
	JobObjectCompletionCounter = 17,
	JobObjectFreezeInformation = 18,
	JobObjectExtendedAccountingInformation = 19,
	JobObjectWakeInformation = 20,
	JobObjectBackgroundInformation = 21,
	JobObjectSchedulingRankBiasInformation = 22,
	JobObjectTimerVirtualizationInformation = 23,
	JobObjectCycleTimeNotification = 24,
	JobObjectClearEvent = 25,
	JobObjectReserved1Information = 18,
	JobObjectReserved2Information = 19,
	JobObjectReserved3Information = 20,
	JobObjectReserved4Information = 21,
	JobObjectReserved5Information = 22,
	JobObjectReserved6Information = 23,
	JobObjectReserved7Information = 24,
	JobObjectReserved8Information = 25,
	MaxJobObjectInfoClass = 26
};
typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST {
	ULONG NumberOfAssignedProcesses;
	ULONG NumberOfProcessIdsInList;
	ULONG_PTR ProcessIdList[1];
} JOBOBJECT_BASIC_PROCESS_ID_LIST, * PJOBOBJECT_BASIC_PROCESS_ID_LIST;



#define KUSER_SHARED_DATA_USERMODE 0x7FFE0000
#define KUSER_SHARED_DATA_KERNELMODE 0xFFFFF78000000000
#define HEAP_SKIP_VALIDATION_CHECKS 0x10000000  
#define HEAP_VALIDATE_PARAMETERS_ENABLED  0x40000000


#define ObjectTypesInformation 3
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x4
#define PROCESS_DEBUG_INHERIT 0x00000001 // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process
#define PROCESS_QUERY_INFORMATION   0x0400
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        (*ReturnLength) = TempReturnLength



BOOLEAN HiderInitialize();
VOID HiderUninitialize();
VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
BOOLEAN CreateEntry(PEPROCESS DebuggerProcess, PEPROCESS DebuggedProcess);
BOOLEAN RemoveEntry(PEPROCESS TargetProcess);
BOOLEAN Hide(PHIDE_INFO HideInfo);
BOOLEAN IsHidden(PEPROCESS TargetProcess, INT32 HideType);
UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess);
BOOLEAN IsProcessNameBad(PUNICODE_STRING ProcessName);
PHIDDEN_THREAD AppendThreadList(PEPROCESS TargetProcess, PETHREAD ThreadObject);
BOOLEAN IsProcessWindowBad(PUNICODE_STRING WindowName);
BOOLEAN IsProcessWindowClassBad(PUNICODE_STRING WindowClassName);
BOOLEAN IsWindowBad(HANDLE hWnd);
VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo);
VOID FilterHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX HandleInfoEx);
VOID FilterHandles(PSYSTEM_HANDLE_INFORMATION HandleInfo);
PHIDDEN_PROCESS QueryHiddenProcess(PEPROCESS TargetProcess);
BOOLEAN IsSetThreadContextRestricted(PEPROCESS TargetProcess);
BOOLEAN IsPicoContextNull(PETHREAD TargetThread);
BOOLEAN IsDriverHandleHidden(PUNICODE_STRING SymLink);
BOOLEAN IsDebuggerProcess(PEPROCESS TargetProcess);
PEPROCESS GetProcessByName(CONST unsigned short* ProcessName);

EXTERN_C PVOID NTAPI PsGetCurrentProcessWow64Process();
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process
(
	IN PEPROCESS Process
);

