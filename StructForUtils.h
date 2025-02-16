#pragma once
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // 10, not implemented
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q
	SystemVdmBopInformation, // 20, not implemented
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented
	SystemMirrorMemoryInformation, // 30, s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege)
	SystemPerformanceTraceInformation, // s
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // 40, s (requires SeDebugPrivilege)
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented
	SystemRangeStartInformation, // 50, q
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q
	SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q
	SystemComPlusPackage, // q; s
	SystemNumaAvailableMemory, // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation, // q
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s
	SystemObjectSecurityMode, // 70, q
	SystemWatchdogTimerHandler, // s (kernel-mode only)
	SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation, // not implemented
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // 80, q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege)
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // 90, q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION
	SystemHypervisorInformation, // q; s (kernel-mode only)
	SystemVerifierInformationEx, // q; s
	SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation, // not implemented
	SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // 100, q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
	SystemNumaProximityNodeInformation, // q
	SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s
	SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s // SmQueryStoreInformation
	SystemRegistryAppendString, // 110, s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation, // not implemented
	SystemSpare1, // not implemented
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // 120, q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes)
	SystemNodeDistanceInformation, // q
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // since WIN8
	SystemBootGraphicsInformation,
	SystemScrubPhysicalMemoryInformation,
	SystemBadPageInformation,
	SystemProcessorProfileControlArea,
	SystemCombinePhysicalMemoryInformation, // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation,
	SystemPlatformBinaryInformation,
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation,
	SystemDeviceDataInformation,
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation,
	SystemMemoryChannelInformation,
	SystemBootLogoInformation, // 140
	SystemProcessorPerformanceInformationEx, // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation,
	SystemPageFileInformationEx,
	SystemSecureBootInformation,
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation,
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx,
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation,
	SystemElamCertificateInformation,
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation,
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	MaxSystemInfoClass,
	SystemKernelDebuggerFlags = 163
} SYSTEM_INFORMATION_CLASS;




typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;
typedef struct _SYSTEM_MODULE {
	PVOID 	Reserved1;
	PVOID 	Reserved2;
	PVOID 	ImageBaseAddress;
	ULONG 	ImageSize;
	ULONG 	Flags;
	unsigned short 	Id;
	unsigned short 	Rank;
	unsigned short 	Unknown;
	unsigned short 	NameOffset;
	unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                       ModulesCount;
	SYSTEM_MODULE_ENTRY         Modules[1];
	ULONG                       Count;
	SYSTEM_MODULE 	            Sys_Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	ULONG Mutant;                                                           //0x4
	ULONG ImageBaseAddress;                                                 //0x8
	ULONG Ldr;                                                              //0xc
	ULONG ProcessParameters;                                                //0x10
	ULONG SubSystemData;                                                    //0x14
	ULONG ProcessHeap;                                                      //0x18
	ULONG FastPebLock;                                                      //0x1c
	ULONG AtlThunkSListPtr;                                                 //0x20
	ULONG IFEOKey;                                                          //0x24
	union
	{
		ULONG CrossProcessFlags;                                            //0x28
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x28
			ULONG ProcessInitializing : 1;                                    //0x28
			ULONG ProcessUsingVEH : 1;                                        //0x28
			ULONG ProcessUsingVCH : 1;                                        //0x28
			ULONG ProcessUsingFTH : 1;                                        //0x28
			ULONG ProcessPreviouslyThrottled : 1;                             //0x28
			ULONG ProcessCurrentlyThrottled : 1;                              //0x28
			ULONG ProcessImagesHotPatched : 1;                                //0x28
			ULONG ReservedBits0 : 24;                                         //0x28
		};
	};
	union
	{
		ULONG KernelCallbackTable;                                          //0x2c
		ULONG UserSharedInfoPtr;                                            //0x2c
	};
	ULONG SystemReserved;                                                   //0x30
	ULONG AtlThunkSListPtr32;                                               //0x34
	ULONG ApiSetMap;                                                        //0x38
	ULONG TlsExpansionCounter;                                              //0x3c
	ULONG TlsBitmap;                                                        //0x40
	ULONG TlsBitmapBits[2];                                                 //0x44
	ULONG ReadOnlySharedMemoryBase;                                         //0x4c
	ULONG SharedData;                                                       //0x50
	ULONG ReadOnlyStaticServerData;                                         //0x54
	ULONG AnsiCodePageData;                                                 //0x58
	ULONG OemCodePageData;                                                  //0x5c
	ULONG UnicodeCaseTableData;                                             //0x60
	ULONG NumberOfProcessors;                                               //0x64
	ULONG NtGlobalFlag;                                                     //0x68
	LARGE_INTEGER CriticalSectionTimeout;                            //0x70
	ULONG HeapSegmentReserve;                                               //0x78
	ULONG HeapSegmentCommit;                                                //0x7c
	ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
	ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
	ULONG NumberOfHeaps;                                                    //0x88
	ULONG MaximumNumberOfHeaps;                                             //0x8c
	ULONG ProcessHeaps;                                                     //0x90
	ULONG GdiSharedHandleTable;                                             //0x94
	ULONG ProcessStarterHelper;                                             //0x98
	ULONG GdiDCAttributeList;                                               //0x9c
	ULONG LoaderLock;                                                       //0xa0
	ULONG OSMajorVersion;                                                   //0xa4
	ULONG OSMinorVersion;                                                   //0xa8
	USHORT OSBuildNumber;                                                   //0xac
	USHORT OSCSDVersion;                                                    //0xae
	ULONG OSPlatformId;                                                     //0xb0
	ULONG ImageSubsystem;                                                   //0xb4
	ULONG ImageSubsystemMajorVersion;                                       //0xb8
	ULONG ImageSubsystemMinorVersion;                                       //0xbc
	ULONG ActiveProcessAffinityMask;                                        //0xc0
	ULONG GdiHandleBuffer[34];                                              //0xc4
	ULONG PostProcessInitRoutine;                                           //0x14c
	ULONG TlsExpansionBitmap;                                               //0x150
	ULONG TlsExpansionBitmapBits[32];                                       //0x154
	ULONG SessionId;                                                        //0x1d4
	ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
	ULONG pShimData;                                                        //0x1e8
	ULONG AppCompatInfo;                                                    //0x1ec
	STRING32 CSDVersion;                                            //0x1f0
	ULONG ActivationContextData;                                            //0x1f8
	ULONG ProcessAssemblyStorageMap;                                        //0x1fc
	ULONG SystemDefaultActivationContextData;                               //0x200
	ULONG SystemAssemblyStorageMap;                                         //0x204
	ULONG MinimumStackCommit;                                               //0x208
	ULONG SparePointers[4];                                                 //0x20c
	ULONG SpareUlongs[5];                                                   //0x21c
	ULONG WerRegistrationData;                                              //0x230
	ULONG WerShipAssertPtr;                                                 //0x234
	ULONG pUnused;                                                          //0x238
	ULONG pImageHeaderHash;                                                 //0x23c
	union
	{
		ULONG TracingFlags;                                                 //0x240
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x240
			ULONG CritSecTracingEnabled : 1;                                  //0x240
			ULONG LibLoaderTracingEnabled : 1;                                //0x240
			ULONG SpareTracingBits : 29;                                      //0x240
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
	ULONG TppWorkerpListLock;                                               //0x250
	LIST_ENTRY32 TppWorkerpList;                                     //0x254
	ULONG WaitOnAddressHashTable[128];                                      //0x25c
	ULONG TelemetryCoverageHeader;                                          //0x45c
	ULONG CloudFileFlags;                                                   //0x460
	ULONG CloudFileDiagFlags;                                               //0x464
	CHAR PlaceholderCompatibilityMode;                                      //0x468
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
	ULONG LeapSecondData;                                                   //0x470
	union
	{
		ULONG LeapSecondFlags;                                              //0x474
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x474
			ULONG Reserved : 31;                                              //0x474
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x478
}PEB32, * PPEB32;
typedef struct _PEB_LDR_DATA32
{
	ULONG 	Length;
	BOOLEAN 	Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 	InLoadOrderModuleList;
	LIST_ENTRY32 	InMemoryOrderModuleList;
	LIST_ENTRY32 	InInitializationOrderModuleList;
	BOOLEAN 	ShutdownInProgress;
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#ifndef _LDR_DATA_TABLE_ENTRY_
#define _LDR_DATA_TABLE_ENTRY_
typedef struct _LDR_DATA_TABLE_ENTRY                         // 24 elements, 0xE0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     VOID* DllBase;
	/*0x038*/     VOID* EntryPoint;
	/*0x040*/     UINT32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x068*/     UINT32      Flags;
	/*0x06C*/     UINT16       LoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	union                                                    // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x070*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x10 bytes (sizeof)
		struct                                               // 2 elements, 0x10 bytes (sizeof)
		{
			/*0x070*/             VOID* SectionPointer;
			/*0x078*/             UINT32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union                                                    // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x080*/         UINT32      TimeDateStamp;
		/*0x080*/         VOID* LoadedImports;
	};
	/*0x088*/     UINT64 EntryPointActivationContext;
	/*0x090*/     VOID* PatchInformation;
	/*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
	/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
	/*0x0C8*/     VOID* ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#endif _LDR_DATA_TABLE_ENTRY_



#ifndef _PEB_LDR_DATA_
#define _PEB_LDR_DATA_
typedef struct _PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof)
{
	/*0x000*/     UINT32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID* SsHandle;
	/*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof)
	/*0x040*/     VOID* EntryInProgress;
	/*0x048*/     UINT8        ShutdownInProgress;
	/*0x049*/     UINT8        _PADDING1_[0x7];
	/*0x050*/     VOID* ShutdownThreadId;
}PEB_LDR_DATA, * PPEB_LDR_DATA;
#endif // !_PEB_LDR_DATA_


#ifndef _PEB_
#define _PEB_
typedef struct _PEB
{
	/* 0x0000 */ unsigned char InheritedAddressSpace;
	/* 0x0001 */ unsigned char ReadImageFileExecOptions;
	/* 0x0002 */ unsigned char BeingDebugged;
	union
	{
		/* 0x0003 */ unsigned char BitField;
		struct /* bitfield */
		{
			/* 0x0003 */ unsigned char ImageUsesLargePages : 1; /* bit position: 0 */
			/* 0x0003 */ unsigned char IsProtectedProcess : 1; /* bit position: 1 */
			/* 0x0003 */ unsigned char IsImageDynamicallyRelocated : 1; /* bit position: 2 */
			/* 0x0003 */ unsigned char SkipPatchingUser32Forwarders : 1; /* bit position: 3 */
			/* 0x0003 */ unsigned char IsPackagedProcess : 1; /* bit position: 4 */
			/* 0x0003 */ unsigned char IsAppContainer : 1; /* bit position: 5 */
			/* 0x0003 */ unsigned char IsProtectedProcessLight : 1; /* bit position: 6 */
			/* 0x0003 */ unsigned char IsLongPathAwareProcess : 1; /* bit position: 7 */
		}; /* bitfield */
	}; /* size: 0x0001 */
	/* 0x0004 */ unsigned char Padding0[4];
	/* 0x0008 */ void* Mutant;
	/* 0x0010 */ void* ImageBaseAddress;
	/* 0x0018 */ struct _PEB_LDR_DATA* Ldr;
	/* 0x0020 */ struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	/* 0x0028 */ void* SubSystemData;
	/* 0x0030 */ void* ProcessHeap;
	/* 0x0038 */ struct _RTL_CRITICAL_SECTION* FastPebLock;
	/* 0x0040 */ union _SLIST_HEADER* volatile AtlThunkSListPtr;
	/* 0x0048 */ void* IFEOKey;
	union
	{
		/* 0x0050 */ unsigned long CrossProcessFlags;
		struct /* bitfield */
		{
			/* 0x0050 */ unsigned long ProcessInJob : 1; /* bit position: 0 */
			/* 0x0050 */ unsigned long ProcessInitializing : 1; /* bit position: 1 */
			/* 0x0050 */ unsigned long ProcessUsingVEH : 1; /* bit position: 2 */
			/* 0x0050 */ unsigned long ProcessUsingVCH : 1; /* bit position: 3 */
			/* 0x0050 */ unsigned long ProcessUsingFTH : 1; /* bit position: 4 */
			/* 0x0050 */ unsigned long ProcessPreviouslyThrottled : 1; /* bit position: 5 */
			/* 0x0050 */ unsigned long ProcessCurrentlyThrottled : 1; /* bit position: 6 */
			/* 0x0050 */ unsigned long ProcessImagesHotPatched : 1; /* bit position: 7 */
			/* 0x0050 */ unsigned long ReservedBits0 : 24; /* bit position: 8 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x0054 */ unsigned char Padding1[4];
	union
	{
		/* 0x0058 */ void* KernelCallbackTable;
		/* 0x0058 */ void* UserSharedInfoPtr;
	}; /* size: 0x0008 */
	/* 0x0060 */ unsigned long SystemReserved;
	/* 0x0064 */ unsigned long AtlThunkSListPtr32;
	/* 0x0068 */ void* ApiSetMap;
	/* 0x0070 */ unsigned long TlsExpansionCounter;
	/* 0x0074 */ unsigned char Padding2[4];
	/* 0x0078 */ void* TlsBitmap;
	/* 0x0080 */ unsigned long TlsBitmapBits[2];
	/* 0x0088 */ void* ReadOnlySharedMemoryBase;
	/* 0x0090 */ void* SharedData;
	/* 0x0098 */ void** ReadOnlyStaticServerData;
	/* 0x00a0 */ void* AnsiCodePageData;
	/* 0x00a8 */ void* OemCodePageData;
	/* 0x00b0 */ void* UnicodeCaseTableData;
	/* 0x00b8 */ unsigned long NumberOfProcessors;
	/* 0x00bc */ unsigned long NtGlobalFlag;
	/* 0x00c0 */ union _LARGE_INTEGER CriticalSectionTimeout;
	/* 0x00c8 */ UINT64 HeapSegmentReserve;
	/* 0x00d0 */ UINT64 HeapSegmentCommit;
	/* 0x00d8 */ UINT64 HeapDeCommitTotalFreeThreshold;
	/* 0x00e0 */ UINT64 HeapDeCommitFreeBlockThreshold;
	/* 0x00e8 */ unsigned long NumberOfHeaps;
	/* 0x00ec */ unsigned long MaximumNumberOfHeaps;
	/* 0x00f0 */ void** ProcessHeaps;
	/* 0x00f8 */ void* GdiSharedHandleTable;
	/* 0x0100 */ void* ProcessStarterHelper;
	/* 0x0108 */ unsigned long GdiDCAttributeList;
	/* 0x010c */ unsigned char Padding3[4];
	/* 0x0110 */ struct _RTL_CRITICAL_SECTION* LoaderLock;
	/* 0x0118 */ unsigned long OSMajorVersion;
	/* 0x011c */ unsigned long OSMinorVersion;
	/* 0x0120 */ unsigned short OSBuildNumber;
	/* 0x0122 */ unsigned short OSCSDVersion;
	/* 0x0124 */ unsigned long OSPlatformId;
	/* 0x0128 */ unsigned long ImageSubsystem;
	/* 0x012c */ unsigned long ImageSubsystemMajorVersion;
	/* 0x0130 */ unsigned long ImageSubsystemMinorVersion;
	/* 0x0134 */ unsigned char Padding4[4];
	/* 0x0138 */ UINT64 ActiveProcessAffinityMask;
	/* 0x0140 */ unsigned long GdiHandleBuffer[60];
	/* 0x0230 */ void* PostProcessInitRoutine /* function */;
	/* 0x0238 */ void* TlsExpansionBitmap;
	/* 0x0240 */ unsigned long TlsExpansionBitmapBits[32];
	/* 0x02c0 */ unsigned long SessionId;
	/* 0x02c4 */ unsigned char Padding5[4];
	/* 0x02c8 */ union _ULARGE_INTEGER AppCompatFlags;
	/* 0x02d0 */ union _ULARGE_INTEGER AppCompatFlagsUser;
	/* 0x02d8 */ void* pShimData;
	/* 0x02e0 */ void* AppCompatInfo;
	/* 0x02e8 */ struct _UNICODE_STRING CSDVersion;
	/* 0x02f8 */ const struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
	/* 0x0300 */ struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	/* 0x0308 */ const struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	/* 0x0310 */ struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	/* 0x0318 */ UINT64 MinimumStackCommit;
	/* 0x0320 */ void* SparePointers[4];
	/* 0x0340 */ unsigned long SpareUlongs[5];
	/* 0x0354 */ long Padding_1;
	/* 0x0358 */ void* WerRegistrationData;
	/* 0x0360 */ void* WerShipAssertPtr;
	/* 0x0368 */ void* pUnused;
	/* 0x0370 */ void* pImageHeaderHash;
	union
	{
		/* 0x0378 */ unsigned long TracingFlags;
		struct /* bitfield */
		{
			/* 0x0378 */ unsigned long HeapTracingEnabled : 1; /* bit position: 0 */
			/* 0x0378 */ unsigned long CritSecTracingEnabled : 1; /* bit position: 1 */
			/* 0x0378 */ unsigned long LibLoaderTracingEnabled : 1; /* bit position: 2 */
			/* 0x0378 */ unsigned long SpareTracingBits : 29; /* bit position: 3 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x037c */ unsigned char Padding6[4];
	/* 0x0380 */ UINT64 CsrServerReadOnlySharedMemoryBase;
	/* 0x0388 */ UINT64 TppWorkerpListLock;
	/* 0x0390 */ struct _LIST_ENTRY TppWorkerpList;
	/* 0x03a0 */ void* WaitOnAddressHashTable[128];
	/* 0x07a0 */ void* TelemetryCoverageHeader;
	/* 0x07a8 */ unsigned long CloudFileFlags;
	/* 0x07ac */ unsigned long CloudFileDiagFlags;
	/* 0x07b0 */ char PlaceholderCompatibilityMode;
	/* 0x07b1 */ char PlaceholderCompatibilityModeReserved[7];
	/* 0x07b8 */ struct _LEAP_SECOND_DATA* LeapSecondData;
	union
	{
		/* 0x07c0 */ unsigned long LeapSecondFlags;
		struct /* bitfield */
		{
			/* 0x07c0 */ unsigned long SixtySecondEnabled : 1; /* bit position: 0 */
			/* 0x07c0 */ unsigned long Reserved : 31; /* bit position: 1 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x07c4 */ unsigned long NtGlobalFlag2;
} PEB, * PPEB; /* size: 0x07c8 */
/*
+0x000 InheritedAddressSpace : UChar
+ 0x001 ReadImageFileExecOptions : UChar
+ 0x002 BeingDebugged : UChar
+ 0x003 BitField : UChar
+ 0x003 ImageUsesLargePages : Pos 0, 1 Bit
+ 0x003 IsProtectedProcess : Pos 1, 1 Bit
+ 0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
+ 0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
+ 0x003 IsPackagedProcess : Pos 4, 1 Bit
+ 0x003 IsAppContainer : Pos 5, 1 Bit
+ 0x003 IsProtectedProcessLight : Pos 6, 1 Bit
+ 0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
+ 0x004 Padding0 : [4] UChar
+ 0x008 Mutant : Ptr64 Void
+ 0x010 ImageBaseAddress : Ptr64 Void
+ 0x018 Ldr : Ptr64 _PEB_LDR_DATA
+ 0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
+ 0x028 SubSystemData : Ptr64 Void
+ 0x030 ProcessHeap : Ptr64 Void
+ 0x038 FastPebLock : Ptr64 _RTL_CRITICAL_SECTION
+ 0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
+ 0x048 IFEOKey : Ptr64 Void
+ 0x050 CrossProcessFlags : Uint4B
+ 0x050 ProcessInJob : Pos 0, 1 Bit
+ 0x050 ProcessInitializing : Pos 1, 1 Bit
+ 0x050 ProcessUsingVEH : Pos 2, 1 Bit
+ 0x050 ProcessUsingVCH : Pos 3, 1 Bit
+ 0x050 ProcessUsingFTH : Pos 4, 1 Bit
+ 0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
+ 0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
+ 0x050 ProcessImagesHotPatched : Pos 7, 1 Bit
+ 0x050 ReservedBits0 : Pos 8, 24 Bits
+ 0x054 Padding1 : [4] UChar
+ 0x058 KernelCallbackTable : Ptr64 Void
+ 0x058 UserSharedInfoPtr : Ptr64 Void
+ 0x060 SystemReserved : Uint4B
+ 0x064 AtlThunkSListPtr32 : Uint4B
+ 0x068 ApiSetMap : Ptr64 Void
+ 0x070 TlsExpansionCounter : Uint4B
+ 0x074 Padding2 : [4] UChar
+ 0x078 TlsBitmap : Ptr64 Void
+ 0x080 TlsBitmapBits : [2] Uint4B
+ 0x088 ReadOnlySharedMemoryBase : Ptr64 Void
+ 0x090 SharedData : Ptr64 Void
+ 0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
+ 0x0a0 AnsiCodePageData : Ptr64 Void
+ 0x0a8 OemCodePageData : Ptr64 Void
+ 0x0b0 UnicodeCaseTableData : Ptr64 Void
+ 0x0b8 NumberOfProcessors : Uint4B
+ 0x0bc NtGlobalFlag : Uint4B
+ 0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
+ 0x0c8 HeapSegmentReserve : Uint8B
+ 0x0d0 HeapSegmentCommit : Uint8B
+ 0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
+ 0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
+ 0x0e8 NumberOfHeaps : Uint4B
+ 0x0ec MaximumNumberOfHeaps : Uint4B
+ 0x0f0 ProcessHeaps : Ptr64 Ptr64 Void
+ 0x0f8 GdiSharedHandleTable : Ptr64 Void
+ 0x100 ProcessStarterHelper : Ptr64 Void
+ 0x108 GdiDCAttributeList : Uint4B
+ 0x10c Padding3 : [4] UChar
+ 0x110 LoaderLock : Ptr64 _RTL_CRITICAL_SECTION
+ 0x118 OSMajorVersion : Uint4B
+ 0x11c OSMinorVersion : Uint4B
+ 0x120 OSBuildNumber : Uint2B
+ 0x122 OSCSDVersion : Uint2B
+ 0x124 OSPlatformId : Uint4B
+ 0x128 ImageSubsystem : Uint4B
+ 0x12c ImageSubsystemMajorVersion : Uint4B
+ 0x130 ImageSubsystemMinorVersion : Uint4B
+ 0x134 Padding4 : [4] UChar
+ 0x138 ActiveProcessAffinityMask : Uint8B
+ 0x140 GdiHandleBuffer : [60] Uint4B
+ 0x230 PostProcessInitRoutine : Ptr64     void
+ 0x238 TlsExpansionBitmap : Ptr64 Void
+ 0x240 TlsExpansionBitmapBits : [32] Uint4B
+ 0x2c0 SessionId : Uint4B
+ 0x2c4 Padding5 : [4] UChar
+ 0x2c8 AppCompatFlags : _ULARGE_INTEGER
+ 0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
+ 0x2d8 pShimData : Ptr64 Void
+ 0x2e0 AppCompatInfo : Ptr64 Void
+ 0x2e8 CSDVersion : _UNICODE_STRING
+ 0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
+ 0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
+ 0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
+ 0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
+ 0x318 MinimumStackCommit : Uint8B
+ 0x320 SparePointers : [4] Ptr64 Void
+ 0x340 SpareUlongs : [5] Uint4B
+ 0x358 WerRegistrationData : Ptr64 Void
+ 0x360 WerShipAssertPtr : Ptr64 Void
+ 0x368 pUnused : Ptr64 Void
+ 0x370 pImageHeaderHash : Ptr64 Void
+ 0x378 TracingFlags : Uint4B
+ 0x378 HeapTracingEnabled : Pos 0, 1 Bit
+ 0x378 CritSecTracingEnabled : Pos 1, 1 Bit
+ 0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
+ 0x378 SpareTracingBits : Pos 3, 29 Bits
+ 0x37c Padding6 : [4] UChar
+ 0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
+ 0x388 TppWorkerpListLock : Uint8B
+ 0x390 TppWorkerpList : _LIST_ENTRY
+ 0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
+ 0x7a0 TelemetryCoverageHeader : Ptr64 Void
+ 0x7a8 CloudFileFlags : Uint4B
+ 0x7ac CloudFileDiagFlags : Uint4B
+ 0x7b0 PlaceholderCompatibilityMode : Char
+ 0x7b1 PlaceholderCompatibilityModeReserved : [7] Char
+ 0x7b8 LeapSecondData : Ptr64 _LEAP_SECOND_DATA
+ 0x7c0 LeapSecondFlags : Uint4B
+ 0x7c0 SixtySecondEnabled : Pos 0, 1 Bit
+ 0x7c0 Reserved : Pos 1, 31 Bits
+ 0x7c4 NtGlobalFlag2 : Uint4B
*/
#endif