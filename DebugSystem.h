#pragma once
#include "GlobalConfig.h"
#define VOID void
#define STDCALL __stdcall
#define CDECL __cdecl
#define THISCALL __thiscall
#define NEAR 
#define FAR

//
// Define debug object access types. No security is present on this object.
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
                              DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)
#define DEBUG_KILL_ON_CLOSE  (0x1) // Kill all debuggees on last handle close

#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.

#define DEBUG_EVENT_READ            (0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT          (0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE        (0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE         (0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED  (0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND         (0x20)  // Resume thread on continue


//
// Define the debug object thats used to attatch to processes that are being debugged.
//
#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE  (0x2) // Kill all debugged processes on close

#define DEBUG_OBJECT_WOW64_DEBUGGER  (0x4) // Debugger is a x86 process


//
// Flags for cross thread access. Use interlocked operations
// via PS_SET_BITS etc.
//

//
// Used to signify that the delete APC has been queued or the
// thread has called PspExitThread itself.
//

#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL

//
// Thread create failed
//

#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL

//
// Debugger isn't shown this thread
//

#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL

//
// Thread is impersonating
//

#define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL

//
// This is a system thread
//

#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL

//
// Hard errors are disabled for this thread
//

#define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL

//
// We should break in when this thread is terminated
//

#define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL

//
// This thread should skip sending its create thread message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL

//
// This thread should skip sending its final thread termination message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL

#define PS_SET_BITS(Flags, Flag) \
                    RtlInterlockedSetBitsDiscardReturn (Flags, Flag)
//
// Valid return values for the PORT_MESSAGE Type file
//

#define LPC_REQUEST             1
#define LPC_REPLY               2
#define LPC_DATAGRAM            3
#define LPC_LOST_REPLY          4
#define LPC_PORT_CLOSED         5
#define LPC_CLIENT_DIED         6
#define LPC_EXCEPTION           7
#define LPC_DEBUG_EVENT         8
#define LPC_ERROR_EVENT         9
#define LPC_CONNECTION_REQUEST 10
//
// DbgKm Apis are from the kernel component (Dbgk) through a process
// debug port.
//

#define DBGKM_MSG_OVERHEAD \
    (FIELD_OFFSET(DBGKM_APIMSG, u.Exception) - sizeof(PORT_MESSAGE))

#define DBGKM_API_MSG_LENGTH(TypeSize) \
    ((sizeof(DBGKM_APIMSG) << 16) | (DBGKM_MSG_OVERHEAD + (TypeSize)))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)

#define PS_TEST_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBits (Flags, Flag)

#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
            ((hdrs)->OptionalHeader.##field)


#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed
#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)
#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27
#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //

#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code

typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;

typedef          char   int8;
typedef   signed char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef   signed short  sint16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef   signed int    sint32;
typedef unsigned int    uint32;


// Some convenience macros to make partial accesses nicer
// first unsigned macros:
#define LOBYTE(x)   (*((BYTE*)&(x)))   // low byte
#define LOWORD(x)   (*((WORD*)&(x)))   // low word
#define LODWORD(x)  (*((DWORD*)&(x)))  // low dword
#define HIBYTE(x)   (*((BYTE*)&(x)+1))
#define HIWORD(x)   (*((WORD*)&(x)+1))
#define HIDWORD(x)  (*((DWORD*)&(x)+1))
#define BYTEn(x, n)   (*((BYTE*)&(x)+n))
#define WORDn(x, n)   (*((WORD*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x)   BYTEn(x,  4)
#define BYTE5(x)   BYTEn(x,  5)
#define BYTE6(x)   BYTEn(x,  6)
#define BYTE7(x)   BYTEn(x,  7)
#define BYTE8(x)   BYTEn(x,  8)
#define BYTE9(x)   BYTEn(x,  9)
#define BYTE10(x)  BYTEn(x, 10)
#define BYTE11(x)  BYTEn(x, 11)
#define BYTE12(x)  BYTEn(x, 12)
#define BYTE13(x)  BYTEn(x, 13)
#define BYTE14(x)  BYTEn(x, 14)
#define BYTE15(x)  BYTEn(x, 15)
#define WORD1(x)   WORDn(x,  1)
#define WORD2(x)   WORDn(x,  2)         // third word of the object, unsigned
#define WORD3(x)   WORDn(x,  3)
#define WORD4(x)   WORDn(x,  4)
#define WORD5(x)   WORDn(x,  5)
#define WORD6(x)   WORDn(x,  6)
#define WORD7(x)   WORDn(x,  7)

// now signed macros (the same but with sign extension)
#define SLOBYTE(x)   (*((int8*)&(x)))
#define SLOWORD(x)   (*((int16*)&(x)))
#define SLODWORD(x)  (*((int32*)&(x)))
#define SHIBYTE(x)   (*((int8*)&(x)+1))
#define SHIWORD(x)   (*((int16*)&(x)+1))
#define SHIDWORD(x)  (*((int32*)&(x)+1))
#define SBYTEn(x, n)   (*((int8*)&(x)+n))
#define SWORDn(x, n)   (*((int16*)&(x)+n))
#define SBYTE1(x)   SBYTEn(x,  1)
#define SBYTE2(x)   SBYTEn(x,  2)
#define SBYTE3(x)   SBYTEn(x,  3)
#define SBYTE4(x)   SBYTEn(x,  4)
#define SBYTE5(x)   SBYTEn(x,  5)
#define SBYTE6(x)   SBYTEn(x,  6)
#define SBYTE7(x)   SBYTEn(x,  7)
#define SBYTE8(x)   SBYTEn(x,  8)
#define SBYTE9(x)   SBYTEn(x,  9)
#define SBYTE10(x)  SBYTEn(x, 10)
#define SBYTE11(x)  SBYTEn(x, 11)
#define SBYTE12(x)  SBYTEn(x, 12)
#define SBYTE13(x)  SBYTEn(x, 13)
#define SBYTE14(x)  SBYTEn(x, 14)
#define SBYTE15(x)  SBYTEn(x, 15)
#define SWORD1(x)   SWORDn(x,  1)
#define SWORD2(x)   SWORDn(x,  2)
#define SWORD3(x)   SWORDn(x,  3)
#define SWORD4(x)   SWORDn(x,  4)
#define SWORD5(x)   SWORDn(x,  5)
#define SWORD6(x)   SWORDn(x,  6)
#define SWORD7(x)   SWORDn(x,  7)



#define PROCESS_TERMINATE						(0x0001)  




typedef enum _OB_OPEN_REASON {
	ObCreateHandle,
	ObOpenHandle,
	ObDuplicateHandle,
	ObInheritHandle,
	ObMaxOpenReason
} OB_OPEN_REASON;
typedef VOID(NEAR CDECL FUNCT_011D_2820_DumpProcedure) (VOID*, struct _OBJECT_DUMP_CONTROL*);
typedef LONG32(NEAR CDECL FUNCT_0115_2828_OpenProcedure) (enum _OB_OPEN_REASON, CHAR, struct _EPROCESS*, VOID*, ULONG32*, ULONG32);
typedef VOID(NEAR CDECL FUNCT_011D_2836_CloseProcedure) (struct _EPROCESS*, VOID*, UINT64, UINT64);
typedef VOID(NEAR CDECL FUNCT_011D_059F_Free_InterfaceReference_InterfaceDereference_WorkerRoutine_Callback_DevicePowerRequired_DevicePowerNotRequired_DeleteCallback_Uninitialize_ClearLocalUnitError_EndOfInterrupt_InitializeController_DeleteProcedure_ReleaseFromLazyWrite_ReleaseFromReadAhead_CleanupProcedure_HalLocateHiberRanges_HalDpReplaceTarget_HalDpReplaceEnd_DisableCallback) (VOID*);
typedef LONG32(NEAR CDECL FUNCT_0115_283C_ParseProcedure) (VOID*, VOID*, struct _ACCESS_STATE*, CHAR, ULONG32, struct _UNICODE_STRING*, struct _UNICODE_STRING*, VOID*, struct _SECURITY_QUALITY_OF_SERVICE*, VOID**);
typedef LONG32(NEAR CDECL FUNCT_0115_2848_ParseProcedureEx) (VOID*, VOID*, struct _ACCESS_STATE*, CHAR, ULONG32, struct _UNICODE_STRING*, struct _UNICODE_STRING*, VOID*, struct _SECURITY_QUALITY_OF_SERVICE*, struct _OB_EXTENDED_PARSE_PARAMETERS*, VOID**);
typedef LONG32(NEAR CDECL FUNCT_0115_285A_SecurityProcedure) (VOID*, enum _SECURITY_OPERATION_CODE, ULONG32*, VOID*, ULONG32*, VOID**, enum _POOL_TYPE, struct _GENERIC_MAPPING*, CHAR);
typedef LONG32(NEAR CDECL FUNCT_0115_286B_QueryNameProcedure) (VOID*, UINT8, struct _OBJECT_NAME_INFORMATION*, ULONG32, ULONG32*, CHAR);
typedef UINT8(NEAR CDECL FUNCT_0116_2873_OkayToCloseProcedure) (struct _EPROCESS*, VOID*, VOID*, CHAR);
typedef VOID(NEAR CDECL FUNCT_011D_122D_PostProcessInitRoutine_FastEndOfInterrupt_EndOfInterrupt_HalHaltSystem_KdCheckPowerButton_HalResumeProcessorFromIdle_HalSaveAndDisableHvEnlightenment_HalRestoreHvEnlightenment_HalPciMarkHiberPhase_HalClockTimerInitialize_HalClockTimerStop_HalTimerWatchdogStart_HalTimerWatchdogResetCountdown_HalTimerWatchdogStop_HalAcpiLateRestore_HalInitPlatformDebugTriggers_DispatchAddress_FinishRoutine) ();

typedef enum _DBG_STATE {
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, * PDBG_STATE;

typedef struct _DBGKM_EXCEPTION32               // 2 elements, 0x54 bytes (sizeof) 
{
	/*0x000*/     struct _EXCEPTION_RECORD32 ExceptionRecord; // 6 elements, 0x50 bytes (sizeof) 
	/*0x050*/     ULONG32      FirstChance;
}DBGKM_EXCEPTION32, * PDBGKM_EXCEPTION32;

typedef struct _DBGKM_EXCEPTION64               // 2 elements, 0xA0 bytes (sizeof) 
{
	/*0x000*/     struct _EXCEPTION_RECORD ExceptionRecord; // 7 elements, 0x98 bytes (sizeof) 
	/*0x098*/     ULONG32      FirstChance;
	/*0x09C*/     UINT8        _PADDING0_[0x4];
}DBGKM_EXCEPTION64, * PDBGKM_EXCEPTION64;

typedef DBGKM_EXCEPTION64 DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
	HANDLE FileHandle;		// 0x0
	PVOID BaseOfDll;		// 0x8
	ULONG DebugInfoFileOffset;	// 0x10
	ULONG DebugInfoSize;	// 0x14
	PVOID NamePointer;		// 0x18
} DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;
typedef struct _DBGUI_CREATE_THREAD {
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, * PDBGUI_CREATE_THREAD;
typedef struct _DBGUI_CREATE_PROCESS {
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, * PDBGUI_CREATE_PROCESS;
typedef struct _DBGUI_WAIT_STATE_CHANGE {
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union {
		DBGKM_EXCEPTION Exception;
		DBGUI_CREATE_THREAD CreateThread;
		DBGUI_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                                                                                                                                                                                                                                     // 32 elements, 0x78 bytes (sizeof) 
{
	UINT16 Length;
	UINT16 ObjectTypeFlags;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG RetainAccess;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID OpenProcedureEx;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
	ULONG WaitObjectFlagMask;
	ULONG WaitObjectFlagOffset;
	ULONG WaitObjectPointerOffset;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof) 
{
	union                                    // 3 elements, 0x8 bytes (sizeof) 
	{
		struct                               // 5 elements, 0x8 bytes (sizeof) 
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                  
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                  
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                  
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                  
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                  
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID* Ptr;
	};
}EX_PUSH_LOCK_BY, * PEX_PUSH_LOCK_BY;
typedef struct _OBJECT_TYPE                   // 12 elements, 0xD8 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)  
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)  
	/*0x020*/     VOID* DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x029*/     UINT8        _PADDING0_[0x3];
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x03C*/     UINT8        _PADDING1_[0x4];
	/*0x040*/     struct _OBJECT_TYPE_INITIALIZER TypeInfo; // 32 elements, 0x78 bytes (sizeof) 
	/*0x0B8*/     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)   
	/*0x0C0*/     ULONG32      Key;
	/*0x0C4*/     UINT8        _PADDING2_[0x4];
	/*0x0C8*/     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)  
}OBJECT_TYPE, * POBJECT_TYPE;
typedef struct _DEBUG_OBJECT {
	//
	// Event thats set when the EventList is populated.
	//
	KEVENT EventsPresent;
	//
	// Mutex to protect the structure
	//
	FAST_MUTEX Mutex;
	//
	// Queue of events waiting for debugger intervention
	//
	LIST_ENTRY EventList;
	//
	// Flags for the object
	//
	ULONG Flags;
} DEBUG_OBJECT, * PDEBUG_OBJECT;
typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			SHORT DataLength;                                               //0x0
			SHORT TotalLength;                                              //0x2
		} s1;                                                               //0x0
		ULONG Length;                                                       //0x0
	} u1;                                                                   //0x0
	union
	{
		struct
		{
			SHORT Type;                                                     //0x4
			SHORT DataInfoOffset;                                           //0x6
		} s2;                                                               //0x4
		ULONG ZeroInit;                                                     //0x4
	} u2;                                                                   //0x4
	union
	{
		struct _CLIENT_ID ClientId;                                         //0x8
		double DoNotUseThisField;                                           //0x8
	};
	ULONG MessageId;                                                        //0x18
	union
	{
		ULONGLONG ClientViewSize;                                           //0x20
		ULONG CallbackId;                                                   //0x20
	};
}PORT_MESSAGE, * PPORT_MESSAGE;
typedef enum _DBGKM_APINUMBER {
	DbgKmExceptionApi,
	DbgKmCreateThreadApi,
	DbgKmCreateProcessApi,
	DbgKmExitThreadApi,
	DbgKmExitProcessApi,
	DbgKmLoadDllApi,
	DbgKmUnloadDllApi,
	DbgKmMaxApiNumber
} DBGKM_APINUMBER;
//消息结构
typedef struct _DBGKM_APIMSG {
	PORT_MESSAGE h;								//+0x0
	DBGKM_APINUMBER ApiNumber;					//+0x28
	NTSTATUS ReturnedStatus;					//+0x1c
	union {
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} u;										//0x20

	//以上这个部分占了0x74个大小，而windows7此结构的大小是A8，下面应该是输入异常相关的信息，为此，我们要凑够0xA8个大小，不然处理异常的时候会蓝屏掉
	UCHAR	ExceptPart[0x40];
} DBGKM_APIMSG, * PDBGKM_APIMSG;

typedef struct _DEBUG_EVENT {
	LIST_ENTRY EventList;		//	0x0		Queued to event object through this
	KEVENT ContinueEvent;		//	0x10
	CLIENT_ID ClientId;			//	0x28
	PEPROCESS Process;			//	0x38	Waiting process
	PETHREAD Thread;			//	0x40	Waiting thread
	NTSTATUS Status;			//	0x48	Status of operation
	ULONG Flags;				//	0x4C
	PETHREAD BackoutThread;		//	0x50	Backout key for faked messages
	DBGKM_APIMSG ApiMsg;		//	0x58	Message being sent
} DEBUG_EVENT, * PDEBUG_EVENT;
typedef struct _PS_PROTECTION        // 4 elements, 0x1 bytes (sizeof) 
{
	union                            // 2 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        Level;
		struct                       // 3 elements, 0x1 bytes (sizeof) 
		{
			/*0x000*/             UINT8        Type : 3;   // 0 BitPosition                  
			/*0x000*/             UINT8        Audit : 1;  // 3 BitPosition                  
			/*0x000*/             UINT8        Signer : 4; // 4 BitPosition                  
		};
	};
}PS_PROTECTION, * PPS_PROTECTION;
typedef struct _PS_SYSTEM_DLL_INFO {

	//
	// Flags.
	// Initialized statically.
	// 

	USHORT        Flags;        // 0x0

	//
	// Machine type of this WoW64 NTDLL.
	// Initialized statically.
	// Examples:
	//   - IMAGE_FILE_MACHINE_I386
	//   - IMAGE_FILE_MACHINE_ARMNT
	//

	USHORT        MachineType;  // 0x2

	//
	// Unused, always 0.
	//

	ULONG         Reserved1;    // 0x4

	//
	// Path to the WoW64 NTDLL.
	// Initialized statically.
	// Examples:
	//   - "\\SystemRoot\\SysWOW64\\ntdll.dll"
	//   - "\\SystemRoot\\SysArm32\\ntdll.dll"
	//

	UNICODE_STRING Ntdll32Path; // 0x8

	//
	// Image base of the DLL.
	// Initialized at runtime by PspMapSystemDll.
	// Equivalent of:
	//      RtlImageNtHeader(BaseAddress)->
	//          OptionalHeader.ImageBase;
	//

	PVOID         ImageBase;    // 0x18

	//
	// Contains DLL name (such as "ntdll.dll" or
	// "ntdll32.dll") before runtime initialization.
	// Initialized at runtime by MmMapViewOfSectionEx,
	// called from PspMapSystemDll.
	//

	union {                     // 0x20
		PVOID       BaseAddress;
		PWCHAR      DllName;
	};

	//
	// Unused, always 0.
	//

	PVOID         Reserved2;    // 0x28

	//
	// Section relocation information.
	//

	PVOID         SectionRelocationInformation; // 0x30

	//
	// Unused, always 0.
	//

	PVOID         Reserved3;    // 0x30

} PS_SYSTEM_DLL_INFO, * PPS_SYSTEM_DLL_INFO;

typedef struct _SYSTEM_DLL_ENTRY
{

	ULONG64 Type;
	UNICODE_STRING FullName;
	PVOID ImageBase;
	PWCHAR BaseName;
	PWCHAR StaticUnicodeBuffer;
}SYSTEM_DLL_ENTRY, * PSYSTEM_DLL_ENTRY;
typedef struct _SYSTEM_DLL_INFO
{
	PVOID Section;
	ULONG64 Un1;
	SYSTEM_DLL_ENTRY Entry;

}SYSTEM_DLL_INFO, * PSYSTEM_DLL_INFO;

enum _SYSTEM_DLL_TYPE
{
	PsNativeSystemDll = 0,
	PsWowX86SystemDll = 1,
	PsWowArm32SystemDll = 2,
	PsWowChpeX86SystemDll = 3,
	PsChpeV2SystemDll = 4,
	PsVsmEnclaveRuntimeDll = 5,
	PsTrustedAppsRuntimeDll = 6,
	PsSystemDllTotalTypes = 7
};
typedef struct _EWOW64PROCESS        // 3 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     VOID* Peb;
	/*0x008*/     enum _SYSTEM_DLL_TYPE NtdllType;
}EWOW64PROCESS, * PEWOW64PROCESS;
typedef struct _EX_FAST_REF      // 3 elements, 0x8 bytes (sizeof) 
{
	union                        // 3 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         VOID* Object;
		/*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition                  
		/*0x000*/         UINT64       Value;
	};
}EX_FAST_REF, * PEX_FAST_REF;
typedef struct _PS_SYSTEM_DLL {

	//
	// _SECTION* object of the DLL.
	// Initialized at runtime by PspLocateSystemDll.
	//

	union {     // 0x0
		EX_FAST_REF SectionObjectFastRef;
		PVOID       SectionObject;
	};

	//
	// Push lock.
	//

	EX_PUSH_LOCK  PushLock;     // 0x8

	//
	// System DLL information.
	// This part is returned by PsQuerySystemDllInfo.
	//

	PS_SYSTEM_DLL_INFO SystemDllInfo;   // 0x10

} PS_SYSTEM_DLL, * PPS_SYSTEM_DLL;
typedef struct _MMSECTION_FLAGS                        // 27 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT32       BeingDeleted : 1;                     // 0 BitPosition                   
	/*0x000*/     UINT32       BeingCreated : 1;                     // 1 BitPosition                   
	/*0x000*/     UINT32       BeingPurged : 1;                      // 2 BitPosition                   
	/*0x000*/     UINT32       NoModifiedWriting : 1;                // 3 BitPosition                   
	/*0x000*/     UINT32       FailAllIo : 1;                        // 4 BitPosition                   
	/*0x000*/     UINT32       Image : 1;                            // 5 BitPosition                   
	/*0x000*/     UINT32       Based : 1;                            // 6 BitPosition                   
	/*0x000*/     UINT32       File : 1;                             // 7 BitPosition                   
	/*0x000*/     UINT32       AttemptingDelete : 1;                 // 8 BitPosition                   
	/*0x000*/     UINT32       PrefetchCreated : 1;                  // 9 BitPosition                   
	/*0x000*/     UINT32       PhysicalMemory : 1;                   // 10 BitPosition                  
	/*0x000*/     UINT32       ImageControlAreaOnRemovableMedia : 1; // 11 BitPosition                  
	/*0x000*/     UINT32       Reserve : 1;                          // 12 BitPosition                  
	/*0x000*/     UINT32       Commit : 1;                           // 13 BitPosition                  
	/*0x000*/     UINT32       NoChange : 1;                         // 14 BitPosition                  
	/*0x000*/     UINT32       WasPurged : 1;                        // 15 BitPosition                  
	/*0x000*/     UINT32       UserReference : 1;                    // 16 BitPosition                  
	/*0x000*/     UINT32       GlobalMemory : 1;                     // 17 BitPosition                  
	/*0x000*/     UINT32       DeleteOnClose : 1;                    // 18 BitPosition                  
	/*0x000*/     UINT32       FilePointerNull : 1;                  // 19 BitPosition                  
	/*0x000*/     UINT32       PreferredNode : 6;                    // 20 BitPosition                  
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;             // 26 BitPosition                  
	/*0x000*/     UINT32       UserWritable : 1;                     // 27 BitPosition                  
	/*0x000*/     UINT32       SystemVaAllocated : 1;                // 28 BitPosition                  
	/*0x000*/     UINT32       PreferredFsCompressionBoundary : 1;   // 29 BitPosition                  
	/*0x000*/     UINT32       UsingFileExtents : 1;                 // 30 BitPosition                  
	/*0x000*/     UINT32       PageSize64K : 1;                      // 31 BitPosition                  
}MMSECTION_FLAGS, * PMMSECTION_FLAGS;
typedef struct _SECTION                             // 9 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_BALANCED_NODE SectionNode;          // 6 elements, 0x18 bytes (sizeof) 
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
	union                                           // 4 elements, 0x8 bytes (sizeof)  
	{
		/*0x028*/         struct _CONTROL_AREA* ControlArea;
		/*0x028*/         struct _FILE_OBJECT* FileObject;
		struct                                      // 2 elements, 0x8 bytes (sizeof)  
		{
			/*0x028*/             UINT64       RemoteImageFileObject : 1; // 0 BitPosition                   
			/*0x028*/             UINT64       RemoteDataFileObject : 1;  // 1 BitPosition                   
		};
	}u1;
	/*0x030*/     UINT64       SizeOfSection;
	union                                           // 2 elements, 0x4 bytes (sizeof)  
	{
		/*0x038*/         ULONG32      LongFlags;
		/*0x038*/         struct _MMSECTION_FLAGS Flags;              // 27 elements, 0x4 bytes (sizeof) 
	}u;
	struct                                          // 3 elements, 0x4 bytes (sizeof)  
	{
		/*0x03C*/         ULONG32      InitialPageProtection : 12;    // 0 BitPosition                   
		/*0x03C*/         ULONG32      SessionId : 19;                // 12 BitPosition                  
		/*0x03C*/         ULONG32      NoValidationNeeded : 1;        // 31 BitPosition                  
	};
}SECTION, * PSECTION;
typedef struct _MMSECTION_FLAGS2          // 2 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      PartitionId : 10;        // 0 BitPosition                  
	/*0x000*/     ULONG32      NumberOfChildViews : 22; // 10 BitPosition                 
}MMSECTION_FLAGS2, * PMMSECTION_FLAGS2;
typedef struct _CONTROL_AREA                                      // 16 elements, 0x80 bytes (sizeof) 
{
	/*0x000*/     struct _SEGMENT* Segment;
	/*0x008*/     struct _LIST_ENTRY ListHead;                                  // 2 elements, 0x10 bytes (sizeof)  
	/*0x018*/     UINT64       NumberOfSectionReferences;
	/*0x020*/     UINT64       NumberOfPfnReferences;
	/*0x028*/     UINT64       NumberOfMappedViews;
	/*0x030*/     UINT64       NumberOfUserReferences;
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x038*/         ULONG32      LongFlags;
		/*0x038*/         struct _MMSECTION_FLAGS Flags;                            // 27 elements, 0x4 bytes (sizeof)  
	}u;
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x03C*/         ULONG32      LongFlags;
		/*0x03C*/         struct _MMSECTION_FLAGS2 Flags;                           // 2 elements, 0x4 bytes (sizeof)   
	}u1;
	/*0x040*/     struct _EX_FAST_REF FilePointer;                              // 3 elements, 0x8 bytes (sizeof)   
	/*0x048*/     LONG32       ControlAreaLock;
	/*0x04C*/     ULONG32      ModifiedWriteCount;
	/*0x050*/     struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;
	union                                                         // 1 elements, 0x10 bytes (sizeof)  
	{
		struct                                                    // 13 elements, 0x10 bytes (sizeof) 
		{
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x058*/                 ULONG32      NumberOfSystemCacheViews;
				/*0x058*/                 ULONG32      ImageRelocationStartBit;
			};
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x05C*/                 LONG32       WritableUserReferences;
				struct                                            // 7 elements, 0x4 bytes (sizeof)   
				{
					/*0x05C*/                     ULONG32      ImageRelocationSizeIn64k : 16;   // 0 BitPosition                    
					/*0x05C*/                     ULONG32      Unused : 9;                      // 16 BitPosition                   
					/*0x05C*/                     ULONG32      SystemImage : 1;                 // 25 BitPosition                   
					/*0x05C*/                     ULONG32      StrongCode : 2;                  // 26 BitPosition                   
					/*0x05C*/                     ULONG32      CantMove : 1;                    // 28 BitPosition                   
					/*0x05C*/                     ULONG32      BitMap : 2;                      // 29 BitPosition                   
					/*0x05C*/                     ULONG32      ImageActive : 1;                 // 31 BitPosition                   
				};
			};
			union                                                 // 3 elements, 0x8 bytes (sizeof)   
			{
				/*0x060*/                 ULONG32      FlushInProgressCount;
				/*0x060*/                 ULONG32      NumberOfSubsections;
				/*0x060*/                 struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;
			};
		}e2;
	}u2;
	/*0x068*/     struct _EX_PUSH_LOCK FileObjectLock;                          // 7 elements, 0x8 bytes (sizeof)   
	/*0x070*/     UINT64       LockedPages;
	union                                                         // 3 elements, 0x8 bytes (sizeof)   
	{
		struct                                                    // 2 elements, 0x8 bytes (sizeof)   
		{
			/*0x078*/             UINT64       IoAttributionContext : 61;               // 0 BitPosition                    
			/*0x078*/             UINT64       Spare : 3;                               // 61 BitPosition                   
		};
		/*0x078*/         UINT64       SpareImage;
	}u3;
}CONTROL_AREA, * PCONTROL_AREA;

typedef struct _ADD_DEBUGGER
{
	UINT64 DebuggerPid;
	UINT64 DebugeePid;
	BOOLEAN Status;
}ADD_DEBUGGER, * PADD_DEBUGGER;
typedef struct _DEBUG_STATE
{
	LIST_ENTRY DebugStateList;
	UINT64 DebuggerPid;
	UINT64 DebugeePid;
	PDEBUG_OBJECT DebugObject;
}DEBUG_STATE, * PDEBUG_STATE;

typedef NTSTATUS(*FnPsTerminateProcess)(
	PEPROCESS Process,
	NTSTATUS ExitStatus
	);

typedef PEPROCESS(*FnPsGetNextProcess)(
	PEPROCESS Process
	);
typedef VOID(*FnDbgkpWakeTarget)(
	IN PDEBUG_EVENT DebugEvent
	);

typedef NTSTATUS(*FnObCreateObjectType)(
	__in PUNICODE_STRING TypeName,
	__in POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out POBJECT_TYPE* ObjectType
	);
typedef BOOLEAN(*FnPspCheckForInvalidAccessByProtection)(
	IN UCHAR CurrentPreviousMode,
	IN PS_PROTECTION SourceProcessProtection,
	IN PS_PROTECTION TargetProcessProtection
	);
typedef PETHREAD(*FnPsGetNextProcessThread)(
	IN PEPROCESS Process,
	IN PETHREAD Thread
	);
typedef NTSTATUS(*FnPsSynchronizeWithThreadInsertion)(
	IN PETHREAD Thread1,
	IN PETHREAD Thread2
	);
typedef NTSTATUS(*FnPsSuspendThread)(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);
typedef HANDLE(*FnDbgkpSectionToFileHandle)(
	IN VOID* SectionObject
	);
typedef NTSTATUS(*FnPsResumeThread)(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);
typedef PSYSTEM_DLL_ENTRY(*FnPsQuerySystemDllInfo)(
	IN int Index
	);
typedef BOOLEAN(*FnDbgkpSuspendProcess)(
	PEPROCESS
	);
typedef VOID(*FnPsThawMultiProcess)(
	PEPROCESS Process,
	ULONG64 Flags,
	UINT32 Unknown
	);
typedef NTSTATUS(*FnMmGetFileNameForAddress)(
	PIMAGE_NT_HEADERS NtHeaders,
	PUNICODE_STRING Name
	);
typedef NTSTATUS(*FnPsCallImageNotifyRoutines)(
	IN PUNICODE_STRING FileName,
	IN PVOID Process,
	IN PIMAGE_INFO ImageInfo,
	IN PFILE_OBJECT FileObject
	);

typedef PSECTION(*FnPspReferenceSystemDll)(
	PEX_FAST_REF FastRef
	);

typedef PCONTROL_AREA(*FnMiSectionControlArea)(
	PSECTION Section
	);

typedef PFILE_OBJECT(*FnMiReferenceControlAreaFile)(
	PCONTROL_AREA ControlArea
	);
typedef PFILE_OBJECT(*FnObFastDereferenceObject)(
	PEX_FAST_REF FastRef,
	PVOID Object
	);
typedef VOID(*FnDbgkpConvertKernelToUserStateChange)(
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PDEBUG_EVENT DebugEvent
	);

typedef VOID(*FnDbgkpOpenHandles)(
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PEPROCESS Process,
	PETHREAD Thread
	);
typedef PVOID(*FnPsCaptureExceptionPort)(
	IN PEPROCESS Process
	);
typedef NTSTATUS(*FnDbgkpSendApiMessageLpc)(
	PDBGKM_APIMSG ApiMsg,
	PVOID Port,
	BOOLEAN DebugException
	);
typedef NTSTATUS(*FnDbgkpSendErrorMessage)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	ULONG64 arg2,
	PDBGKM_APIMSG pm
	);

class DebugSystem
{
public:

	static VOID Initialize();
	static VOID Destory();

public:
	static BOOLEAN StartDebug(UINT64 DebuggerPid, UINT64 DebugeePid);


public:
	static VOID InitDebugObjectType();
	static BOOLEAN HookDebugFunctions();
	static VOID UnHookDebugFunctions();

private:
	static BOOLEAN GetStateByDebuggerPid(UINT64 DebuggerPid, PDEBUG_STATE PDebugState);
	static BOOLEAN SetStateByDebuggerPid(UINT64 DebuggerPid, UINT64 DebugeePid);
	static BOOLEAN GetStateByDebugeePid(UINT64 DebuggerPid, PDEBUG_STATE PDebugState);
	static BOOLEAN RemoveStateByDebuggerPid(UINT64 DebuggerPid);
	static BOOLEAN RemoveStateByDebugeePid(UINT64 DebugeePid);
	static BOOLEAN GetDebugeePid(UINT64* DebugeePid);

	static PDEBUG_OBJECT GetDebugObject(PEPROCESS PEprocess);
	static VOID SetDebugObject(PEPROCESS PEprocess, PDEBUG_OBJECT DebugObject);

	static UINT64* GetWoW64ProcessAddress(PEPROCESS PEprocess);
	static UINT64* GetUniqueProcessIdAddress(PEPROCESS PEprocess);
	static UINT64* GetProtectionAddress(PEPROCESS PEprocess);
	static UINT64* GetPcbSecureStateAddress(PEPROCESS PEprocess);
	static UINT64* GetRundownProtectAddress(PEPROCESS PEprocess);
	static UINT64* GetSectionObjectAddress(PEPROCESS PEprocess);
	static UINT64* GetSectionBaseAddressAddress(PEPROCESS PEprocess);
	static UINT64* GetPebAddress(PEPROCESS PEprocess);
	static UINT64* GetFlagsAddress(PEPROCESS PEprocess);
	static UINT64* GetExitTimeAddress(PEPROCESS PEprocess);
	static UINT64* GetMachineAddress(PEPROCESS PEprocess);
	static UINT64* GetSeAuditProcessCreationInfoImageFileNameNameAddress(PEPROCESS PEprocess);


	static UINT64* GetThreadRundownProtectAddress(PETHREAD PEthread);
	static UINT64* GetMiscFlagsAddress(PETHREAD PEthread);
	static UINT64* GetCrossThreadFlagsAddress(PETHREAD PEthread);
	static UINT64* GetWin32StartAddressAddress(PETHREAD PEthread);
	static UINT64* GetCidAddress(PETHREAD PEthread);
	static UINT64* GetApcStateAddress(PETHREAD PEthread);
	static UINT64* GetApcStateProcessAddress(PETHREAD PEthread);
	static UINT64* GetTebAddress(PETHREAD PEthread);
	static UINT64* GetSameThreadPassiveFlagsAddress(PETHREAD PEthread);
	static UINT64* GetTcbPreviousModeAddress(PETHREAD PEthread);
	static UINT64* GetTcbProcessAddress(PETHREAD PEthread);



	static UINT64* GetTebStaticUnicodeBufferAddress(PVOID PTEB);
	static UINT64* GetNtTibArbitraryUserPointerAddress(PVOID PTEB);
	static UINT64* GetSameTebFlagsAddress(PVOID PTEB);



	static UINT64* GetWoW64ProcessPebAddress(PEWOW64PROCESS PWoW64Process);




private:
	// 调试运行时的状态
	static POBJECT_TYPE DbgkDebugObjectType;
	static FAST_MUTEX DbgkpProcessDebugPortMutex;
	static LIST_ENTRY DebugStateListHead;
	static KSPIN_LOCK DebugStateListLock;

private:
	static NTSTATUS(NTAPI* OriginalNtTerminateThread)(
		_In_opt_ HANDLE ThreadHandle,
		_In_ NTSTATUS ExitStatus);
	static VOID(NTAPI* OriginalKiDispatchException)(PEXCEPTION_RECORD ExceptionRecord,
		PKEXCEPTION_FRAME ExceptionFrame,
		PKTRAP_FRAME TrapFrame,
		KPROCESSOR_MODE PreviousMode,
		BOOLEAN FirstChance);
	static NTSTATUS(NTAPI* OriginalNtCreateDebugObject)(OUT PHANDLE DebugObjectHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN ULONG Flags
		);
	static NTSTATUS(NTAPI* OriginalNtDebugActiveProcess)(
		IN HANDLE DebugeeProcessHandle,
		IN HANDLE DebugObjectHandle
		);
	static VOID(NTAPI* OriginalDbgkCreateThread)(
		PETHREAD Thread
		);
	static NTSTATUS(NTAPI* OriginalDbgkExitThread)(
		NTSTATUS ExitStatus
		);
	static NTSTATUS(NTAPI* OriginalDbgkExitProcess)(
		NTSTATUS ExitStatus
		);
	static VOID(NTAPI* OriginalDbgkMapViewOfSection)(
		IN PEPROCESS Process,
		IN PVOID SectionObject,
		IN PVOID SectionBaseAddress
		);
	static VOID(NTAPI* OriginalDbgkUnMapViewOfSection)(
		IN PEPROCESS Process,
		IN PVOID BaseAddress
		);
	static NTSTATUS(NTAPI* OriginalNtWaitForDebugEvent)(
		IN HANDLE DebugObjectHandle,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER Timeout OPTIONAL,
		OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
		);
	static VOID(NTAPI* OriginalDbgkpCloseObject)(
		IN PEPROCESS Process,
		IN PVOID Object,
		IN ULONG_PTR ProcessHandleCount,
		IN ULONG_PTR SystemHandleCount
		);
	static NTSTATUS(NTAPI* OriginalNtDebugContinue)(
		IN HANDLE DebugObjectHandle,
		IN PCLIENT_ID ClientId,
		IN NTSTATUS ContinueStatus
		);
	static BOOLEAN(NTAPI* OriginalDbgkForwardException)(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN BOOLEAN DebugException,
		IN BOOLEAN SecondChance
		);
	static VOID(NTAPI* OriginalDbgkpMarkProcessPeb)(
		PEPROCESS Process
		);

	static NTSTATUS(NTAPI* OriginalNtTerminateProcess)(
		OPTIONAL HANDLE ProcessHandle,
		IN NTSTATUS ExitStatus
		);

	static NTSTATUS(NTAPI* OriginalObpReferenceObjectByHandleWithTag)(
		HANDLE                     Handle,
		ACCESS_MASK                DesiredAccess,
		POBJECT_TYPE               ObjectType,
		KPROCESSOR_MODE            AccessMode,
		ULONG                      Tag,
		PVOID* Object,
		POBJECT_HANDLE_INFORMATION HandleInformation,
		PVOID					   UnKnown
		);

	static LONG_PTR(FASTCALL* OriginalObfDereferenceObjectWithTag)(
		 PVOID Object,
		 ULONG Tag
		);
private:
	static LONG_PTR FASTCALL NewObfDereferenceObjectWithTag(
		 PVOID Object,
		 ULONG Tag
		);

	static NTSTATUS NewNtTerminateThread(
		HANDLE ThreadHandle,
		NTSTATUS ExitStatus);

	static NTSTATUS NTAPI NewObpReferenceObjectByHandleWithTag(
		HANDLE                     Handle,
		ACCESS_MASK                DesiredAccess,
		POBJECT_TYPE               ObjectType,
		KPROCESSOR_MODE            AccessMode,
		ULONG                      Tag,
		PVOID* Object,
		POBJECT_HANDLE_INFORMATION HandleInformation,
		PVOID					   UnKnown
	);


	static INT64 NTAPI NewDbgkpSuppressDbgMsg(
		PVOID Teb
	);

	static NTSTATUS NTAPI NewDbgkpPostModuleMessages(
		IN PEPROCESS Process,
		IN PETHREAD Thread,
		IN PDEBUG_OBJECT DebugObject
	);
	static NTSTATUS NTAPI NewDbgkpSendApiMessage(
		PEPROCESS Process,
		ULONG Flags,
		PDBGKM_APIMSG ApiMsg
	);

	static ULONG64 MyPsWow64GetProcessNtdllType(PEPROCESS Process);

	static NTSTATUS NTAPI NewDbgkpQueueMessage(
		IN PEPROCESS Process,
		IN PETHREAD Thread,
		IN OUT PDBGKM_APIMSG ApiMsg,
		IN ULONG Flags,
		IN PDEBUG_OBJECT TargetDebugObject
	);
	static VOID NTAPI NewDbgkSendSystemDllMessages(
		PETHREAD Thread,
		PDEBUG_OBJECT DebugObject,
		PDBGKM_APIMSG ApiMsg
	);
	static NTSTATUS NTAPI NewDbgkpPostFakeProcessCreateMessages(
		IN PEPROCESS Process,
		IN PDEBUG_OBJECT DebugObject,
		IN PETHREAD* pLastThread
	);
	static NTSTATUS NTAPI NewDbgkpPostFakeThreadMessages(
		IN PEPROCESS Process,
		IN PDEBUG_OBJECT DebugObject,
		IN PETHREAD StartThread,
		OUT PETHREAD* pFirstThread,
		OUT PETHREAD* pLastThread
	);
	static NTSTATUS NTAPI NewDbgkpSetProcessDebugObject(
		IN PEPROCESS Process,
		IN PDEBUG_OBJECT DebugObject,
		IN NTSTATUS MsgStatus,
		IN PETHREAD LastThread
	);
	static VOID NTAPI NewKiDispatchException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN PKEXCEPTION_FRAME ExceptionFrame,
		IN PKTRAP_FRAME TrapFrame,
		IN KPROCESSOR_MODE PreviousMode,
		IN BOOLEAN FirstChance
	);
	static NTSTATUS NTAPI NewNtCreateDebugObject(
		OUT PHANDLE DebugObjectHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN ULONG Flags
	);
	static NTSTATUS NTAPI NewNtDebugActiveProcess(
		IN HANDLE DebugeeProcessHandle,
		IN HANDLE DebugObjectHandle
	);
	static VOID NTAPI NewDbgkCreateThread(
		PETHREAD Thread
	);
	static NTSTATUS NTAPI NewDbgkExitThread(
		NTSTATUS ExitStatus
	);
	static NTSTATUS NTAPI NewDbgkExitProcess(
		NTSTATUS ExitStatus
	);

	static VOID NTAPI NewDbgkMapViewOfSection(
		IN PEPROCESS Process,
		IN PVOID SectionObject,
		IN PVOID SectionBaseAddress
	);
	static VOID NTAPI NewDbgkUnMapViewOfSection(
		IN PEPROCESS Process,
		IN PVOID BaseAddress
	);
	static NTSTATUS NTAPI NewNtWaitForDebugEvent(
		IN HANDLE DebugObjectHandle,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER Timeout OPTIONAL,
		OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
	);
	static VOID NTAPI NewDbgkpCloseObject(
		IN PEPROCESS Process,
		IN PVOID Object,
		IN ULONG_PTR ProcessHandleCount,
		IN ULONG_PTR SystemHandleCount
	);

	static NTSTATUS NTAPI NewNtDebugContinue(
		IN HANDLE DebugObjectHandle,
		IN PCLIENT_ID ClientId,
		IN NTSTATUS ContinueStatus
	);
	static VOID NTAPI NewDbgkpMarkProcessPeb(
		PEPROCESS Process
	);
	static BOOLEAN NTAPI NewDbgkForwardException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN BOOLEAN DebugException,
		IN BOOLEAN SecondChance
	);

	static NTSTATUS NTAPI NewNtTerminateProcess(
		OPTIONAL HANDLE ProcessHandle,
		IN NTSTATUS ExitStatus
	);
};

