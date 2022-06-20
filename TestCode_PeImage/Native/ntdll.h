#ifndef Ntdll_H
#define Ntdll_H

#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include "ntstatus.h"

#if !defined(NTSTATUS)
typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#if !defined(SECURITY_STATUS)
typedef LONG SECURITY_STATUS;
#endif

#if !defined(KIRQL)
typedef UCHAR KIRQL;
typedef KIRQL* PKIRQL;
#endif

#if !defined(NOP_FUNCTION)
#if (_MSC_VER >= 1210)
#define NOP_FUNCTION __noop
#else
#define NOP_FUNCTION (void)0
#endif
#endif

#if !defined(PAGED_CODE)
#define PAGED_CODE() NOP_FUNCTION;
#endif

#if !defined(PAGE_SIZE)
#define PAGE_SIZE 0x1000
#endif

#define LDRP_IMAGE_DLL                          0x00000004

#define LDRP_ENTRY_INSERTED                     0x00008000

#define LDRP_ENTRY_PROCESSED                    0x00004000

#define LDRP_PROCESS_ATTACH_CALLED              0x00080000

#define LDRP_COR_IMAGE                          0x00400000

#define RtlInitializeListEntry(entry) ((entry)->Blink = (entry)->Flink = (entry))

#define RtlInitializeSingleEntry(entry) ((entry->Next = (entry)))

#define SEC_NO_CHANGE 0x00400000

#define PAGE_SIZE_L 0x3E8

#define IsVerifyDos(Base) (PIMAGE_DOS_HEADER(Base)->e_magic == IMAGE_DOS_SIGNATURE)

#define ALIGN_TO_POWER2( x, n ) (((ULONG)(x) + ((n)-1)) & ~((ULONG)(n)-1))

#define jmp_length(y,x) (((uint32_t)x-(uint32_t)y)-5)

#define stc_jc(y,x) ((x-y)-7)

#define PTR_ADD_OFFSET(Pointer, mOffset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(mOffset)))

#define AlignValueUp(value, alignment) ((size_t(value) + size_t(alignment) + 1) & ~(size_t(alignment) - 1))

#define OffsetPointer(data, offset) LPVOID(LPBYTE(data) + ptrdiff_t(offset))

#define GET_HEADER_DICTIONARY(headers, idx)  &headers->OptionalHeader.DataDirectory[idx]

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE},
	}, {
		// executable
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
	},
};

#define GetCallsite(Esp,Ebp,Caller) __asm      \
{                         \
   __asm mov Esp, esp        \
   __asm mov esp, ebp   \
   __asm pop Ebp       \
   __asm pop Caller       \
   __asm push Caller       \
   __asm push Ebp       \
   __asm mov esp, Esp       \
}
/*			
            void* caller = 0;   

			unsigned int TempEsp = 0;

			unsigned int TempEbp = 0;

			GetCallsite(TempEsp, TempEbp, caller);
*/

typedef struct _REBASE_INFO {
	USHORT Offset : 12;
	USHORT Type : 4;
}REBASE_INFO, * PREBASE_INFO;
typedef struct _IMAGE_BASE_RELOCATION_HEADER {
	DWORD VirtualAddress;
	DWORD SizeOfBlock;
	REBASE_INFO TypeOffset[ANYSIZE_ARRAY];

	DWORD TypeOffsetCount()const {
		return (this->SizeOfBlock - 8) / sizeof(_REBASE_INFO);
	}
}IMAGE_BASE_RELOCATION_HEADER, * PIMAGE_BASE_RELOCATION_HEADER;

typedef BOOL(WINAPI* PDLL_STARTUP_ROUTINE)(PVOID hinstDLL, DWORD fdwReason, LPVOID lpReserved);

typedef enum _WINDOWS_VERSION {
	null,
	xp,
	vista,
	win7,
	win8,
	win8_1,
	win10,
	win10_1,
	win10_2,
	invalid
}WINDOWS_VERSION;



typedef VOID(NTAPI* mRtlGetNtVersionNumbers)(OUT DWORD* MajorVersion, OUT DWORD* MinorVersion, OUT DWORD* BuildNumber);

#if !defined(PRTL_HEAP_COMMIT_ROUTINE)
typedef NTSTATUS(NTAPI* PRTL_HEAP_COMMIT_ROUTINE)(_In_ PVOID Base, _Inout_ PVOID* CommitAddress, _Inout_ PSIZE_T CommitSize);
#endif

#if !defined(_PROCESS_ACCESS_TOKEN)
typedef struct _PROCESS_ACCESS_TOKEN {
	HANDLE Token;
	HANDLE Thread;
} PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;
#endif

#if !defined(_RTL_HEAP_PARAMETERS)
typedef struct _RTL_HEAP_PARAMETERS
{
	ULONG Length;
	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;
	SIZE_T MaximumAllocationSize;
	SIZE_T VirtualMemoryThreshold;
	SIZE_T InitialCommit;
	SIZE_T InitialReserve;
	PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
	SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;
#endif

#if !defined(_UNICODE_STRING)
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
#endif

#if !defined(_OBJECT_ATTRIBUTES)
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG			uLength;
	HANDLE			hRootDirectory;
	PUNICODE_STRING	pObjectName;
	ULONG			uAttributes;
	PVOID			pSecurityDescriptor;
	PVOID			pSecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
#endif

#if !defined(_MEMORY_INFORMATION_CLASS)
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;
#endif

#if !defined(THREADINFOCLASS)
enum class  THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	MaxThreadInfoClass
};
#endif

#if !defined(_CLIENT_ID)
typedef struct _CLIENT_ID
{
	DWORD	UniqueProcess;
	DWORD	UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
#endif

#if !defined(_IO_STATUS_BLOCK)
typedef struct _IO_STATUS_BLOCK
{
	NTSTATUS	Status;
	ULONG		uInformation;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
#endif

#if !defined(PROCESSINFOCLASS)
enum class PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
	ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets, // 80
	ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
	ProcessImageSection, // q: HANDLE
	ProcessDebugAuthInformation, // since REDSTONE4 // 90
	ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	ProcessLoaderDetour, // since REDSTONE5
	ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	MaxProcessInfoClass
};
#endif

#if !defined(_STRING)
typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;
#endif

#if !defined(_RIOT_STRING)
typedef struct _RIOT_STRING
{
	PCHAR Buffer;
	USHORT Length = 0;
	USHORT MaximumLength = 256;
} riot_string, * priot_string;
#endif

#if !defined(PIO_APC_ROUTINE)
typedef void (*PIO_APC_ROUTINE)	(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);
#endif

typedef struct _MEMORYMODULE {
	ULONG64 Signature;

	DWORD SizeofHeaders;
	union {
		struct {
			BYTE initialized : 1;
			BYTE loadFromNtLoadDllMemory : 1;
			BYTE underUnload : 1;
			BYTE reservedStatusFlags : 5;
			BYTE cbFlagsReserved;
			WORD MappedDll : 1;
			WORD InsertInvertedFunctionTableEntry : 1;
			WORD TlsHandled : 1;
			WORD UseReferenceCount : 1;
			WORD reservedLoadFlags : 12;

		};
		DWORD dwFlags;
	};

	LPBYTE codeBase;
	PVOID lpReserved;
	HMODULE* hModulesList;
	DWORD dwModulesCount;
	DWORD dwReserved;
	DWORD dwImageFileSize;
	DWORD headers_align;

} MEMORYMODULE, * PMEMORYMODULE;

#if !defined(FILE_INFORMATION_CLASS)
enum class FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileInformationReserved32,
	FileInformationReserved33,
	FileNetworkOpenInformation,
	FileMaximumInformation
};
#endif

#if !defined(_OBJECT_INFORMATION_CLASS)
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectTypeInformation
} OBJECT_INFORMATION_CLASS;
#endif

#if !defined(_SECTION_INHERIT)
enum class _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
};
#endif

#if !defined(_PEB_LDR_DATA)
typedef struct _PEB_LDR_DATA
{
	ULONG		Length;
	BOOLEAN		Initialized;
	PVOID		SsHandle;
	LIST_ENTRY	InLoadOrderModuleList;
	LIST_ENTRY	InMemoryOrderModuleList;
	LIST_ENTRY	InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
#endif

#if !defined(_LDR_MODULE)
typedef struct _LDR_MODULE
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_MODULE, * PLDR_MODULE, LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#endif

#if !defined(_CURDIR)
typedef struct _CURDIR
{
	UNICODE_STRING	DosPath;
	HANDLE			Handle;
} CURDIR, * PCURDIR;
#endif

#if !defined(_RTL_DRIVE_LETTER_CURDIR)
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	WORD	Flags;
	WORD	Length;
	DWORD	TimeStamp;
	STRING	DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
#endif

#if !defined(_PROCESS_PARAMETERS)
typedef struct _PROCESS_PARAMETERS
{
	ULONG					MaximumLength;
	ULONG					Length;
	ULONG					Flags;
	ULONG					DebugFlags;
	HANDLE					ConsoleHandle;
	ULONG					ConsoleFlags;
	HANDLE					StandardInput;
	HANDLE					StandardOutput;
	HANDLE					StandardError;
	CURDIR					CurrentDirectory;
	UNICODE_STRING			DllPath;
	UNICODE_STRING			ImagePathName;
	UNICODE_STRING			CommandLine;
	PWSTR					Environment;
	ULONG					StartingX;
	ULONG					StartingY;
	ULONG					CountX;
	ULONG					CountY;
	ULONG					CountCharsX;
	ULONG					CountCharsY;
	ULONG					FillAttribute;
	ULONG					WindowFlags;
	ULONG					ShowWindowFlags;
	UNICODE_STRING			WindowTitle;
	UNICODE_STRING			Desktop;
	UNICODE_STRING			ShellInfo;
	UNICODE_STRING			RuntimeInfo;
	RTL_DRIVE_LETTER_CURDIR	CurrentDirectores[32];
} PROCESS_PARAMETERS, * PPROCESS_PARAMETERS;
#endif

#if !defined(PPEBLOCKROUTINE)
typedef VOID NTSYSAPI(*PPEBLOCKROUTINE)(PVOID Object);
#endif

#if !defined(_PEB_FREE_BLOCK)
typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* Next;
	ULONG					Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;
#endif

#if !defined(_RTL_BITMAP)
typedef struct _RTL_BITMAP
{
	DWORD	SizeOfBitMap;
	PDWORD	Buffer;
} RTL_BITMAP, * PRTL_BITMAP, ** PPRTL_BITMAP;
#endif

#if !defined(_PEB)
typedef struct _PEB
{
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	BYTE				b003;
	PVOID				Mutant;
	PVOID				ImageBaseAddress;
	PPEB_LDR_DATA		Ldr;
	PPROCESS_PARAMETERS	ProcessParameters;
	PVOID				SubSystemData;
	PVOID				ProcessHeap;
	KSPIN_LOCK			FastPebLock;
	PPEBLOCKROUTINE		FastPebLockRoutine;
	PPEBLOCKROUTINE		FastPebUnlockRoutine;
	ULONG				EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID				EventLogSection;
	PVOID				EventLog;
	PPEB_FREE_BLOCK		FreeList;
	ULONG				TlsExpansionCounter;
	PRTL_BITMAP			TlsBitmap;
	ULONG				TlsBitmapData[0x2];
	PVOID				ReadOnlySharedMemoryBase;
	PVOID				ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID				InitAnsiCodePageData;
	PVOID				InitOemCodePageData;
	PVOID				InitUnicodeCaseTableData;
	ULONG				KeNumberProcessors;
	ULONG				NtGlobalFlag;
	DWORD				d6C;
	LARGE_INTEGER		MmCriticalSectionTimeout;
	ULONG				MmHeapSegmentReserve;
	ULONG				MmHeapSegmentCommit;
	ULONG				MmHeapDeCommitTotalFreeThreshold;
	ULONG				MmHeapDeCommitFreeBlockThreshold;
	ULONG				NumberOfHeaps;
	ULONG				AvailableHeaps;
	PHANDLE				ProcessHeapsListBuffer;
	PVOID				GdiSharedHandleTable;
	PVOID				ProcessStarterHelper;
	PVOID				GdiDCAttributeList;
	KSPIN_LOCK			LoaderLock;
	ULONG				NtMajorVersion;
	ULONG				NtMinorVersion;
	USHORT				NtBuildNumber;
	USHORT				NtCSDVersion;
	ULONG				PlatformId;
	ULONG				Subsystem;
	ULONG				MajorSubsystemVersion;
	ULONG				MinorSubsystemVersion;
	KAFFINITY			AffinityMask;
	ULONG				GdiHandleBuffer[0x22];
	ULONG				PostProcessInitRoutine;
	ULONG				TlsExpansionBitmap;
	UCHAR				TlsExpansionBitmapBits[0x80];
	ULONG				SessionId;
	ULARGE_INTEGER		AppCompatFlags;
	PWORD				CSDVersion;
	PVOID				AppCompatInfo;
	UNICODE_STRING		usCSDVersion;
	PVOID				ActivationContextData;
	PVOID				ProcessAssemblyStorageMap;
	PVOID				SystemDefaultActivationContextData;
	PVOID				SystemAssemblyStorageMap;
	ULONG				MinimumStackCommit;
} PEB, * PPEB;
#endif

#if !defined(_TEB)
typedef struct _TEB
{
	NT_TIB			Tib;
	PVOID			EnvironmentPointer;
	CLIENT_ID		ClientId; // 记录进程ID 和 主线程ID
	PVOID			ActiveRpcInfo;
	PVOID			ThreadLocalStoragePointer;
	PPEB			Peb;
	ULONG			LastErrorValue;
	ULONG			CountOfOwnedCriticalSections;
	PVOID			CsrClientThread;
	PVOID			Win32ThreadInfo;
	ULONG			Win32ClientInfo[0x1F];
	PVOID			WOW32Reserved;
	ULONG			CurrentLocale;
	ULONG			FpSoftwareStatusRegister;
	PVOID			SystemReserved1[0x36];
	PVOID			Spare1;
	LONG			ExceptionCode;
	ULONG			SpareBytes1[0x28];
	PVOID			SystemReserved2[0xA];
	ULONG			gdiRgn;
	ULONG			gdiPen;
	ULONG			gdiBrush;
	CLIENT_ID		RealClientId;
	PVOID			GdiCachedProcessHandle;
	ULONG			GdiClientPID;
	ULONG			GdiClientTID;
	PVOID			GdiThreadLocaleInfo;
	PVOID			UserReserved[5];
	PVOID			glDispatchTable[0x118];
	ULONG			glReserved1[0x1A];
	PVOID			glReserved2;
	PVOID			glSectionInfo;
	PVOID			glSection;
	PVOID			glTable;
	PVOID			glCurrentRC;
	PVOID			glContext;
	NTSTATUS		LastStatusValue;
	UNICODE_STRING	StaticUnicodeString;
	WCHAR			StaticUnicodeBuffer[0x105];
	PVOID			DeallocationStack;
	PVOID			TlsSlots[0x40];
	LIST_ENTRY		TlsLinks;
	PVOID			Vdm;
	PVOID			ReservedForNtRpc;
	PVOID			DbgSsReserved[0x2];
	ULONG			HardErrorDisabled;
	PVOID			Instrumentation[0x10];
	PVOID			WinSockData;
	ULONG			GdiBatchCount;
	ULONG			Spare2;
	ULONG			Spare3;
	PVOID			ReservedForPerf;
	PVOID			ReservedForOle;
	ULONG			WaitingOnLoaderLock;
	PVOID			StackCommit;
	PVOID			StackCommitMax;
	PVOID			StackReserve;
	PVOID Wx86Thread;
	PVOID* TlsExpansionSlots;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
} TEB, * PTEB;
#endif


#if !defined(NtQueryProcessData_T)
typedef NTSTATUS(NTAPI* NtQueryProcessData_T) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
#endif

#if !defined(NtVirtualMemoryRead_T)
typedef NTSTATUS(NTAPI* NtVirtualMemoryRead_T) (HANDLE, PVOID64, PVOID, ULONG64, PULONG64);
#endif

#if !defined(NtVirtualMemoryWrite_T)
typedef NTSTATUS(NTAPI* NtVirtualMemoryWrite_T) (HANDLE, PVOID64, PVOID, ULONGLONG, PULONGLONG);
#endif

#if !defined(NtProtectVirtualMemory_T)
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_T) (HANDLE, PVOID*, PULONG, ULONG, PULONG);
#endif

#if !defined(NtWriteVirtualMemory_T)
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_T) (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
#endif

#if !defined(NtCreateSection_T)
typedef NTSTATUS(NTAPI* NtCreateSection_T) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
#endif

#if !defined(NtMapViewOfSection_T)
typedef NTSTATUS(NTAPI* NtMapViewOfSection_T) (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, _SECTION_INHERIT, ULONG, ULONG);
#endif

#if !defined(NtUnmapViewOfSection_T)
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_T) (HANDLE, PVOID);
#endif

#if !defined(NtReadVirtualMemory_T)
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_T) (HANDLE, PVOID, PVOID, ULONG, PULONG);
#endif


#if !defined(DllEntryPoint)
typedef BOOL(__stdcall* DllEntryPoint)(HINSTANCE, DWORD, LPVOID);
#endif



#if !defined(_FILE_STANDARD_INFORMATION)
typedef struct _FILE_STANDARD_INFORMATION
{
	LARGE_INTEGER	AllocationSize;
	LARGE_INTEGER	EndOfFile;
	ULONG			NumberOfLinks;
	BOOLEAN			DeletePending;
	BOOLEAN			Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;
#endif

#if !defined(_IMAGE_MAPDATA)
typedef struct _IMAGE_MAPDATA
{
	BOOL Image;
	HANDLE FileHandle;
	PBYTE lpBuffer;
	size_t ImageFileSize;
	struct _IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileStandard;
	HANDLE SectionHandle;
	PVOID BaseAddress;
	PVOID SectionAddress;
	PVOID pdSectionAddress;
	ULONG ImageHeaderSize;
	ULONG ErrorValue;
	NTSTATUS Status;
	ULONG VirtualSize;
	ULONG VirtualProtect;
	SIZE_T ViewSize;
	ULONG ReturnLength;
	LARGE_INTEGER SectionSize;
	PIMAGE_DOS_HEADER DosHeaders;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_SECTION_HEADER Section;
	DllEntryPoint EntryPoint;
	BOOL IsIat;
	BOOL IsExport;
	PIMAGE_BASE_RELOCATION RelocationDir;
	DWORD Relocation;
	BOOL IsTls;
	PIMAGE_TLS_DIRECTORY Tls;
	PIMAGE_TLS_CALLBACK* TlsCallback;
	PIMAGE_IMPORT_DESCRIPTOR Iat;
	PIMAGE_EXPORT_DIRECTORY Export;
	DWORD ExportSize;
	DWORD ExportOffset;
	LPDWORD ExportprtAddress;
	LPWORD  ExportOrdinals;
	LPDWORD ExportNames;
	INT Ordinal;
	INT Found;
	DWORD ExportOffset_V;
	BOOL ErasePE;
	PVOID Heap;
}IMAGE_MAPDATA, * PIMAGE_MAPDATA;
#endif

#if !defined(_Code_Type)
enum class _Code_Type : uint8_t
{
	CALL = 1,
	JMP = 2,
	CALL_dword = 3
};
#endif

#if !defined(_Wow64_Type)
enum class _Wow64_Type : uint8_t
{
	x86 = 1,
	x64 = 2,
	NtWow64 = 3
};
#endif

#if !defined(_Inject_Type)
enum class _Inject_Type : uint8_t
{
	Client = 1,
	ACE = 2
};
#endif

#if !defined(_Object_Type)
enum class _Object_Type : uint8_t
{
	Handle = 1,
	MapPage = 2,
	NewPtr = 3
};
#endif

#if !defined(_Thread_SR_Type)
enum class _Thread_SR_Type : uint8_t
{
	Suspend = 1,
	Resume = 2
};
#endif

#if !defined(_Context_SG_Type)
enum class _Context_SG_Type : uint8_t
{
	SetThread = 1,
	GetThread = 2
};
#endif

#if !defined(_Get_Current_Type)
enum class _Get_Current_Type : uint8_t
{
	ThreadId = 1,
	LastError = 2
};
#endif

#if !defined(_Get_CurrentHandle_Type)
enum class _Get_CurrentHandle_Type : uint8_t
{
	Thread = 1,
	Process = 2
};
#endif

#if !defined(_Open_Handle_Type)
enum class _Open_Handle_Type : uint8_t
{
	Thread = 1,
	Process = 2
};
#endif
struct _LDR_SERVICE_TAG_RECORD {
	_LDR_SERVICE_TAG_RECORD* Next;									        //0x0
	ULONG ServiceTag;                                                       //0x8
};

//0x8 bytes (sizeof)
struct _LDRP_CSLIST {
	struct _LDRP_CSLIST_DEPENDENT {
		_SINGLE_LIST_ENTRY* NextDependentEntry;                                        //0x0
		struct _LDR_DDAG_NODE* DependentDdagNode;
	}Dependent;
	struct _LDRP_CSLIST_INCOMMING {
		_SINGLE_LIST_ENTRY* NextIncommingEntry;
		struct _LDR_DDAG_NODE* IncommingDdagNode;
	}Incomming;
};

enum _LDR_DLL_LOAD_REASON {
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonUnknown = -1
};

enum _LDR_DDAG_STATE {
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
};

struct _LDR_DDAG_NODE {
	_LIST_ENTRY Modules;												    //0x0
	_LDR_SERVICE_TAG_RECORD* ServiceTagList;							    //0x10
	ULONG LoadCount;                                                        //0x18
	ULONG LoadWhileUnloadingCount;                                          //0x1c
	ULONG LowestLink;                                                       //0x20
	_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT* Dependencies;						//0x28
	_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING* IncomingDependencies;				//0x30
	_LDR_DDAG_STATE State;													//0x38
	_SINGLE_LIST_ENTRY CondenseLink;										//0x40
	ULONG PreorderNumber;                                                   //0x48
};

typedef struct _RTL_BALANCED_NODE {
	union {
		_RTL_BALANCED_NODE* Children[2];					                //0x0
		struct {
			_RTL_BALANCED_NODE* Left;						                //0x0
			_RTL_BALANCED_NODE* Right;				                        //0x8
		};
	};
	union {
		struct {
			UCHAR Red : 1;                                                  //0x10
			UCHAR Balance : 2;                                              //0x10
		};
		size_t ParentValue;                                                 //0x10
	};
}RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE {
	PRTL_BALANCED_NODE Root;
	PRTL_BALANCED_NODE Min;
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _SEARCH_CONTEXT {
	union {
		IN PVOID  MemoryBuffer;
		size_t InBufferPtr;
	};
	union {
		IN DWORD BufferLength;
		size_t reserved0;
	};

	union {
		OUT PVOID  MemoryBlockInSection;
		size_t OutBufferPtr;
	};
	union {
		DWORD RemainingLength;
		size_t reserved1;
	};
}SEARCH_CONTEXT, * PSEARCH_CONTEXT;

struct _LDR_DDAG_NODE_WIN8 {
	_LIST_ENTRY Modules;							                        //0x0
	_LDR_SERVICE_TAG_RECORD* ServiceTagList;				                //0x10
	ULONG LoadCount;                                                        //0x18
	ULONG ReferenceCount;                                                   //0x1c
	ULONG DependencyCount;                                                  //0x20
	_LDRP_CSLIST::_LDRP_CSLIST_DEPENDENT* Dependencies;						//0x28
	_LDRP_CSLIST::_LDRP_CSLIST_INCOMMING* IncomingDependencies;				//0x30
	_LDR_DDAG_STATE State;                                                  //0x38
	_SINGLE_LIST_ENTRY CondenseLink;									    //0x40
	ULONG PreorderNumber;                                                   //0x48
	ULONG LowestLink;                                                       //0x4c
};

typedef struct _LDR_DATA_TABLE_ENTRY_XP {
	_LIST_ENTRY InLoadOrderLinks;											//0x0
	_LIST_ENTRY InMemoryOrderLinks;											//0x10
	_LIST_ENTRY InInitializationOrderLinks;									//0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	_UNICODE_STRING FullDllName;											//0x48
	_UNICODE_STRING BaseDllName;											//0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	USHORT TlsIndex;                                                        //0x6e
	union {
		_LIST_ENTRY HashLinks;												//0x70
		struct {
			VOID* SectionPointer;                                           //0x70
			ULONG CheckSum;                                                 //0x78
		};
	};
	union {
		ULONG TimeDateStamp;                                                //0x80
		VOID* LoadedImports;                                                //0x80
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;						//0x88
	VOID* PatchInformation;                                                 //0x90
}LDR_DATA_TABLE_ENTRY_XP, * PLDR_DATA_TABLE_ENTRY_XP;

typedef struct _LDR_DATA_TABLE_ENTRY_VISTA :public _LDR_DATA_TABLE_ENTRY_XP {
	_LIST_ENTRY ForwarderLinks;                                      //0x98
	_LIST_ENTRY ServiceTagLinks;                                     //0xa8
	_LIST_ENTRY StaticLinks;                                         //0xb8
}LDR_DATA_TABLE_ENTRY_VISTA, * PLDR_DATA_TABLE_ENTRY_VISTA;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN7 :public _LDR_DATA_TABLE_ENTRY_VISTA {
	VOID* ContextInformation;                                               //0xc8
	ULONGLONG OriginalBase;                                                 //0xd0
	_LARGE_INTEGER LoadTime;                                                //0xd8
}LDR_DATA_TABLE_ENTRY_WIN7, * PLDR_DATA_TABLE_ENTRY_WIN7;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN8 {
	_LIST_ENTRY InLoadOrderLinks;											  //0x0
	_LIST_ENTRY InMemoryOrderLinks;											  //0x10
	union {
		_LIST_ENTRY InInitializationOrderLinks;								  //0x20
		_LIST_ENTRY InProgressLinks;										  //0x20
	};
	VOID* DllBase;                                                            //0x30
	VOID* EntryPoint;                                                         //0x38
	ULONG SizeOfImage;                                                        //0x40
	_UNICODE_STRING FullDllName;											  //0x48
	_UNICODE_STRING BaseDllName;											  //0x58
	union {
		UCHAR FlagGroup[4];                                                   //0x68
		ULONG Flags;                                                          //0x68
		struct {
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG ReservedFlags2 : 1;                                         //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ReservedFlags3 : 3;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                                 //0x6c
	USHORT TlsIndex;                                                          //0x6e
	_LIST_ENTRY HashLinks;                                                    //0x70
	ULONG TimeDateStamp;                                                      //0x80
	_ACTIVATION_CONTEXT* EntryPointActivationContext;                         //0x88
	VOID* PatchInformation;                                                   //0x90
	_LDR_DDAG_NODE_WIN8* DdagNode;                                            //0x98
	_LIST_ENTRY NodeModuleLink;                                               //0xa0
	VOID* SnapContext;						                                  //0xb0
	VOID* ParentDllBase;                                                      //0xb8
	VOID* SwitchBackContext;                                                  //0xc0
	_RTL_BALANCED_NODE BaseAddressIndexNode;                                  //0xc8
	_RTL_BALANCED_NODE MappingInfoIndexNode;                                  //0xe0
	ULONGLONG OriginalBase;                                                   //0xf8
	_LARGE_INTEGER LoadTime;                                                  //0x100
	ULONG BaseNameHashValue;                                                  //0x108
	_LDR_DLL_LOAD_REASON LoadReason;                                          //0x10c
}LDR_DATA_TABLE_ENTRY_WIN8, * PLDR_DATA_TABLE_ENTRY_WIN8;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN8_1 :public _LDR_DATA_TABLE_ENTRY_WIN8 {
	ULONG ImplicitPathOptions;
}LDR_DATA_TABLE_ENTRY_WIN8_1, * PLDR_DATA_TABLE_ENTRY_WIN8_1;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN10 {
	_LIST_ENTRY InLoadOrderLinks;											  //0x0
	_LIST_ENTRY InMemoryOrderLinks;											  //0x10
	_LIST_ENTRY InInitializationOrderLinks;									  //0x20
	VOID* DllBase;                                                            //0x30
	VOID* EntryPoint;                                                         //0x38
	ULONG SizeOfImage;                                                        //0x40
	_UNICODE_STRING FullDllName;											  //0x48
	_UNICODE_STRING BaseDllName;											  //0x58
	union {
		UCHAR FlagGroup[4];                                                   //0x68
		ULONG Flags;                                                          //0x68
		struct {
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;												  //0x6c
	USHORT TlsIndex;														  //0x6e
	_LIST_ENTRY HashLinks;												      //0x70
	ULONG TimeDateStamp;                                                      //0x80
	_ACTIVATION_CONTEXT* EntryPointActivationContext;				          //0x88
	VOID* Lock;                                                               //0x90
	_LDR_DDAG_NODE* DdagNode;											      //0x98
	_LIST_ENTRY NodeModuleLink;										          //0xa0
	VOID* LoadContext;														  //0xb0
	VOID* ParentDllBase;                                                      //0xb8
	VOID* SwitchBackContext;                                                  //0xc0
	_RTL_BALANCED_NODE BaseAddressIndexNode;								  //0xc8
	_RTL_BALANCED_NODE MappingInfoIndexNode;								  //0xe0
	ULONGLONG OriginalBase;                                                   //0xf8
	_LARGE_INTEGER LoadTime;												  //0x100
	ULONG BaseNameHashValue;                                                  //0x108
	_LDR_DLL_LOAD_REASON LoadReason;										  //0x10c
	ULONG ImplicitPathOptions;                                                //0x110
	ULONG ReferenceCount;                                                     //0x114
}LDR_DATA_TABLE_ENTRY_WIN10, * PLDR_DATA_TABLE_ENTRY_WIN10;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN10_1 :public _LDR_DATA_TABLE_ENTRY_WIN10 {
	ULONG DependentLoadFlags;                                               //0x118
}LDR_DATA_TABLE_ENTRY_WIN10_1, * PLDR_DATA_TABLE_ENTRY_WIN10_1;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN10_2 {
	_LIST_ENTRY InLoadOrderLinks;											//0x0
	_LIST_ENTRY InMemoryOrderLinks;											//0x10
	_LIST_ENTRY InInitializationOrderLinks;									//0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	_UNICODE_STRING FullDllName;											//0x48
	_UNICODE_STRING BaseDllName;											//0x58
	union {
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct {
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	_LIST_ENTRY HashLinks;												    //0x70
	ULONG TimeDateStamp;                                                    //0x80
	_ACTIVATION_CONTEXT* EntryPointActivationContext;			            //0x88
	VOID* Lock;                                                             //0x90
	_LDR_DDAG_NODE* DdagNode;											    //0x98
	_LIST_ENTRY NodeModuleLink;				                                //0xa0
	VOID* LoadContext;						                                //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	_RTL_BALANCED_NODE BaseAddressIndexNode;								//0xc8
	_RTL_BALANCED_NODE MappingInfoIndexNode;								//0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	_LARGE_INTEGER LoadTime;												//0x100
	ULONG BaseNameHashValue;                                                //0x108
	_LDR_DLL_LOAD_REASON LoadReason;										//0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY_WIN10_2, * PLDR_DATA_TABLE_ENTRY_WIN10_2;

#if !defined(AppObject)
enum class AppObject
{
	ACEHelper = 1,
	ACEHelper_GZP,
	LeagueClient,
	LeagueClientUx,
	LeagueofLegends,
	GZSkins,
	Client
};
#endif

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 {
	PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG ExceptionDirectorySize;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY_64, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_64 {
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	ULONG Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY_64 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE_64, * PRTL_INVERTED_FUNCTION_TABLE_64;


#if !defined(_HANDLE_OBJECT)
typedef struct _HANDLE_OBJECT
{
	HANDLE Object;
	bool	Close;
} HANDLE_OBJECT, * PHANDLE_OBJECT;
#endif

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 {
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG SEHandlerCount;
	PVOID NextEntrySEHandlerTableEncoded;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32;

typedef _RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 _RTL_INVERTED_FUNCTION_TABLE_ENTRY, RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;


typedef struct _RTL_INVERTED_FUNCTION_TABLE_WIN7_32 {
	ULONG Count;
	ULONG MaxCount;
	ULONG Overflow;
	ULONG NextEntrySEHandlerTableEncoded;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE_WIN7_32, * PRTL_INVERTED_FUNCTION_TABLE_WIN7_32;

typedef RTL_INVERTED_FUNCTION_TABLE_WIN7_32 _RTL_INVERTED_FUNCTION_TABLE, RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;

typedef struct _TLS_ENTRY {
	LIST_ENTRY            TlsEntryLinks;
	IMAGE_TLS_DIRECTORY   TlsDirectory;
	PLDR_DATA_TABLE_ENTRY ModuleEntry;
} TLS_ENTRY, * PTLS_ENTRY;

typedef VOID(__stdcall* RtlRbRemoveNode_T)(IN PRTL_RB_TREE Tree, IN PRTL_BALANCED_NODE Node);

typedef VOID(NTAPI* RtlRbInsertNodeEx_T) (IN PRTL_RB_TREE Tree, IN PRTL_BALANCED_NODE Parent, IN BOOLEAN Right, OUT PRTL_BALANCED_NODE Node);

typedef enum _PROCESS_TLS_INFORMATION_TYPE {
	ProcessTlsReplaceIndex,
	ProcessTlsReplaceVector,
	MaxProcessTlsOperation
} PROCESS_TLS_INFORMATION_TYPE, * PPROCESS_TLS_INFORMATION_TYPE;

typedef struct _THREAD_TLS_INFORMATION {
	ULONG Flags;

	union {
		PVOID* TlsVector;
		PVOID TlsModulePointer;
	};

	HANDLE ThreadId;
} THREAD_TLS_INFORMATION, * PTHREAD_TLS_INFORMATION;

typedef struct _PROCESS_TLS_INFORMATION {
	ULONG Reserved;
	PROCESS_TLS_INFORMATION_TYPE OperationType;
	ULONG ThreadDataCount;

	union {
		ULONG TlsIndex;
		ULONG TlsVectorLength;
	};

	THREAD_TLS_INFORMATION ThreadData[ANYSIZE_ARRAY];
} PROCESS_TLS_INFORMATION, * PPROCESS_TLS_INFORMATION;
#if !defined(InitializePointerObject)
#define InitializePointerObject(Object,Ptr,type,level,page,pHandle) { \
	(Object)->Handle = Ptr;          \
    (Object)->Type = type;          \
    (Object)->Close = 0;           \
    (Object)->uLength = sizeof( OBJECT_DATA );          \
    (Object)->Level = level;           \
    (Object)->ProcessHandle = pHandle;          \
    (Object)->Page = page;           \
}
#endif

#if !defined(InitializeObjectAttributes)
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->uLength = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->hRootDirectory = r;                             \
	(p)->uAttributes = a;                                \
	(p)->pObjectName = n;                                \
	(p)->pSecurityDescriptor = s;                        \
	(p)->pSecurityQualityOfService = 0;               \
}
#endif

#if !defined(InitializeSecurityQuality)
#define InitializeSecurityQuality(Object,a,b,c) { \
	(Object)->Length = sizeof(SECURITY_QUALITY_OF_SERVICE);          \
	(Object)->ImpersonationLevel = a;                             \
	(Object)->ContextTrackingMode = b;                                \
    (Object)->EffectiveOnly = c;                                \
}
#endif

// Privileges

#if !defined(SE_MIN_WELL_KNOWN_PRIVILEGE)
#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#endif

#if !defined(SE_CREATE_TOKEN_PRIVILEGE)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#endif

#if !defined(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#endif

#if !defined(SE_LOCK_MEMORY_PRIVILEGE)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#endif

#if !defined(SE_INCREASE_QUOTA_PRIVILEGE)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#endif

#if !defined(SE_MACHINE_ACCOUNT_PRIVILEGE)
#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#endif

#if !defined(SE_TCB_PRIVILEGE)
#define SE_TCB_PRIVILEGE (7L)
#endif

#if !defined(SE_SECURITY_PRIVILEGE)
#define SE_SECURITY_PRIVILEGE (8L)
#endif

#if !defined(SE_TAKE_OWNERSHIP_PRIVILEGE)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#endif

#if !defined(SE_LOAD_DRIVER_PRIVILEGE)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#endif

#if !defined(SE_SYSTEM_PROFILE_PRIVILEGE)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#endif

#if !defined(SE_SYSTEMTIME_PRIVILEGE)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#endif

#if !defined(SE_PROF_SINGLE_PROCESS_PRIVILEGE)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#endif

#if !defined(SE_INC_BASE_PRIORITY_PRIVILEGE)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#endif

#if !defined(SE_CREATE_PAGEFILE_PRIVILEGE)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#endif

#if !defined(SE_CREATE_PERMANENT_PRIVILEGE)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#endif

#if !defined(SE_BACKUP_PRIVILEGE)
#define SE_BACKUP_PRIVILEGE (17L)
#endif

#if !defined(SE_RESTORE_PRIVILEGE)
#define SE_RESTORE_PRIVILEGE (18L)
#endif

#if !defined(SE_SHUTDOWN_PRIVILEGE)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#endif

#if !defined(SE_DEBUG_PRIVILEGE)
#define SE_DEBUG_PRIVILEGE (20L)
#endif

#if !defined(SE_AUDIT_PRIVILEGE)
#define SE_AUDIT_PRIVILEGE (21L)
#endif

#if !defined(SE_SYSTEM_ENVIRONMENT_PRIVILEGE)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#endif

#if !defined(SE_CHANGE_NOTIFY_PRIVILEGE)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#endif

#if !defined(SE_REMOTE_SHUTDOWN_PRIVILEGE)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#endif

#if !defined(SE_UNDOCK_PRIVILEGE)
#define SE_UNDOCK_PRIVILEGE (25L)
#endif

#if !defined(SE_SYNC_AGENT_PRIVILEGE)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#endif

#if !defined(SE_ENABLE_DELEGATION_PRIVILEGE)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#endif

#if !defined(SE_MANAGE_VOLUME_PRIVILEGE)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#endif

#if !defined(SE_IMPERSONATE_PRIVILEGE)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#endif

#if !defined(SE_CREATE_GLOBAL_PRIVILEGE)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#endif

#if !defined(SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#endif

#if !defined(SE_RELABEL_PRIVILEGE)
#define SE_RELABEL_PRIVILEGE (32L)
#endif

#if !defined(SE_INC_WORKING_SET_PRIVILEGE)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#endif

#if !defined(SE_TIME_ZONE_PRIVILEGE)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#endif

#if !defined(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#endif

#if !defined(SE_MAX_WELL_KNOWN_PRIVILEGE)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
#endif



namespace Native
{
#ifdef __cplusplus
	extern "C" {
#endif

		_Must_inspect_result_
			NTSYSAPI
			PVOID
			NTAPI
			RtlCreateHeap(
				_In_ ULONG Flags,
				_In_opt_ PVOID HeapBase,
				_In_opt_ SIZE_T ReserveSize,
				_In_opt_ SIZE_T CommitSize,
				_In_opt_ PVOID Lock,
				_In_opt_ PRTL_HEAP_PARAMETERS Parameters
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtDuplicateObject(
				HANDLE SourceProcessHandle,
				HANDLE SourceHandle,
				HANDLE TargetProcessHandle,
				PHANDLE TargetHandle,
				ACCESS_MASK DesiredAccess,
				ULONG HandleAttributes,
				ULONG Options
			);

		NTSYSAPI
			PVOID
			NTAPI
			RtlDestroyHeap(
				_In_ _Post_invalid_ PVOID HeapHandle
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtTerminateProcess(
				HANDLE ProcessHandle,
				NTSTATUS ExitStatus
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtCreateSection(
				OUT PHANDLE SectionHandle,
				IN ACCESS_MASK DesiredAccess,
				IN POBJECT_ATTRIBUTES ObjectAttributes,
				IN PLARGE_INTEGER SectionSize OPTIONAL,
				IN ULONG Protect,
				IN ULONG Attributes,
				IN HANDLE FileHandle
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtQueryVirtualMemory(
				IN            HANDLE  ProcessHandle,
				IN OPTIONAL  PVOID BaseAddress,
				IN            MEMORY_INFORMATION_CLASS MemoryInformationClass,
				OUT           PVOID MemoryInformation,
				IN            SIZE_T MemoryInformationLength,
				OUT OPTIONAL PSIZE_T ReturnLength
			);

		NTSYSAPI
			NTSTATUS
			NTAPI NtResumeThread(
				IN HANDLE ThreadHandle,
				OUT PULONG PreviousSuspendCount OPTIONAL
			);

		NTSYSAPI
			NTSTATUS
			NTAPI NtSuspendThread(
				IN HANDLE ThreadHandle,
				OUT PULONG PreviousSuspendCount OPTIONAL
			);

		NTSYSAPI
			NTSTATUS
			NTAPI NtAllocateVirtualMemory(
				IN      HANDLE    ProcessHandle,
				_Out_ PVOID* BaseAddress,
				IN      ULONG_PTR ZeroBits,
				_Out_ PSIZE_T   RegionSize,
				IN      ULONG     AllocationType,
				IN      ULONG     Protect
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtSetInformationThread(
				HANDLE          ThreadHandle,
				THREADINFOCLASS ThreadInformationClass,
				PVOID           ThreadInformation,
				ULONG           ThreadInformationLength
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtDuplicateToken(
				_In_ HANDLE             ExistingTokenHandle,
				_In_ ACCESS_MASK        DesiredAccess,
				_In_  POBJECT_ATTRIBUTES ObjectAttributes,
				_In_  BOOLEAN            EffectiveOnly,
				_In_  TOKEN_TYPE         TokenType,
				_Out_ PHANDLE            NewTokenHandle
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtQueryInformationToken(
				_In_  HANDLE                  TokenHandle,
				_In_  TOKEN_INFORMATION_CLASS TokenInformationClass,
				_Out_ PVOID                   TokenInformation,
				_In_  ULONG                   TokenInformationLength,
				_Out_ PULONG                  ReturnLength
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtSetInformationToken(
				_In_ HANDLE                  TokenHandle,
				_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
				_In_ PVOID                   TokenInformation,
				_In_ ULONG                   TokenInformationLength
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtOpenThread(
				_Out_ PHANDLE            ThreadHandle,
				_In_  ACCESS_MASK        DesiredAccess,
				_In_  POBJECT_ATTRIBUTES ObjectAttributes,
				_In_  PCLIENT_ID         ClientId
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlImpersonateSelf(
				IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtWaitForSingleObject(
				IN HANDLE			hObject,
				IN BOOL				fAlertable,
				IN PLARGE_INTEGER	pliTimeout
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtGetContextThread(
				_In_ HANDLE hThread,
				_Inout_ LPCONTEXT lpContext
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtSetContextThread(
				_In_ HANDLE hThread,
				_In_ CONST CONTEXT* lpContext
			);

		NTSYSAPI
			PVOID
			NTAPI
			RtlImageDirectoryEntryToData(
				PVOID BaseAddress,
				BOOLEAN MappedAsImage,
				USHORT Directory,
				PULONG Size);

		NTSYSAPI
			VOID
			NTAPI
			DbgBreakPoint();

		NTSYSAPI
			VOID
			NTAPI
			DbgUserBreakPoint();

		NTSYSAPI
			NTSTATUS
			NTAPI
			LdrUnlockLoaderLock(
				_In_ ULONG Flags,
				_Inout_ ULONG_PTR Cookie
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtOpenFile(
				OUT PHANDLE            FileHandle,
				IN  ACCESS_MASK        DesiredAccess,
				IN  POBJECT_ATTRIBUTES ObjectAttributes,
				OUT PIO_STATUS_BLOCK   IoStatusBlock,
				IN  ULONG              ShareAccess,
				IN  ULONG              OpenOptions
			);

		NTSYSAPI 
			VOID 
			NTAPI 
			RtlClearBits(
			_In_ PRTL_BITMAP BitMapHeader,
			_In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
			_In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear
		);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtOpenProcessToken(
				HANDLE ProcessHandle,
				ACCESS_MASK DesiredAccess,
				PHANDLE TokenHandle
			);

		NTSYSAPI
			VOID
			NTAPI
			RtlSetLastWin32Error(IN ULONG LastError);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtCreateThreadEx(
				PHANDLE ThreadHandle,
				ACCESS_MASK DesiredAccess,
				LPVOID ObjectAttributes,
				HANDLE ProcessHandle,
				LPTHREAD_START_ROUTINE lpStartAddress,
				LPVOID lpParameter,
				BOOL CreateSuspended,
				DWORD dwStackZeroBits,
				DWORD dwSizeOfStackCommit,
				DWORD dwSizeOfStackReserve,
				LPVOID lpBytesBuffer
			);

		NTSYSAPI
			ULONG
			NTAPI
			RtlNtStatusToDosError(
				NTSTATUS	status
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtCreateFile(
				OUT PHANDLE FileHandle,
				IN ACCESS_MASK DesiredAccess,
				IN POBJECT_ATTRIBUTES ObjectAttributes,
				OUT PIO_STATUS_BLOCK IoStatusBlock,
				IN OPTIONAL PLARGE_INTEGER AllocationSize,
				IN ULONG FileAttributes,
				IN ULONG ShareAccess,
				IN ULONG CreateDisposition,
				IN ULONG CreateOptions,
				IN OPTIONAL PVOID EaBuffer,
				IN ULONG EaLength
			);

		_Success_(return)
			NTSYSAPI
			BOOLEAN
			NTAPI
			RtlFreeHeap(
				_In_ PVOID HeapHandle,
				_In_opt_ ULONG Flags,
				_Frees_ptr_opt_ PVOID BaseAddress
			);

		NTSYSAPI
			VOID
			NTAPI
			RtlFreeUnicodeString(
				_In_ PUNICODE_STRING UnicodeString
			);

		NTSYSAPI
			BOOLEAN
			NTAPI
			RtlDosPathNameToNtPathName_U(
				IN PCWSTR			DosName,
				OUT PUNICODE_STRING	NtName,
				OUT PCWSTR* DosFilePath OPTIONAL,
				OUT PUNICODE_STRING	NtFilePath OPTIONAL
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtAdjustPrivilegesToken(
				HANDLE TokenHandle,
				BOOLEAN DisableAllPrivileges,
				PTOKEN_PRIVILEGES NewState,
				ULONG BufferLength,
				PTOKEN_PRIVILEGES PreviousState,
				PULONG ReturnLength
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlImageNtHeaderEx(
				_In_ ULONG Flags,
				_In_ PVOID Base,
				_In_ ULONG64 Size,
				_Out_ PIMAGE_NT_HEADERS* OutHeaders
			);

		NTSYSAPI
			PIMAGE_NT_HEADERS
			NTAPI
			RtlImageNtHeader(
				IN PVOID Base
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtSuspendProcess(
				_In_ HANDLE ProcessHandle
			);

		NTSYSAPI
			VOID
			NTAPI
			RtlGetNtVersionNumbers(
				OUT DWORD * MajorVersion,
				OUT DWORD * MinorVersion,
				OUT DWORD * BuildNumber
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtResumeProcess(
				_In_ HANDLE ProcessHandle
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlInitUnicodeStringEx(
				PUNICODE_STRING DestinationString,
				PCWSTR SourceString
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtQueryInformationProcess(
				__in    HANDLE ProcessHandle,
				__in    PROCESSINFOCLASS ProcessInformationClass,
				__out   PVOID ProcessInformation,
				__in    ULONG ProcessInformationLength,
				__out_opt PULONG ReturnLength
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtFlushInstructionCache(
				_In_ HANDLE ProcessHandle,
				_In_ PVOID BaseAddress,
				_In_ SIZE_T NumberOfBytesToFlush
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtWriteVirtualMemory(
				HANDLE ProcessHandle,
				PVOID BaseAddress,
				PVOID Buffer,
				SIZE_T NumberOfBytesToWrite,
				PSIZE_T NumberOfBytesWritten
			);

		NTSYSAPI 
			VOID 
			NTAPI 
			RtlAcquireSRWLockExclusive(
			_Inout_ PRTL_SRWLOCK SRWLock
		);

		NTSYSAPI
			VOID
			NTAPI
			RtlInitUnicodeString(
				PUNICODE_STRING DestinationString,
				PCWSTR SourceString
			);


		_Must_inspect_result_
			_Ret_maybenull_
			_Post_writable_byte_size_(Size)
			NTSYSAPI
			PVOID
			NTAPI
			RtlAllocateHeap(
				_In_ PVOID HeapHandle,
				_In_opt_ ULONG Flags,
				_In_ SIZE_T Size
			);


		NTSTATUS
			NTAPI
			NtOpenProcess(
				OUT PHANDLE ProcessHandle,
				IN ACCESS_MASK DesiredAccess,
				IN POBJECT_ATTRIBUTES ObjectAttributes,
				IN OPTIONAL PCLIENT_ID ClientId
			);

		NTSYSAPI 
			PVOID 
			NTAPI 
			RtlImageDirectoryEntryToData(
			PVOID BaseAddress,
			BOOLEAN MappedAsImage,
			USHORT 	Directory,
			PULONG 	Size
		);

		NTSYSAPI 
			PVOID 
			NTAPI 
			RtlEncodeSystemPointer(
				PVOID Pointer
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlInitAnsiStringEx(
				OUT PANSI_STRING DestinationString,
				IN LPCSTR SourceString OPTIONAL
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlAnsiStringToUnicodeString(
				OUT PUNICODE_STRING DestinationString,
				IN PANSI_STRING SourceString,
				IN BOOLEAN AllocateDestinationString
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtReadFile(
				HANDLE FileHandle,
				HANDLE Event,
				PIO_APC_ROUTINE ApcRoutine,
				PVOID ApcContext,
				PIO_STATUS_BLOCK IoStatusBlock,
				PVOID Buffer,
				ULONG Length,
				PLARGE_INTEGER ByteOffset,
				PULONG Key
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtLockVirtualMemory(
				HANDLE ProcessHandle,
				PVOID* BaseAddress,
				PSIZE_T NumberOfBytesToLock,
				ULONG MapType);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtSetInformationProcess(
				IN HANDLE			hProcess,
				IN PROCESSINFOCLASS	ProcessInformationClass,
				OUT PVOID			pProcessInformation,
				IN ULONG			uProcessInformationLength
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtQueryInformationFile(
				IN HANDLE					FileHandle,
				OUT PIO_STATUS_BLOCK		IoStatusBlock,
				OUT PVOID					FileInformation,
				IN ULONG					Length,
				IN FILE_INFORMATION_CLASS	FileInformationClass
			);

		NTSYSAPI
			NTSTATUS
			NTAPI NtQueryObject(
				_In_opt_  HANDLE                   Handle,
				_In_            OBJECT_INFORMATION_CLASS ObjectInformationClass,
				_In_opt_ PVOID                    ObjectInformation,
				_In_           ULONG                    ObjectInformationLength,
				_In_opt_ PULONG                   ReturnLength
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			LdrGetDllHandle(
				_In_opt_ PWSTR DllPath,
				_In_opt_ PULONG DllCharacteristics,
				_In_ PUNICODE_STRING DllName,
				_Out_ HMODULE* DllHandle
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			LdrLoadDll(
				PWSTR SearchPathW,
				PULONG LoadFlags,
				PUNICODE_STRING Name,
				HMODULE* BaseAddress
			);


		NTSYSAPI
			VOID
			NTAPI
			RtlInitAnsiString(
				_Out_ PANSI_STRING DestinationString,
				_In_opt_z_ __drv_aliasesMem LPCSTR SourceString
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			LdrGetProcedureAddress(
				IN PVOID DllHandle,
				IN OPTIONAL PANSI_STRING ProcedureName,
				IN OPTIONAL ULONG ProcedureNumber,
				OUT PVOID* ProcedureAddress
			);


		NTSYSAPI
			BOOLEAN
			NTAPI
			RtlCreateUnicodeStringFromAsciiz(
				_Out_ PUNICODE_STRING DestinationString,
				_In_ PCSTR SourceString
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtUnmapViewOfSection(
				IN HANDLE	hProcess,
				IN PVOID	pBaseAddress
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			LdrUnloadDll(
				PVOID BaseAddress
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtReadVirtualMemory(
				IN HANDLE ProcessHandle,
				IN PVOID BaseAddress,
				OUT PVOID Buffer,
				IN ULONG BufferLength,
				OUT PULONG ReturnLength OPTIONAL
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtMapViewOfSection(
				_In_        HANDLE          SectionHandle,
				_In_        HANDLE          ProcessHandle,
				_Inout_     PVOID* BaseAddress,
				_In_        ULONG_PTR       ZeroBits,
				_In_        SIZE_T          CommitSize,
				_Inout_opt_ PLARGE_INTEGER  SectionOffset,
				_Inout_     PSIZE_T         ViewSize,
				_In_        _SECTION_INHERIT InheritDisposition,
				_In_        ULONG           AllocationType,
				_In_        ULONG           Win32Protect
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtProtectVirtualMemory(
				IN HANDLE ProcessHandle,
				IN OUT PVOID* BaseAddress,
				IN OUT PULONG ProtectSize,
				IN ULONG NewProtect,
				OUT PULONG OldProtect
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			NtClose(
				IN HANDLE	hObject
			);


		NTSYSAPI
			VOID
			NTAPI
			RtlReleasePrivilege(
				IN PVOID ReturnedState
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlAcquirePrivilege(
				ULONG Privilege,
				BOOLEAN Enable,
				BOOLEAN CurrentThread,
				PBOOLEAN Enabled
			);


		NTSYSAPI
			NTSTATUS
			NTAPI
			RtlAdjustPrivilege(
				ULONG Privilege,
				BOOLEAN Enable,
				BOOLEAN CurrentThread,
				PBOOLEAN Enabled
			);

		NTSYSAPI
			NTSTATUS
			NTAPI
			NtFreeVirtualMemory(
				HANDLE ProcessHandle,
				PVOID* BaseAddress,
				PSIZE_T RegionSize,
				ULONG FreeType
			);

		NTSYSAPI
			NTSTATUS 
			NTAPI 
			NtQueryVirtualMemory(
			_In_ HANDLE ProcessHandle,
			_In_opt_ PVOID BaseAddress,
			_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
			_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
			_In_ SIZE_T MemoryInformationLength,
			_Out_opt_ PSIZE_T ReturnLength
		);

		NTSYSAPI 
			DECLSPEC_NORETURN 
			VOID 
			NTAPI 
			RtlRaiseStatus(
			_In_ NTSTATUS Status
		);

		NTSYSAPI 
			NTSTATUS 
			NTAPI 
			NtQuerySystemTime(
				PLARGE_INTEGER SystemTime
			);

		NTSYSAPI 
			NTSTATUS 
			NTAPI RtlHashUnicodeString(
			IN  PCUNICODE_STRING String,
			IN  BOOLEAN          CaseInSensitive,
			IN  ULONG            HashAlgorithm,
			OUT PULONG           HashValue
		);

		NTSYSAPI 
			VOID 
			NTAPI 
			RtlReleaseSRWLockExclusive(
			_Inout_ PRTL_SRWLOCK SRWLock
		);

		NTSYSAPI 
			NTSTATUS 
			NTAPI 
			LdrLockLoaderLock(
				size_t Flags, 
				size_t* State,
				size_t* Cookie
			);

		_Success_(return != -1) 
			NTSYSAPI 
			ULONG 
			NTAPI 
			RtlFindClearBitsAndSet(
			_In_ PRTL_BITMAP BitMapHeader,
			_In_ ULONG NumberToFind,
			_In_ ULONG HintIndex
		);

#ifdef __cplusplus
	}
#endif
}

#if !defined(mLdrLoadDll)
static NTSTATUS(__stdcall* mLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, HMODULE*) =
(NTSTATUS(__stdcall*)(PWSTR, PULONG, PUNICODE_STRING, HMODULE*))(&Native::LdrLoadDll);
#endif

static HANDLE(__stdcall* mCreateRw)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) =
(HANDLE(__stdcall*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)) & CreateFileW;

static HANDLE(__stdcall* mCreateRwA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) =
(HANDLE(__stdcall*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)) & CreateFileA;

static BOOL(__stdcall* mReadRw)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) =
(BOOL(__stdcall*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)) & ReadFile;

static BOOL(__stdcall* mGetFileSizeEx)(HANDLE, PLARGE_INTEGER) =
(BOOL(__stdcall*)(HANDLE, PLARGE_INTEGER)) & GetFileSizeEx;

static BOOL(__stdcall* mSetRawEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) =
(BOOL(__stdcall*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD)) & SetFilePointerEx;

static HFILE(__stdcall* mOpenFile)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) =
(HFILE(__stdcall*)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)) & OpenFile;

static BOOL(__stdcall* mCreatePeW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) =
(BOOL(__stdcall*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)) & CreateProcessW;

#define RtlClearBit(BitMapHeader,BitNumber) Native::RtlClearBits((BitMapHeader),(BitNumber),1)

#define RtlProcessHeap() (NtCurrentTeb()->Peb->ProcessHeap)

#define NtCurrentProcessId() (NtCurrentTeb()->ClientId.UniqueProcess)

#define NtCurrentThreadId() (NtCurrentTeb()->ClientId.UniqueThread)

#endif
