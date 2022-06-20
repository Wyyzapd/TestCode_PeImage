#ifndef _NTSTATUS_
#define _NTSTATUS_

#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <cstdint>

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef WIN32_NO_STATUS 

#define NT_SUCCESS(Status) ((LONG)(Status) >= 0)
#define NT_INFORMATION(Status) ((ULONG)(Status) >> 30 == 1)
#define NT_WARNING(Status) ((ULONG)(Status) >> 30 == 2)
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)

#define STATUS_SUCCESS                          ((LONG)0x00000000L) // ntsubauth

#define VA_TO_RVA(B,P) ((ULONG_PTR)(((PCHAR)(P)) - ((PCHAR)(B))))

#define RVA_TO_VA(B,O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))

#define RtlOffsetToPointer(B, O) ((PVOID)(((ULONG_PTR)(B)) + ((ULONG_PTR)(O))))

#define OBJ_INHERIT             0x00000002L
#define OBJ_HANDLE_TAGBITS			0x00000003L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

#define FACILITY_USB_ERROR_CODE          0x10
#define FACILITY_TRANSACTION             0x19
#define FACILITY_TERMINAL_SERVER         0xA
#define FACILITY_SXS_ERROR_CODE          0x15
#define FACILITY_RPC_STUBS               0x3
#define FACILITY_RPC_RUNTIME             0x2
#define FACILITY_IO_ERROR_CODE           0x4
#define FACILITY_HID_ERROR_CODE          0x11
#define FACILITY_FIREWIRE_ERROR_CODE     0x12
#define FACILITY_DEBUGGER                0x1
#define FACILITY_COMMONLOG_ERROR_CODE    0x1A
#define FACILITY_CLUSTER_ERROR_CODE      0x13
#define FACILITY_ACPI_ERROR_CODE         0x14

#define VerifyValue(a,b) (DWORD(a) == DWORD(b)) 
//
// Get module Section header
//
#define GetSection(x) (PIMAGE_SECTION_HEADER(DWORD(x) + sizeof(IMAGE_NT_HEADERS)))
//
// Get module NT header
//
#define GetNtHeader(base) (PIMAGE_NT_HEADERS)((DWORD)base + (DWORD)((PIMAGE_DOS_HEADER)base)->e_lfanew)
//
// Numeric conversion
//
#define LongtoUint32(Value) ((uint32_t)(((Value) << 32) >> 32))

#define Ptr64toPtr32(Value) ((PVOID)((((ULONG64)Value) << 32) >> 32))

#define Ulong64toUlong(Value) ((ULONG)(((Value) << 32) >> 32))

#define Ulong64toUlongPtr(Value) ((SIZE_T)(((Value) << 32) >> 32))

#define Ulong64toNtStatus(Value) ((LONG)(((Value) << 32) >> 32))
//
// Own ThreadHandle
//
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )   
//
// Own ProcessHandle
//
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
//
// Define the severity codes
//
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_ERROR            0x3

#define FLAG_REFERENCE		0
#define FLAG_DEREFERENCE	1
//If this flag is specified, the input image buffer will not be checked before loading.
#define LOAD_FLAGS_PASS_IMAGE_CHECK					0x40000000

#define LDR_HASH_TABLE_ENTRIES		32

#define HASH_STRING_ALGORITHM_DEFAULT 0

#define HASH_STRING_ALGORITHM_X65599 1

#define MEMORY_MODULE_SIGNATURE 0x00aabbcc11ffee00
//If this flag is specified, all subsequent flags will be ignored.
//Also, will be incompatible with Win32 API.
#define LOAD_FLAGS_NOT_MAP_DLL						0x10000000
//Hook for dotnet dlls
#define LOAD_FLAGS_HOOK_DOT_NET						0x00000010
//If this flag is specified, this routine will not fail even if the call to LdrpTlsData fails.
#define LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS			0x20000000
//Dont call LdrpHandleTlsData routine if this flag is specified.
#define LOAD_FLAGS_NOT_HANDLE_TLS					0x00000008
//If this flag is specified, exception handling will not be supported.
#define LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION		0x00000001
//If this flag is specified, LdrLoadDllMemory and LdrUnloadDllMemory will not use reference counting.
//If you try to load the same module, it will fail. When you unload the module,
//	it will be unloaded without checking the reference count.
#define LOAD_FLAGS_NOT_USE_REFERENCE_COUNT			0x00000002
//If this flag is specified, DllName and DllFullName cannot be nullptr,
//	they can be arbitrary strings without having to be correct file names and paths.
//Otherwise, DllName and DllFullName will use random names if they are nullptr.
//For compatibility with GetModuleHandle, DllName and DllFullName should be guaranteed to always end in ".dll"
#define LOAD_FLAGS_USE_DLL_NAME						0x00000004
//
// MessageId: STATUS_WAIT_1
//
// MessageText:
//
//  STATUS_WAIT_1
//
#define STATUS_WAIT_1                    ((LONG)0x00000001L)

//
// MessageId: STATUS_WAIT_2
//
// MessageText:
//
//  STATUS_WAIT_2
//
#define STATUS_WAIT_2                    ((LONG)0x00000002L)

//
// MessageId: STATUS_WAIT_3
//
// MessageText:
//
//  STATUS_WAIT_3
//
#define STATUS_WAIT_3                    ((LONG)0x00000003L)

//
// MessageId: STATUS_WAIT_63
//
// MessageText:
//
//  STATUS_WAIT_63
//
#define STATUS_WAIT_63                   ((LONG)0x0000003FL)


//
// The success status codes 128 - 191 are reserved for wait completion
// status with an abandoned mutant object.
//
#define STATUS_ABANDONED                        ((LONG)0x00000080L)

//
// MessageId: STATUS_ABANDONED_WAIT_63
//
// MessageText:
//
//  STATUS_ABANDONED_WAIT_63
//
#define STATUS_ABANDONED_WAIT_63         ((LONG)0x000000BFL)

//
// MessageId: STATUS_KERNEL_APC
//
// MessageText:
//
//  STATUS_KERNEL_APC
//
#define STATUS_KERNEL_APC                ((LONG)0x00000100L)

//
// MessageId: STATUS_ALERTED
//
// MessageText:
//
//  STATUS_ALERTED
//
#define STATUS_ALERTED                   ((LONG)0x00000101L)

//
// MessageId: STATUS_REPARSE
//
// MessageText:
//
//  A reparse should be performed by the Object Manager since the name of the file resulted in a symbolic link.
//
#define STATUS_REPARSE                   ((LONG)0x00000104L)

//
// MessageId: STATUS_MORE_ENTRIES
//
// MessageText:
//
//  Returned by enumeration APIs to indicate more information is available to successive calls.
//
#define STATUS_MORE_ENTRIES              ((LONG)0x00000105L)

//
// MessageId: STATUS_NOT_ALL_ASSIGNED
//
// MessageText:
//
//  Indicates not all privileges referenced are assigned to the caller.
//  This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned.
//
#define STATUS_NOT_ALL_ASSIGNED          ((LONG)0x00000106L)

//
// MessageId: STATUS_SOME_NOT_MAPPED
//
// MessageText:
//
//  Some of the information to be translated has not been translated.
//
#define STATUS_SOME_NOT_MAPPED           ((LONG)0x00000107L)

//
// MessageId: STATUS_OPLOCK_BREAK_IN_PROGRESS
//
// MessageText:
//
//  An open/create operation completed while an oplock break is underway.
//
#define STATUS_OPLOCK_BREAK_IN_PROGRESS  ((LONG)0x00000108L)

//
// MessageId: STATUS_VOLUME_MOUNTED
//
// MessageText:
//
//  A new volume has been mounted by a file system.
//
#define STATUS_VOLUME_MOUNTED            ((LONG)0x00000109L)

//
// MessageId: STATUS_RXACT_COMMITTED
//
// MessageText:
//
//  This success level status indicates that the transaction state already exists for the registry sub-tree, but that a transaction commit was previously aborted.
//  The commit has now been completed.
//
#define STATUS_RXACT_COMMITTED           ((LONG)0x0000010AL)

//
// MessageId: STATUS_NOTIFY_CLEANUP
//
// MessageText:
//
//  This indicates that a notify change request has been completed due to closing the handle which made the notify change request.
//
#define STATUS_NOTIFY_CLEANUP            ((LONG)0x0000010BL)

//
// MessageId: STATUS_NOTIFY_ENUM_DIR
//
// MessageText:
//
//  This indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer.
//  The caller now needs to enumerate the files to find the changes.
//
#define STATUS_NOTIFY_ENUM_DIR           ((LONG)0x0000010CL)

//
// MessageId: STATUS_NO_QUOTAS_FOR_ACCOUNT
//
// MessageText:
//
//  {No Quotas}
//  No system quota limits are specifically set for this account.
//
#define STATUS_NO_QUOTAS_FOR_ACCOUNT     ((LONG)0x0000010DL)

//
// MessageId: STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED
//
// MessageText:
//
//  {Connect Failure on Primary Transport}
//  An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed.
//  The computer WAS able to connect on a secondary transport.
//
#define STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED ((LONG)0x0000010EL)

//
// MessageId: STATUS_PAGE_FAULT_TRANSITION
//
// MessageText:
//
//  Page fault was a transition fault.
//
#define STATUS_PAGE_FAULT_TRANSITION     ((LONG)0x00000110L)

//
// MessageId: STATUS_PAGE_FAULT_DEMAND_ZERO
//
// MessageText:
//
//  Page fault was a demand zero fault.
//
#define STATUS_PAGE_FAULT_DEMAND_ZERO    ((LONG)0x00000111L)

//
// MessageId: STATUS_PAGE_FAULT_COPY_ON_WRITE
//
// MessageText:
//
//  Page fault was a demand zero fault.
//
#define STATUS_PAGE_FAULT_COPY_ON_WRITE  ((LONG)0x00000112L)

//
// MessageId: STATUS_PAGE_FAULT_GUARD_PAGE
//
// MessageText:
//
//  Page fault was a demand zero fault.
//
#define STATUS_PAGE_FAULT_GUARD_PAGE     ((LONG)0x00000113L)

//
// MessageId: STATUS_PAGE_FAULT_PAGING_FILE
//
// MessageText:
//
//  Page fault was satisfied by reading from a secondary storage device.
//
#define STATUS_PAGE_FAULT_PAGING_FILE    ((LONG)0x00000114L)

//
// MessageId: STATUS_CACHE_PAGE_LOCKED
//
// MessageText:
//
//  Cached page was locked during operation.
//
#define STATUS_CACHE_PAGE_LOCKED         ((LONG)0x00000115L)

//
// MessageId: STATUS_CRASH_DUMP
//
// MessageText:
//
//  Crash dump exists in paging file.
//
#define STATUS_CRASH_DUMP                ((LONG)0x00000116L)

//
// MessageId: STATUS_BUFFER_ALL_ZEROS
//
// MessageText:
//
//  Specified buffer contains all zeros.
//
#define STATUS_BUFFER_ALL_ZEROS          ((LONG)0x00000117L)

//
// MessageId: STATUS_REPARSE_OBJECT
//
// MessageText:
//
//  A reparse should be performed by the Object Manager since the name of the file resulted in a symbolic link.
//
#define STATUS_REPARSE_OBJECT            ((LONG)0x00000118L)

//
// MessageId: STATUS_RESOURCE_REQUIREMENTS_CHANGED
//
// MessageText:
//
//  The device has succeeded a query-stop and its resource requirements have changed.
//
#define STATUS_RESOURCE_REQUIREMENTS_CHANGED ((LONG)0x00000119L)

//
// MessageId: STATUS_TRANSLATION_COMPLETE
//
// MessageText:
//
//  The translator has translated these resources into the global space and no further translations should be performed.
//
#define STATUS_TRANSLATION_COMPLETE      ((LONG)0x00000120L)

//
// MessageId: STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY
//
// MessageText:
//
//  The directory service evaluated group memberships locally, as it was unable to contact a global catalog server.
//
#define STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY ((LONG)0x00000121L)

//
// MessageId: STATUS_NOTHING_TO_TERMINATE
//
// MessageText:
//
//  A process being terminated has no threads to terminate.
//
#define STATUS_NOTHING_TO_TERMINATE      ((LONG)0x00000122L)

//
// MessageId: STATUS_PROCESS_NOT_IN_JOB
//
// MessageText:
//
//  The specified process is not part of a job.
//
#define STATUS_PROCESS_NOT_IN_JOB        ((LONG)0x00000123L)

//
// MessageId: STATUS_PROCESS_IN_JOB
//
// MessageText:
//
//  The specified process is part of a job.
//
#define STATUS_PROCESS_IN_JOB            ((LONG)0x00000124L)

//
// MessageId: STATUS_VOLSNAP_HIBERNATE_READY
//
// MessageText:
//
//  {Volume Shadow Copy Service}
//  The system is now ready for hibernation.
//
#define STATUS_VOLSNAP_HIBERNATE_READY   ((LONG)0x00000125L)

//
// MessageId: STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY
//
// MessageText:
//
//  A file system or file system filter driver has successfully completed an FsFilter operation.
//
#define STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY ((LONG)0x00000126L)


/////////////////////////////////////////////////////////////////////////
//
// Standard Information values
//
/////////////////////////////////////////////////////////////////////////

//
// MessageId: STATUS_OBJECT_NAME_EXISTS
//
// MessageText:
//
//  {Object Exists}
//  An attempt was made to create an object and the object name already existed.
//
#define STATUS_OBJECT_NAME_EXISTS        ((LONG)0x40000000L)

//
// MessageId: STATUS_THREAD_WAS_SUSPENDED
//
// MessageText:
//
//  {Thread Suspended}
//  A thread termination occurred while the thread was suspended. The thread was resumed, and termination proceeded.
//
#define STATUS_THREAD_WAS_SUSPENDED      ((LONG)0x40000001L)

//
// MessageId: STATUS_WORKING_SET_LIMIT_RANGE
//
// MessageText:
//
//  {Working Set Range Error}
//  An attempt was made to set the working set minimum or maximum to values which are outside of the allowable range.
//
#define STATUS_WORKING_SET_LIMIT_RANGE   ((LONG)0x40000002L)

//
// MessageId: STATUS_IMAGE_NOT_AT_BASE
//
// MessageText:
//
//  {Image Relocated}
//  An image file could not be mapped at the address specified in the image file. Local fixups must be performed on this image.
//
#define STATUS_IMAGE_NOT_AT_BASE         ((LONG)0x40000003L)

//
// MessageId: STATUS_RXACT_STATE_CREATED
//
// MessageText:
//
//  This informational level status indicates that a specified registry sub-tree transaction state did not yet exist and had to be created.
//
#define STATUS_RXACT_STATE_CREATED       ((LONG)0x40000004L)

//
// MessageId: STATUS_LOCAL_USER_SESSION_KEY
//
// MessageText:
//
//  {Local Session Key}
//  A user session key was requested for a local RPC connection. The session key returned is a constant value and not unique to this connection.
//
#define STATUS_LOCAL_USER_SESSION_KEY    ((LONG)0x40000006L)

//
// MessageId: STATUS_BAD_CURRENT_DIRECTORY
//
// MessageText:
//
//  {Invalid Current Directory}
//  The process cannot switch to the startup current directory %hs.
//  Select OK to set current directory to %hs, or select CANCEL to exit.
//
#define STATUS_BAD_CURRENT_DIRECTORY     ((LONG)0x40000007L)

//
// MessageId: STATUS_SERIAL_MORE_WRITES
//
// MessageText:
//
//  {Serial IOCTL Complete}
//  A serial I/O operation was completed by another write to a serial port.
//  (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)
//
#define STATUS_SERIAL_MORE_WRITES        ((LONG)0x40000008L)

//
// MessageId: STATUS_REGISTRY_RECOVERED
//
// MessageText:
//
//  {Registry Recovery}
//  One of the files containing the system's Registry data had to be recovered by use of a log or alternate copy.
//  The recovery was successful.
//
#define STATUS_REGISTRY_RECOVERED        ((LONG)0x40000009L)

//
// MessageId: STATUS_FT_READ_RECOVERY_FROM_BACKUP
//
// MessageText:
//
//  {Redundant Read}
//  To satisfy a read request, the NT fault-tolerant file system successfully read the requested data from a redundant copy.
//  This was done because the file system encountered a failure on a member of the fault-tolerant volume, but was unable to reassign the failing area of the device.
//
#define STATUS_FT_READ_RECOVERY_FROM_BACKUP ((LONG)0x4000000AL)

//
// MessageId: STATUS_FT_WRITE_RECOVERY
//
// MessageText:
//
//  {Redundant Write}
//  To satisfy a write request, the NT fault-tolerant file system successfully wrote a redundant copy of the information.
//  This was done because the file system encountered a failure on a member of the fault-tolerant volume, but was not able to reassign the failing area of the device.
//
#define STATUS_FT_WRITE_RECOVERY         ((LONG)0x4000000BL)

//
// MessageId: STATUS_SERIAL_COUNTER_TIMEOUT
//
// MessageText:
//
//  {Serial IOCTL Timeout}
//  A serial I/O operation completed because the time-out period expired.
//  (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)
//
#define STATUS_SERIAL_COUNTER_TIMEOUT    ((LONG)0x4000000CL)

//
// MessageId: STATUS_NULL_LM_PASSWORD
//
// MessageText:
//
//  {Password Too Complex}
//  The Windows password is too complex to be converted to a LAN Manager password.
//  The LAN Manager password returned is a NULL string.
//
#define STATUS_NULL_LM_PASSWORD          ((LONG)0x4000000DL)

//
// MessageId: STATUS_IMAGE_MACHINE_TYPE_MISMATCH
//
// MessageText:
//
//  {Machine Type Mismatch}
//  The image file %hs is valid, but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.
//
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH ((LONG)0x4000000EL)

//
// MessageId: STATUS_RECEIVE_PARTIAL
//
// MessageText:
//
//  {Partial Data Received}
//  The network transport returned partial data to its client. The remaining data will be sent later.
//
#define STATUS_RECEIVE_PARTIAL           ((LONG)0x4000000FL)

//
// MessageId: STATUS_RECEIVE_EXPEDITED
//
// MessageText:
//
//  {Expedited Data Received}
//  The network transport returned data to its client that was marked as expedited by the remote system.
//
#define STATUS_RECEIVE_EXPEDITED         ((LONG)0x40000010L)

//
// MessageId: STATUS_RECEIVE_PARTIAL_EXPEDITED
//
// MessageText:
//
//  {Partial Expedited Data Received}
//  The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.
//
#define STATUS_RECEIVE_PARTIAL_EXPEDITED ((LONG)0x40000011L)

//
// MessageId: STATUS_EVENT_DONE
//
// MessageText:
//
//  {TDI Event Done}
//  The TDI indication has completed successfully.
//
#define STATUS_EVENT_DONE                ((LONG)0x40000012L)

//
// MessageId: STATUS_EVENT_PENDING
//
// MessageText:
//
//  {TDI Event Pending}
//  The TDI indication has entered the pending state.
//
#define STATUS_EVENT_PENDING             ((LONG)0x40000013L)

//
// MessageId: STATUS_CHECKING_FILE_SYSTEM
//
// MessageText:
//
//  Checking file system on %wZ
//
#define STATUS_CHECKING_FILE_SYSTEM      ((LONG)0x40000014L)

//
// MessageId: STATUS_FATAL_APP_EXIT
//
// MessageText:
//
//  {Fatal Application Exit}
//  %hs
//
//#define STATUS_FATAL_APP_EXIT            ((LONG)0x40000015L)

//
// MessageId: STATUS_PREDEFINED_HANDLE
//
// MessageText:
//
//  The specified registry key is referenced by a predefined handle.
//
#define STATUS_PREDEFINED_HANDLE         ((LONG)0x40000016L)

//
// MessageId: STATUS_WAS_UNLOCKED
//
// MessageText:
//
//  {Page Unlocked}
//  The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.
//
#define STATUS_WAS_UNLOCKED              ((LONG)0x40000017L)

//
// MessageId: STATUS_SERVICE_NOTIFICATION
//
// MessageText:
//
//  %hs
//
#define STATUS_SERVICE_NOTIFICATION      ((LONG)0x40000018L)

//
// MessageId: STATUS_WAS_LOCKED
//
// MessageText:
//
//  {Page Locked}
//  One of the pages to lock was already locked.
//
#define STATUS_WAS_LOCKED                ((LONG)0x40000019L)

//
// MessageId: STATUS_LOG_HARD_ERROR
//
// MessageText:
//
//  Application popup: %1 : %2
//
#define STATUS_LOG_HARD_ERROR            ((LONG)0x4000001AL)

//
// MessageId: STATUS_ALREADY_WIN32
//
// MessageText:
//
//  STATUS_ALREADY_WIN32
//
#define STATUS_ALREADY_WIN32             ((LONG)0x4000001BL)

//
// MessageId: STATUS_WX86_UNSIMULATE
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_UNSIMULATE           ((LONG)0x4000001CL)

//
// MessageId: STATUS_WX86_CONTINUE
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_CONTINUE             ((LONG)0x4000001DL)

//
// MessageId: STATUS_WX86_SINGLE_STEP
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_SINGLE_STEP          ((LONG)0x4000001EL)

//
// MessageId: STATUS_WX86_BREAKPOINT
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_BREAKPOINT           ((LONG)0x4000001FL)

//
// MessageId: STATUS_WX86_EXCEPTION_CONTINUE
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_EXCEPTION_CONTINUE   ((LONG)0x40000020L)

//
// MessageId: STATUS_WX86_EXCEPTION_LASTCHANCE
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_EXCEPTION_LASTCHANCE ((LONG)0x40000021L)

//
// MessageId: STATUS_WX86_EXCEPTION_CHAIN
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_EXCEPTION_CHAIN      ((LONG)0x40000022L)

//
// MessageId: STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE
//
// MessageText:
//
//  {Machine Type Mismatch}
//  The image file %hs is valid, but is for a machine type other than the current machine.
//
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE ((LONG)0x40000023L)

//
// MessageId: STATUS_NO_YIELD_PERFORMED
//
// MessageText:
//
//  A yield execution was performed and no thread was available to run.
//
#define STATUS_NO_YIELD_PERFORMED        ((LONG)0x40000024L)

//
// MessageId: STATUS_TIMER_RESUME_IGNORED
//
// MessageText:
//
//  The resumable flag to a timer API was ignored.
//
#define STATUS_TIMER_RESUME_IGNORED      ((LONG)0x40000025L)

//
// MessageId: STATUS_ARBITRATION_UNHANDLED
//
// MessageText:
//
//  The arbiter has deferred arbitration of these resources to its parent
//
#define STATUS_ARBITRATION_UNHANDLED     ((LONG)0x40000026L)

//
// MessageId: STATUS_CARDBUS_NOT_SUPPORTED
//
// MessageText:
//
//  The device "%hs" has detected a CardBus card in its slot, but the firmware on this system is not configured to allow the CardBus controller to be run in CardBus mode.
//  The operating system will currently accept only 16-bit (R2) pc-cards on this controller.
//
#define STATUS_CARDBUS_NOT_SUPPORTED     ((LONG)0x40000027L)

//
// MessageId: STATUS_WX86_CREATEWX86TIB
//
// MessageText:
//
//  Exception status code used by Win32 x86 emulation subsystem.
//
#define STATUS_WX86_CREATEWX86TIB        ((LONG)0x40000028L)

//
// MessageId: STATUS_MP_PROCESSOR_MISMATCH
//
// MessageText:
//
//  The CPUs in this multiprocessor system are not all the same revision level.  To use all processors the operating system restricts itself to the features of the least capable processor in the system.  Should problems occur with this system, contact
//  the CPU manufacturer to see if this mix of processors is supported.
//
#define STATUS_MP_PROCESSOR_MISMATCH     ((LONG)0x40000029L)

//
// MessageId: STATUS_HIBERNATED
//
// MessageText:
//
//  The system was put into hibernation.
//
#define STATUS_HIBERNATED                ((LONG)0x4000002AL)    

//
// MessageId: STATUS_RESUME_HIBERNATION
//
// MessageText:
//
//  The system was resumed from hibernation.
//
#define STATUS_RESUME_HIBERNATION        ((LONG)0x4000002BL)    

//
// MessageId: STATUS_FIRMWARE_UPDATED
//
// MessageText:
//
//  Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3].
//
#define STATUS_FIRMWARE_UPDATED          ((LONG)0x4000002CL)

//
// MessageId: STATUS_DRIVERS_LEAKING_LOCKED_PAGES
//
// MessageText:
//
//  A device driver is leaking locked I/O pages causing system degradation.  The system has automatically enabled tracking code in order to try and catch the culprit.
//
#define STATUS_DRIVERS_LEAKING_LOCKED_PAGES ((LONG)0x4000002DL)

//
// MessageId: DBG_REPLY_LATER
//
// MessageText:
//
//  Debugger will reply later.
//
//#define DBG_REPLY_LATER                  ((LONG)0x40010001L)

//
// MessageId: DBG_UNABLE_TO_PROVIDE_HANDLE
//
// MessageText:
//
//  Debugger can not provide handle.
//
#define DBG_UNABLE_TO_PROVIDE_HANDLE     ((LONG)0x40010002L)


/////////////////////////////////////////////////////////////////////////
//
// Standard Warning values
//
//
// Note:  Do NOT use the value 0x80000000L, as this is a non-portable value
//        for the NT_SUCCESS macro. Warning values start with a code of 1.
//
/////////////////////////////////////////////////////////////////////////

//
// MessageId: STATUS_BUFFER_OVERFLOW
//
// MessageText:
//
//  {Buffer Overflow}
//  The data was too large to fit into the specified buffer.
//
#define STATUS_BUFFER_OVERFLOW           ((LONG)0x80000005L)

//
// MessageId: STATUS_NO_MORE_FILES
//
// MessageText:
//
//  {No More Files}
//  No more files were found which match the file specification.
//
#define STATUS_NO_MORE_FILES             ((LONG)0x80000006L)

//
// MessageId: STATUS_WAKE_SYSTEM_DEBUGGER
//
// MessageText:
//
//  {Kernel Debugger Awakened}
//  the system debugger was awakened by an interrupt.
//
#define STATUS_WAKE_SYSTEM_DEBUGGER      ((LONG)0x80000007L)

//
// MessageId: STATUS_HANDLES_CLOSED
//
// MessageText:
//
//  {Handles Closed}
//  Handles to objects have been automatically closed as a result of the requested operation.
//
#define STATUS_HANDLES_CLOSED            ((LONG)0x8000000AL)

//
// MessageId: STATUS_NO_INHERITANCE
//
// MessageText:
//
//  {Non-Inheritable ACL}
//  An access control list (ACL) contains no components that can be inherited.
//
#define STATUS_NO_INHERITANCE            ((LONG)0x8000000BL)

//
// MessageId: STATUS_GUID_SUBSTITUTION_MADE
//
// MessageText:
//
//  {GUID Substitution}
//  During the translation of a global identifier (GUID) to a Windows security ID (SID), no administratively-defined GUID prefix was found.
//  A substitute prefix was used, which will not compromise system security.
//  However, this may provide a more restrictive access than intended.
//
#define STATUS_GUID_SUBSTITUTION_MADE    ((LONG)0x8000000CL)

//
// MessageId: STATUS_PARTIAL_COPY
//
// MessageText:
//
//  {Partial Copy}
//  Due to protection conflicts not all the requested bytes could be copied.
//
#define STATUS_PARTIAL_COPY              ((LONG)0x8000000DL)

//
// MessageId: STATUS_DEVICE_PAPER_EMPTY
//
// MessageText:
//
//  {Out of Paper}
//  The printer is out of paper.
//
#define STATUS_DEVICE_PAPER_EMPTY        ((LONG)0x8000000EL)

//
// MessageId: STATUS_DEVICE_POWERED_OFF
//
// MessageText:
//
//  {Device Power Is Off}
//  The printer power has been turned off.
//
#define STATUS_DEVICE_POWERED_OFF        ((LONG)0x8000000FL)

//
// MessageId: STATUS_DEVICE_OFF_LINE
//
// MessageText:
//
//  {Device Offline}
//  The printer has been taken offline.
//
#define STATUS_DEVICE_OFF_LINE           ((LONG)0x80000010L)

//
// MessageId: STATUS_DEVICE_BUSY
//
// MessageText:
//
//  {Device Busy}
//  The device is currently busy.
//
#define STATUS_DEVICE_BUSY               ((LONG)0x80000011L)

//
// MessageId: STATUS_NO_MORE_EAS
//
// MessageText:
//
//  {No More EAs}
//  No more extended attributes (EAs) were found for the file.
//
#define STATUS_NO_MORE_EAS               ((LONG)0x80000012L)

//
// MessageId: STATUS_INVALID_EA_NAME
//
// MessageText:
//
//  {Illegal EA}
//  The specified extended attribute (EA) name contains at least one illegal character.
//
#define STATUS_INVALID_EA_NAME           ((LONG)0x80000013L)

//
// MessageId: STATUS_EA_LIST_INCONSISTENT
//
// MessageText:
//
//  {Inconsistent EA List}
//  The extended attribute (EA) list is inconsistent.
//
#define STATUS_EA_LIST_INCONSISTENT      ((LONG)0x80000014L)

//
// MessageId: STATUS_INVALID_EA_FLAG
//
// MessageText:
//
//  {Invalid EA Flag}
//  An invalid extended attribute (EA) flag was set.
//
#define STATUS_INVALID_EA_FLAG           ((LONG)0x80000015L)

//
// MessageId: STATUS_VERIFY_REQUIRED
//
// MessageText:
//
//  {Verifying Disk}
//  The media has changed and a verify operation is in progress so no reads or writes may be performed to the device, except those used in the verify operation.
//
#define STATUS_VERIFY_REQUIRED           ((LONG)0x80000016L)

//
// MessageId: STATUS_EXTRANEOUS_INFORMATION
//
// MessageText:
//
//  {Too Much Information}
//  The specified access control list (ACL) contained more information than was expected.
//
#define STATUS_EXTRANEOUS_INFORMATION    ((LONG)0x80000017L)

//
// MessageId: STATUS_RXACT_COMMIT_NECESSARY
//
// MessageText:
//
//  This warning level status indicates that the transaction state already exists for the registry sub-tree, but that a transaction commit was previously aborted.
//  The commit has NOT been completed, but has not been rolled back either (so it may still be committed if desired).
//
#define STATUS_RXACT_COMMIT_NECESSARY    ((LONG)0x80000018L)

//
// MessageId: STATUS_NO_MORE_ENTRIES
//
// MessageText:
//
//  {No More Entries}
//  No more entries are available from an enumeration operation.
//
#define STATUS_NO_MORE_ENTRIES           ((LONG)0x8000001AL)

//
// MessageId: STATUS_FILEMARK_DETECTED
//
// MessageText:
//
//  {Filemark Found}
//  A filemark was detected.
//
#define STATUS_FILEMARK_DETECTED         ((LONG)0x8000001BL)

//
// MessageId: STATUS_MEDIA_CHANGED
//
// MessageText:
//
//  {Media Changed}
//  The media may have changed.
//
#define STATUS_MEDIA_CHANGED             ((LONG)0x8000001CL)

//
// MessageId: STATUS_BUS_RESET
//
// MessageText:
//
//  {I/O Bus Reset}
//  An I/O bus reset was detected.
//
#define STATUS_BUS_RESET                 ((LONG)0x8000001DL)

//
// MessageId: STATUS_END_OF_MEDIA
//
// MessageText:
//
//  {End of Media}
//  The end of the media was encountered.
//
#define STATUS_END_OF_MEDIA              ((LONG)0x8000001EL)

//
// MessageId: STATUS_BEGINNING_OF_MEDIA
//
// MessageText:
//
//  Beginning of tape or partition has been detected.
//
#define STATUS_BEGINNING_OF_MEDIA        ((LONG)0x8000001FL)

//
// MessageId: STATUS_MEDIA_CHECK
//
// MessageText:
//
//  {Media Changed}
//  The media may have changed.
//
#define STATUS_MEDIA_CHECK               ((LONG)0x80000020L)

//
// MessageId: STATUS_SETMARK_DETECTED
//
// MessageText:
//
//  A tape access reached a setmark.
//
#define STATUS_SETMARK_DETECTED          ((LONG)0x80000021L)

//
// MessageId: STATUS_NO_DATA_DETECTED
//
// MessageText:
//
//  During a tape access, the end of the data written is reached.
//
#define STATUS_NO_DATA_DETECTED          ((LONG)0x80000022L)

//
// MessageId: STATUS_REDIRECTOR_HAS_OPEN_HANDLES
//
// MessageText:
//
//  The redirector is in use and cannot be unloaded.
//
#define STATUS_REDIRECTOR_HAS_OPEN_HANDLES ((LONG)0x80000023L)

//
// MessageId: STATUS_SERVER_HAS_OPEN_HANDLES
//
// MessageText:
//
//  The server is in use and cannot be unloaded.
//
#define STATUS_SERVER_HAS_OPEN_HANDLES   ((LONG)0x80000024L)

//
// MessageId: STATUS_ALREADY_DISCONNECTED
//
// MessageText:
//
//  The specified connection has already been disconnected.
//
#define STATUS_ALREADY_DISCONNECTED      ((LONG)0x80000025L)

//
// MessageId: STATUS_CLEANER_CARTRIDGE_INSTALLED
//
// MessageText:
//
//  A cleaner cartridge is present in the tape library.
//
#define STATUS_CLEANER_CARTRIDGE_INSTALLED ((LONG)0x80000027L)

//
// MessageId: STATUS_PLUGPLAY_QUERY_VETOED
//
// MessageText:
//
//  The Plug and Play query operation was not successful.
//
#define STATUS_PLUGPLAY_QUERY_VETOED     ((LONG)0x80000028L)

//
// MessageId: STATUS_REGISTRY_HIVE_RECOVERED
//
// MessageText:
//
//  {Registry Hive Recovered}
//  Registry hive (file):
//  %hs
//  was corrupted and it has been recovered. Some data might have been lost.
//
#define STATUS_REGISTRY_HIVE_RECOVERED   ((LONG)0x8000002AL)

//
// MessageId: STATUS_DLL_MIGHT_BE_INSECURE
//
// MessageText:
//
//  The application is attempting to run executable code from the module %hs.  This may be insecure.  An alternative, %hs, is available.  Should the application use the secure module %hs?
//
#define STATUS_DLL_MIGHT_BE_INSECURE     ((LONG)0x8000002BL)

//
// MessageId: STATUS_DLL_MIGHT_BE_INCOMPATIBLE
//
// MessageText:
//
//  The application is loading executable code from the module %hs.  This is secure, but may be incompatible with previous releases of the operating system.  An alternative, %hs, is available.  Should the application use the secure module %hs?
//
#define STATUS_DLL_MIGHT_BE_INCOMPATIBLE ((LONG)0x8000002CL)

//
// MessageId: STATUS_CLUSTER_NODE_ALREADY_UP
//
// MessageText:
//
//  The cluster node is already up.
//
#define STATUS_CLUSTER_NODE_ALREADY_UP   ((LONG)0x80130001L)

//
// MessageId: STATUS_CLUSTER_NODE_ALREADY_DOWN
//
// MessageText:
//
//  The cluster node is already down.
//
#define STATUS_CLUSTER_NODE_ALREADY_DOWN ((LONG)0x80130002L)

//
// MessageId: STATUS_CLUSTER_NETWORK_ALREADY_ONLINE
//
// MessageText:
//
//  The cluster network is already online.
//
#define STATUS_CLUSTER_NETWORK_ALREADY_ONLINE ((LONG)0x80130003L)

//
// MessageId: STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE
//
// MessageText:
//
//  The cluster network is already offline.
//
#define STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE ((LONG)0x80130004L)

//
// MessageId: STATUS_CLUSTER_NODE_ALREADY_MEMBER
//
// MessageText:
//
//  The cluster node is already a member of the cluster.
//
#define STATUS_CLUSTER_NODE_ALREADY_MEMBER ((LONG)0x80130005L)



/////////////////////////////////////////////////////////////////////////
//
//  Standard Error values
//
/////////////////////////////////////////////////////////////////////////

//
// MessageId: STATUS_UNSUCCESSFUL
//
// MessageText:
//
//  {Operation Failed}
//  The requested operation was unsuccessful.
//
#define STATUS_UNSUCCESSFUL              ((LONG)0xC0000001L)

//
// MessageId: STATUS_INVALID_INFO_CLASS
//
// MessageText:
//
//  {Invalid Parameter}
//  The specified information class is not a valid information class for the specified object.
//
#define STATUS_INVALID_INFO_CLASS        ((LONG)0xC0000003L)    // ntsubauth

//
// MessageId: STATUS_INFO_LENGTH_MISMATCH
//
// MessageText:
//
//  The specified information record length does not match the length required for the specified information class.
//
#define STATUS_INFO_LENGTH_MISMATCH      ((LONG)0xC0000004L)

//
// MessageId: STATUS_PAGEFILE_QUOTA
//
// MessageText:
//
//  The pagefile quota for the process has been exhausted.
//
#define STATUS_PAGEFILE_QUOTA            ((LONG)0xC0000007L)

//
// MessageId: STATUS_BAD_INITIAL_STACK
//
// MessageText:
//
//  An invalid initial stack was specified in a call to NtCreateThread.
//
#define STATUS_BAD_INITIAL_STACK         ((LONG)0xC0000009L)

//
// MessageId: STATUS_BAD_INITIAL_PC
//
// MessageText:
//
//  An invalid initial start address was specified in a call to NtCreateThread.
//
#define STATUS_BAD_INITIAL_PC            ((LONG)0xC000000AL)

//
// MessageId: STATUS_INVALID_CID
//
// MessageText:
//
//  An invalid Client ID was specified.
//
#define STATUS_INVALID_CID               ((LONG)0xC000000BL)

//
// MessageId: STATUS_TIMER_NOT_CANCELED
//
// MessageText:
//
//  An attempt was made to cancel or set a timer that has an associated APC and the subject thread is not the thread that originally set the timer with an associated APC routine.
//
#define STATUS_TIMER_NOT_CANCELED        ((LONG)0xC000000CL)

//
// MessageId: STATUS_NO_SUCH_DEVICE
//
// MessageText:
//
//  A device which does not exist was specified.
//
#define STATUS_NO_SUCH_DEVICE            ((LONG)0xC000000EL)

//
// MessageId: STATUS_NO_SUCH_FILE
//
// MessageText:
//
//  {File Not Found}
//  The file %hs does not exist.
//
#define STATUS_NO_SUCH_FILE              ((LONG)0xC000000FL)

//
// MessageId: STATUS_END_OF_FILE
//
// MessageText:
//
//  The end-of-file marker has been reached. There is no valid data in the file beyond this marker.
//
#define STATUS_END_OF_FILE               ((LONG)0xC0000011L)

//
// MessageId: STATUS_WRONG_VOLUME
//
// MessageText:
//
//  {Wrong Volume}
//  The wrong volume is in the drive.
//  Please insert volume %hs into drive %hs.
//
#define STATUS_WRONG_VOLUME              ((LONG)0xC0000012L)

//
// MessageId: STATUS_NO_MEDIA_IN_DEVICE
//
// MessageText:
//
//  {No Disk}
//  There is no disk in the drive.
//  Please insert a disk into drive %hs.
//
#define STATUS_NO_MEDIA_IN_DEVICE        ((LONG)0xC0000013L)

//
// MessageId: STATUS_UNRECOGNIZED_MEDIA
//
// MessageText:
//
//  {Unknown Disk Format}
//  The disk in drive %hs is not formatted properly.
//  Please check the disk, and reformat if necessary.
//
#define STATUS_UNRECOGNIZED_MEDIA        ((LONG)0xC0000014L)

//
// MessageId: STATUS_NONEXISTENT_SECTOR
//
// MessageText:
//
//  {Sector Not Found}
//  The specified sector does not exist.
//
#define STATUS_NONEXISTENT_SECTOR        ((LONG)0xC0000015L)

//
// MessageId: STATUS_MORE_PROCESSING_REQUIRED
//
// MessageText:
//
//  {Still Busy}
//  The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
//
#define STATUS_MORE_PROCESSING_REQUIRED  ((LONG)0xC0000016L)

//
// MessageId: STATUS_CONFLICTING_ADDRESSES
//
// MessageText:
//
//  {Conflicting Address Range}
//  The specified address range conflicts with the address space.
//
#define STATUS_CONFLICTING_ADDRESSES     ((LONG)0xC0000018L)

//
// MessageId: STATUS_NOT_MAPPED_VIEW
//
// MessageText:
//
//  Address range to unmap is not a mapped view.
//
#define STATUS_NOT_MAPPED_VIEW           ((LONG)0xC0000019L)

//
// MessageId: STATUS_UNABLE_TO_FREE_VM
//
// MessageText:
//
//  Virtual memory cannot be freed.
//
#define STATUS_UNABLE_TO_FREE_VM         ((LONG)0xC000001AL)

//
// MessageId: STATUS_UNABLE_TO_DELETE_SECTION
//
// MessageText:
//
//  Specified section cannot be deleted.
//
#define STATUS_UNABLE_TO_DELETE_SECTION  ((LONG)0xC000001BL)

//
// MessageId: STATUS_INVALID_SYSTEM_SERVICE
//
// MessageText:
//
//  An invalid system service was specified in a system service call.
//
#define STATUS_INVALID_SYSTEM_SERVICE    ((LONG)0xC000001CL)

//
// MessageId: STATUS_INVALID_LOCK_SEQUENCE
//
// MessageText:
//
//  {Invalid Lock Sequence}
//  An attempt was made to execute an invalid lock sequence.
//
#define STATUS_INVALID_LOCK_SEQUENCE     ((LONG)0xC000001EL)

//
// MessageId: STATUS_INVALID_VIEW_SIZE
//
// MessageText:
//
//  {Invalid Mapping}
//  An attempt was made to create a view for a section which is bigger than the section.
//
#define STATUS_INVALID_VIEW_SIZE         ((LONG)0xC000001FL)

//
// MessageId: STATUS_INVALID_FILE_FOR_SECTION
//
// MessageText:
//
//  {Bad File}
//  The attributes of the specified mapping file for a section of memory cannot be read.
//
#define STATUS_INVALID_FILE_FOR_SECTION  ((LONG)0xC0000020L)

//
// MessageId: STATUS_ALREADY_COMMITTED
//
// MessageText:
//
//  {Already Committed}
//  The specified address range is already committed.
//
#define STATUS_ALREADY_COMMITTED         ((LONG)0xC0000021L)

//
// MessageId: STATUS_ACCESS_DENIED
//
// MessageText:
//
//  {Access Denied}
//  A process has requested access to an object, but has not been granted those access rights.
//
#define STATUS_ACCESS_DENIED             ((LONG)0xC0000022L)

//
// MessageId: STATUS_BUFFER_TOO_SMALL
//
// MessageText:
//
//  {Buffer Too Small}
//  The buffer is too small to contain the entry. No information has been written to the buffer.
//
#define STATUS_BUFFER_TOO_SMALL          ((LONG)0xC0000023L)

//
// MessageId: STATUS_OBJECT_TYPE_MISMATCH
//
// MessageText:
//
//  {Wrong Type}
//  There is a mismatch between the type of object required by the requested operation and the type of object that is specified in the request.
//
#define STATUS_OBJECT_TYPE_MISMATCH      ((LONG)0xC0000024L)

//
// MessageId: STATUS_UNWIND
//
// MessageText:
//
//  Unwind exception code.
//
#define STATUS_UNWIND                    ((LONG)0xC0000027L)

//
// MessageId: STATUS_BAD_STACK
//
// MessageText:
//
//  An invalid or unaligned stack was encountered during an unwind operation.
//
#define STATUS_BAD_STACK                 ((LONG)0xC0000028L)

//
// MessageId: STATUS_INVALID_UNWIND_TARGET
//
// MessageText:
//
//  An invalid unwind target was encountered during an unwind operation.
//
#define STATUS_INVALID_UNWIND_TARGET     ((LONG)0xC0000029L)

//
// MessageId: STATUS_NOT_LOCKED
//
// MessageText:
//
//  An attempt was made to unlock a page of memory which was not locked.
//
#define STATUS_NOT_LOCKED                ((LONG)0xC000002AL)

//
// MessageId: STATUS_PARITY_ERROR
//
// MessageText:
//
//  Device parity error on I/O operation.
//
#define STATUS_PARITY_ERROR              ((LONG)0xC000002BL)

//
// MessageId: STATUS_UNABLE_TO_DECOMMIT_VM
//
// MessageText:
//
//  An attempt was made to decommit uncommitted virtual memory.
//
#define STATUS_UNABLE_TO_DECOMMIT_VM     ((LONG)0xC000002CL)

//
// MessageId: STATUS_NOT_COMMITTED
//
// MessageText:
//
//  An attempt was made to change the attributes on memory that has not been committed.
//
#define STATUS_NOT_COMMITTED             ((LONG)0xC000002DL)

//
// MessageId: STATUS_INVALID_PORT_ATTRIBUTES
//
// MessageText:
//
//  Invalid Object Attributes specified to NtCreatePort or invalid Port Attributes specified to NtConnectPort
//
#define STATUS_INVALID_PORT_ATTRIBUTES   ((LONG)0xC000002EL)

//
// MessageId: STATUS_PORT_MESSAGE_TOO_LONG
//
// MessageText:
//
//  Length of message passed to NtRequestPort or NtRequestWaitReplyPort was longer than the maximum message allowed by the port.
//
#define STATUS_PORT_MESSAGE_TOO_LONG     ((LONG)0xC000002FL)

//
// MessageId: STATUS_INVALID_PARAMETER_MIX
//
// MessageText:
//
//  An invalid combination of parameters was specified.
//
#define STATUS_INVALID_PARAMETER_MIX     ((LONG)0xC0000030L)

//
// MessageId: STATUS_INVALID_QUOTA_LOWER
//
// MessageText:
//
//  An attempt was made to lower a quota limit below the current usage.
//
#define STATUS_INVALID_QUOTA_LOWER       ((LONG)0xC0000031L)

//
// MessageId: STATUS_DISK_CORRUPT_ERROR
//
// MessageText:
//
//  {Corrupt Disk}
//  The file system structure on the disk is corrupt and unusable.
//  Please run the Chkdsk utility on the volume %hs.
//
#define STATUS_DISK_CORRUPT_ERROR        ((LONG)0xC0000032L)

//
// MessageId: STATUS_OBJECT_NAME_INVALID
//
// MessageText:
//
//  Object Name invalid.
//
#define STATUS_OBJECT_NAME_INVALID       ((LONG)0xC0000033L)

//
// MessageId: STATUS_OBJECT_NAME_NOT_FOUND
//
// MessageText:
//
//  Object Name not found.
//
#define STATUS_OBJECT_NAME_NOT_FOUND     ((LONG)0xC0000034L)

//
// MessageId: STATUS_OBJECT_NAME_COLLISION
//
// MessageText:
//
//  Object Name already exists.
//
#define STATUS_OBJECT_NAME_COLLISION     ((LONG)0xC0000035L)

//
// MessageId: STATUS_PORT_DISCONNECTED
//
// MessageText:
//
//  Attempt to send a message to a disconnected communication port.
//
#define STATUS_PORT_DISCONNECTED         ((LONG)0xC0000037L)

//
// MessageId: STATUS_DEVICE_ALREADY_ATTACHED
//
// MessageText:
//
//  An attempt was made to attach to a device that was already attached to another device.
//
#define STATUS_DEVICE_ALREADY_ATTACHED   ((LONG)0xC0000038L)

//
// MessageId: STATUS_OBJECT_PATH_INVALID
//
// MessageText:
//
//  Object Path Component was not a directory object.
//
#define STATUS_OBJECT_PATH_INVALID       ((LONG)0xC0000039L)

//
// MessageId: STATUS_OBJECT_PATH_NOT_FOUND
//
// MessageText:
//
//  {Path Not Found}
//  The path %hs does not exist.
//
#define STATUS_OBJECT_PATH_NOT_FOUND     ((LONG)0xC000003AL)

//
// MessageId: STATUS_OBJECT_PATH_SYNTAX_BAD
//
// MessageText:
//
//  Object Path Component was not a directory object.
//
#define STATUS_OBJECT_PATH_SYNTAX_BAD    ((LONG)0xC000003BL)

//
// MessageId: STATUS_DATA_OVERRUN
//
// MessageText:
//
//  {Data Overrun}
//  A data overrun error occurred.
//
#define STATUS_DATA_OVERRUN              ((LONG)0xC000003CL)

//
// MessageId: STATUS_DATA_LATE_ERROR
//
// MessageText:
//
//  {Data Late}
//  A data late error occurred.
//
#define STATUS_DATA_LATE_ERROR           ((LONG)0xC000003DL)

//
// MessageId: STATUS_DATA_ERROR
//
// MessageText:
//
//  {Data Error}
//  An error in reading or writing data occurred.
//
#define STATUS_DATA_ERROR                ((LONG)0xC000003EL)

//
// MessageId: STATUS_CRC_ERROR
//
// MessageText:
//
//  {Bad CRC}
//  A cyclic redundancy check (CRC) checksum error occurred.
//
#define STATUS_CRC_ERROR                 ((LONG)0xC000003FL)

//
// MessageId: STATUS_SECTION_TOO_BIG
//
// MessageText:
//
//  {Section Too Large}
//  The specified section is too big to map the file.
//
#define STATUS_SECTION_TOO_BIG           ((LONG)0xC0000040L)

//
// MessageId: STATUS_PORT_CONNECTION_REFUSED
//
// MessageText:
//
//  The NtConnectPort request is refused.
//
#define STATUS_PORT_CONNECTION_REFUSED   ((LONG)0xC0000041L)

//
// MessageId: STATUS_INVALID_PORT_HANDLE
//
// MessageText:
//
//  The type of port handle is invalid for the operation requested.
//
#define STATUS_INVALID_PORT_HANDLE       ((LONG)0xC0000042L)

//
// MessageId: STATUS_SHARING_VIOLATION
//
// MessageText:
//
//  A file cannot be opened because the share access flags are incompatible.
//
#define STATUS_SHARING_VIOLATION         ((LONG)0xC0000043L)

//
// MessageId: STATUS_QUOTA_EXCEEDED
//
// MessageText:
//
//  Insufficient quota exists to complete the operation
//
#define STATUS_QUOTA_EXCEEDED            ((LONG)0xC0000044L)

//
// MessageId: STATUS_INVALID_PAGE_PROTECTION
//
// MessageText:
//
//  The specified page protection was not valid.
//
#define STATUS_INVALID_PAGE_PROTECTION   ((LONG)0xC0000045L)

//
// MessageId: STATUS_MUTANT_NOT_OWNED
//
// MessageText:
//
//  An attempt to release a mutant object was made by a thread that was not the owner of the mutant object.
//
#define STATUS_MUTANT_NOT_OWNED          ((LONG)0xC0000046L)

//
// MessageId: STATUS_SEMAPHORE_LIMIT_EXCEEDED
//
// MessageText:
//
//  An attempt was made to release a semaphore such that its maximum count would have been exceeded.
//
#define STATUS_SEMAPHORE_LIMIT_EXCEEDED  ((LONG)0xC0000047L)

//
// MessageId: STATUS_PORT_ALREADY_SET
//
// MessageText:
//
//  An attempt to set a processes DebugPort or ExceptionPort was made, but a port already exists in the process or
//  an attempt to set a file's CompletionPort made, but a port was already set in the file.
//
#define STATUS_PORT_ALREADY_SET          ((LONG)0xC0000048L)

//
// MessageId: STATUS_SECTION_NOT_IMAGE
//
// MessageText:
//
//  An attempt was made to query image information on a section which does not map an image.
//
#define STATUS_SECTION_NOT_IMAGE         ((LONG)0xC0000049L)

//
// MessageId: STATUS_SUSPEND_COUNT_EXCEEDED
//
// MessageText:
//
//  An attempt was made to suspend a thread whose suspend count was at its maximum.
//
#define STATUS_SUSPEND_COUNT_EXCEEDED    ((LONG)0xC000004AL)

//
// MessageId: STATUS_THREAD_IS_TERMINATING
//
// MessageText:
//
//  An attempt was made to suspend a thread that has begun termination.
//
#define STATUS_THREAD_IS_TERMINATING     ((LONG)0xC000004BL)

//
// MessageId: STATUS_BAD_WORKING_SET_LIMIT
//
// MessageText:
//
//  An attempt was made to set the working set limit to an invalid value (minimum greater than maximum, etc).
//
#define STATUS_BAD_WORKING_SET_LIMIT     ((LONG)0xC000004CL)

//
// MessageId: STATUS_INCOMPATIBLE_FILE_MAP
//
// MessageText:
//
//  A section was created to map a file which is not compatible to an already existing section which maps the same file.
//
#define STATUS_INCOMPATIBLE_FILE_MAP     ((LONG)0xC000004DL)

//
// MessageId: STATUS_SECTION_PROTECTION
//
// MessageText:
//
//  A view to a section specifies a protection which is incompatible with the initial view's protection.
//
#define STATUS_SECTION_PROTECTION        ((LONG)0xC000004EL)

//
// MessageId: STATUS_EAS_NOT_SUPPORTED
//
// MessageText:
//
//  An operation involving EAs failed because the file system does not support EAs.
//
#define STATUS_EAS_NOT_SUPPORTED         ((LONG)0xC000004FL)

//
// MessageId: STATUS_EA_TOO_LARGE
//
// MessageText:
//
//  An EA operation failed because EA set is too large.
//
#define STATUS_EA_TOO_LARGE              ((LONG)0xC0000050L)

//
// MessageId: STATUS_NONEXISTENT_EA_ENTRY
//
// MessageText:
//
//  An EA operation failed because the name or EA index is invalid.
//
#define STATUS_NONEXISTENT_EA_ENTRY      ((LONG)0xC0000051L)

//
// MessageId: STATUS_NO_EAS_ON_FILE
//
// MessageText:
//
//  The file for which EAs were requested has no EAs.
//
#define STATUS_NO_EAS_ON_FILE            ((LONG)0xC0000052L)

//
// MessageId: STATUS_EA_CORRUPT_ERROR
//
// MessageText:
//
//  The EA is corrupt and non-readable.
//
#define STATUS_EA_CORRUPT_ERROR          ((LONG)0xC0000053L)

//
// MessageId: STATUS_FILE_LOCK_CONFLICT
//
// MessageText:
//
//  A requested read/write cannot be granted due to a conflicting file lock.
//
#define STATUS_FILE_LOCK_CONFLICT        ((LONG)0xC0000054L)

//
// MessageId: STATUS_LOCK_NOT_GRANTED
//
// MessageText:
//
//  A requested file lock cannot be granted due to other existing locks.
//
#define STATUS_LOCK_NOT_GRANTED          ((LONG)0xC0000055L)

//
// MessageId: STATUS_DELETE_PENDING
//
// MessageText:
//
//  A non close operation has been requested of a file object with a delete pending.
//
#define STATUS_DELETE_PENDING            ((LONG)0xC0000056L)

//
// MessageId: STATUS_CTL_FILE_NOT_SUPPORTED
//
// MessageText:
//
//  An attempt was made to set the control attribute on a file. This attribute is not supported in the target file system.
//
#define STATUS_CTL_FILE_NOT_SUPPORTED    ((LONG)0xC0000057L)

//
// MessageId: STATUS_UNKNOWN_REVISION
//
// MessageText:
//
//  Indicates a revision number encountered or specified is not one known by the service. It may be a more recent revision than the service is aware of.
//
#define STATUS_UNKNOWN_REVISION          ((LONG)0xC0000058L)

//
// MessageId: STATUS_REVISION_MISMATCH
//
// MessageText:
//
//  Indicates two revision levels are incompatible.
//
#define STATUS_REVISION_MISMATCH         ((LONG)0xC0000059L)

//
// MessageId: STATUS_INVALID_OWNER
//
// MessageText:
//
//  Indicates a particular Security ID may not be assigned as the owner of an object.
//
#define STATUS_INVALID_OWNER             ((LONG)0xC000005AL)

//
// MessageId: STATUS_INVALID_PRIMARY_GROUP
//
// MessageText:
//
//  Indicates a particular Security ID may not be assigned as the primary group of an object.
//
#define STATUS_INVALID_PRIMARY_GROUP     ((LONG)0xC000005BL)

//
// MessageId: STATUS_NO_IMPERSONATION_TOKEN
//
// MessageText:
//
//  An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.
//
#define STATUS_NO_IMPERSONATION_TOKEN    ((LONG)0xC000005CL)

//
// MessageId: STATUS_CANT_DISABLE_MANDATORY
//
// MessageText:
//
//  A mandatory group may not be disabled.
//
#define STATUS_CANT_DISABLE_MANDATORY    ((LONG)0xC000005DL)

//
// MessageId: STATUS_NO_LOGON_SERVERS
//
// MessageText:
//
//  There are currently no logon servers available to service the logon request.
//
#define STATUS_NO_LOGON_SERVERS          ((LONG)0xC000005EL)

//
// MessageId: STATUS_NO_SUCH_LOGON_SESSION
//
// MessageText:
//
//  A specified logon session does not exist. It may already have been terminated.
//
#define STATUS_NO_SUCH_LOGON_SESSION     ((LONG)0xC000005FL)

//
// MessageId: STATUS_NO_SUCH_PRIVILEGE
//
// MessageText:
//
//  A specified privilege does not exist.
//
#define STATUS_NO_SUCH_PRIVILEGE         ((LONG)0xC0000060L)

//
// MessageId: STATUS_PRIVILEGE_NOT_HELD
//
// MessageText:
//
//  A required privilege is not held by the client.
//
#define STATUS_PRIVILEGE_NOT_HELD        ((LONG)0xC0000061L)

//
// MessageId: STATUS_INVALID_ACCOUNT_NAME
//
// MessageText:
//
//  The name provided is not a properly formed account name.
//
#define STATUS_INVALID_ACCOUNT_NAME      ((LONG)0xC0000062L)

//
// MessageId: STATUS_USER_EXISTS
//
// MessageText:
//
//  The specified user already exists.
//
#define STATUS_USER_EXISTS               ((LONG)0xC0000063L)

//
// MessageId: STATUS_NO_SUCH_USER
//
// MessageText:
//
//  The specified user does not exist.
//
#define STATUS_NO_SUCH_USER              ((LONG)0xC0000064L)     // ntsubauth

//
// MessageId: STATUS_GROUP_EXISTS
//
// MessageText:
//
//  The specified group already exists.
//
#define STATUS_GROUP_EXISTS              ((LONG)0xC0000065L)

//
// MessageId: STATUS_NO_SUCH_GROUP
//
// MessageText:
//
//  The specified group does not exist.
//
#define STATUS_NO_SUCH_GROUP             ((LONG)0xC0000066L)

//
// MessageId: STATUS_MEMBER_IN_GROUP
//
// MessageText:
//
//  The specified user account is already in the specified group account.
//  Also used to indicate a group cannot be deleted because it contains a member.
//
#define STATUS_MEMBER_IN_GROUP           ((LONG)0xC0000067L)

//
// MessageId: STATUS_MEMBER_NOT_IN_GROUP
//
// MessageText:
//
//  The specified user account is not a member of the specified group account.
//
#define STATUS_MEMBER_NOT_IN_GROUP       ((LONG)0xC0000068L)

//
// MessageId: STATUS_LAST_ADMIN
//
// MessageText:
//
//  Indicates the requested operation would disable or delete the last remaining administration account.
//  This is not allowed to prevent creating a situation in which the system cannot be administrated.
//
#define STATUS_LAST_ADMIN                ((LONG)0xC0000069L)

//
// MessageId: STATUS_WRONG_PASSWORD
//
// MessageText:
//
//  When trying to update a password, this return status indicates that the value provided as the current password is not correct.
//
#define STATUS_WRONG_PASSWORD            ((LONG)0xC000006AL)     // ntsubauth

//
// MessageId: STATUS_ILL_FORMED_PASSWORD
//
// MessageText:
//
//  When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords.
//
#define STATUS_ILL_FORMED_PASSWORD       ((LONG)0xC000006BL)

//
// MessageId: STATUS_PASSWORD_RESTRICTION
//
// MessageText:
//
//  When trying to update a password, this status indicates that some password update rule has been violated. For example, the password may not meet length criteria.
//
#define STATUS_PASSWORD_RESTRICTION      ((LONG)0xC000006CL)     // ntsubauth

//
// MessageId: STATUS_LOGON_FAILURE
//
// MessageText:
//
//  The attempted logon is invalid. This is either due to a bad username or authentication information.
//
#define STATUS_LOGON_FAILURE             ((LONG)0xC000006DL)     // ntsubauth

//
// MessageId: STATUS_ACCOUNT_RESTRICTION
//
// MessageText:
//
//  Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).
//
#define STATUS_ACCOUNT_RESTRICTION       ((LONG)0xC000006EL)     // ntsubauth

//
// MessageId: STATUS_INVALID_LOGON_HOURS
//
// MessageText:
//
//  The user account has time restrictions and may not be logged onto at this time.
//
#define STATUS_INVALID_LOGON_HOURS       ((LONG)0xC000006FL)     // ntsubauth

//
// MessageId: STATUS_INVALID_WORKSTATION
//
// MessageText:
//
//  The user account is restricted such that it may not be used to log on from the source workstation.
//
#define STATUS_INVALID_WORKSTATION       ((LONG)0xC0000070L)     // ntsubauth

//
// MessageId: STATUS_PASSWORD_EXPIRED
//
// MessageText:
//
//  The user account's password has expired.
//
#define STATUS_PASSWORD_EXPIRED          ((LONG)0xC0000071L)     // ntsubauth

//
// MessageId: STATUS_ACCOUNT_DISABLED
//
// MessageText:
//
//  The referenced account is currently disabled and may not be logged on to.
//
#define STATUS_ACCOUNT_DISABLED          ((LONG)0xC0000072L)     // ntsubauth

//
// MessageId: STATUS_NONE_MAPPED
//
// MessageText:
//
//  None of the information to be translated has been translated.
//
#define STATUS_NONE_MAPPED               ((LONG)0xC0000073L)

//
// MessageId: STATUS_TOO_MANY_LUIDS_REQUESTED
//
// MessageText:
//
//  The number of LUIDs requested may not be allocated with a single allocation.
//
#define STATUS_TOO_MANY_LUIDS_REQUESTED  ((LONG)0xC0000074L)

//
// MessageId: STATUS_LUIDS_EXHAUSTED
//
// MessageText:
//
//  Indicates there are no more LUIDs to allocate.
//
#define STATUS_LUIDS_EXHAUSTED           ((LONG)0xC0000075L)

//
// MessageId: STATUS_INVALID_SUB_AUTHORITY
//
// MessageText:
//
//  Indicates the sub-authority value is invalid for the particular use.
//
#define STATUS_INVALID_SUB_AUTHORITY     ((LONG)0xC0000076L)

//
// MessageId: STATUS_INVALID_ACL
//
// MessageText:
//
//  Indicates the ACL structure is not valid.
//
#define STATUS_INVALID_ACL               ((LONG)0xC0000077L)

//
// MessageId: STATUS_INVALID_SID
//
// MessageText:
//
//  Indicates the SID structure is not valid.
//
#define STATUS_INVALID_SID               ((LONG)0xC0000078L)

//
// MessageId: STATUS_INVALID_SECURITY_DESCR
//
// MessageText:
//
//  Indicates the SECURITY_DESCRIPTOR structure is not valid.
//
#define STATUS_INVALID_SECURITY_DESCR    ((LONG)0xC0000079L)

//
// MessageId: STATUS_PROCEDURE_NOT_FOUND
//
// MessageText:
//
//  Indicates the specified procedure address cannot be found in the DLL.
//
#define STATUS_PROCEDURE_NOT_FOUND       ((LONG)0xC000007AL)

//
// MessageId: STATUS_INVALID_IMAGE_FORMAT
//
// MessageText:
//
//  {Bad Image}
//  The application or DLL %hs is not a valid Windows image. Please check this against your installation diskette.
//
#define STATUS_INVALID_IMAGE_FORMAT      ((LONG)0xC000007BL)

//
// MessageId: STATUS_NO_TOKEN
//
// MessageText:
//
//  An attempt was made to reference a token that doesn't exist.
//  This is typically done by referencing the token associated with a thread when the thread is not impersonating a client.
//
#define STATUS_NO_TOKEN                  ((LONG)0xC000007CL)

//
// MessageId: STATUS_BAD_INHERITANCE_ACL
//
// MessageText:
//
//  Indicates that an attempt to build either an inherited ACL or ACE was not successful.
//  This can be caused by a number of things. One of the more probable causes is the replacement of a CreatorId with an SID that didn't fit into the ACE or ACL.
//
#define STATUS_BAD_INHERITANCE_ACL       ((LONG)0xC000007DL)

//
// MessageId: STATUS_RANGE_NOT_LOCKED
//
// MessageText:
//
//  The range specified in NtUnlockFile was not locked.
//
#define STATUS_RANGE_NOT_LOCKED          ((LONG)0xC000007EL)

//
// MessageId: STATUS_DISK_FULL
//
// MessageText:
//
//  An operation failed because the disk was full.
//
#define STATUS_DISK_FULL                 ((LONG)0xC000007FL)

//
// MessageId: STATUS_SERVER_DISABLED
//
// MessageText:
//
//  The GUID allocation server is [already] disabled at the moment.
//
#define STATUS_SERVER_DISABLED           ((LONG)0xC0000080L)

//
// MessageId: STATUS_SERVER_NOT_DISABLED
//
// MessageText:
//
//  The GUID allocation server is [already] enabled at the moment.
//
#define STATUS_SERVER_NOT_DISABLED       ((LONG)0xC0000081L)

//
// MessageId: STATUS_TOO_MANY_GUIDS_REQUESTED
//
// MessageText:
//
//  Too many GUIDs were requested from the allocation server at once.
//
#define STATUS_TOO_MANY_GUIDS_REQUESTED  ((LONG)0xC0000082L)

//
// MessageId: STATUS_GUIDS_EXHAUSTED
//
// MessageText:
//
//  The GUIDs could not be allocated because the Authority Agent was exhausted.
//
#define STATUS_GUIDS_EXHAUSTED           ((LONG)0xC0000083L)

//
// MessageId: STATUS_INVALID_ID_AUTHORITY
//
// MessageText:
//
//  The value provided was an invalid value for an identifier authority.
//
#define STATUS_INVALID_ID_AUTHORITY      ((LONG)0xC0000084L)

//
// MessageId: STATUS_AGENTS_EXHAUSTED
//
// MessageText:
//
//  There are no more authority agent values available for the given identifier authority value.
//
#define STATUS_AGENTS_EXHAUSTED          ((LONG)0xC0000085L)

//
// MessageId: STATUS_INVALID_VOLUME_LABEL
//
// MessageText:
//
//  An invalid volume label has been specified.
//
#define STATUS_INVALID_VOLUME_LABEL      ((LONG)0xC0000086L)

//
// MessageId: STATUS_SECTION_NOT_EXTENDED
//
// MessageText:
//
//  A mapped section could not be extended.
//
#define STATUS_SECTION_NOT_EXTENDED      ((LONG)0xC0000087L)

//
// MessageId: STATUS_NOT_MAPPED_DATA
//
// MessageText:
//
//  Specified section to flush does not map a data file.
//
#define STATUS_NOT_MAPPED_DATA           ((LONG)0xC0000088L)

//
// MessageId: STATUS_RESOURCE_DATA_NOT_FOUND
//
// MessageText:
//
//  Indicates the specified image file did not contain a resource section.
//
#define STATUS_RESOURCE_DATA_NOT_FOUND   ((LONG)0xC0000089L)

//
// MessageId: STATUS_RESOURCE_TYPE_NOT_FOUND
//
// MessageText:
//
//  Indicates the specified resource type cannot be found in the image file.
//
#define STATUS_RESOURCE_TYPE_NOT_FOUND   ((LONG)0xC000008AL)

//
// MessageId: STATUS_RESOURCE_NAME_NOT_FOUND
//
// MessageText:
//
//  Indicates the specified resource name cannot be found in the image file.
//
#define STATUS_RESOURCE_NAME_NOT_FOUND   ((LONG)0xC000008BL)

//
// MessageId: STATUS_TOO_MANY_PAGING_FILES
//
// MessageText:
//
//  An attempt was made to install more paging files than the system supports.
//
#define STATUS_TOO_MANY_PAGING_FILES     ((LONG)0xC0000097L)

//
// MessageId: STATUS_FILE_INVALID
//
// MessageText:
//
//  The volume for a file has been externally altered such that the opened file is no longer valid.
//
#define STATUS_FILE_INVALID              ((LONG)0xC0000098L)

//
// MessageId: STATUS_ALLOTTED_SPACE_EXCEEDED
//
// MessageText:
//
//  When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates may exceed the amount of memory originally allotted.
//  Since quota may already have been charged to several processes which have handles to the object, it is not reasonable to alter the size of the allocated memory.
//  Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTED_SPACE_EXCEEDED error returned.
//
#define STATUS_ALLOTTED_SPACE_EXCEEDED   ((LONG)0xC0000099L)

//
// MessageId: STATUS_INSUFFICIENT_RESOURCES
//
// MessageText:
//
//  Insufficient system resources exist to complete the API.
//
#define STATUS_INSUFFICIENT_RESOURCES    ((LONG)0xC000009AL)     // ntsubauth

//
// MessageId: STATUS_DFS_EXIT_PATH_FOUND
//
// MessageText:
//
//  An attempt has been made to open a DFS exit path control file.
//
#define STATUS_DFS_EXIT_PATH_FOUND       ((LONG)0xC000009BL)

//
// MessageId: STATUS_DEVICE_DATA_ERROR
//
// MessageText:
//
//  STATUS_DEVICE_DATA_ERROR
//
#define STATUS_DEVICE_DATA_ERROR         ((LONG)0xC000009CL)

//
// MessageId: STATUS_DEVICE_NOT_CONNECTED
//
// MessageText:
//
//  STATUS_DEVICE_NOT_CONNECTED
//
#define STATUS_DEVICE_NOT_CONNECTED      ((LONG)0xC000009DL)

//
// MessageId: STATUS_DEVICE_POWER_FAILURE
//
// MessageText:
//
//  STATUS_DEVICE_POWER_FAILURE
//
#define STATUS_DEVICE_POWER_FAILURE      ((LONG)0xC000009EL)

//
// MessageId: STATUS_FREE_VM_NOT_AT_BASE
//
// MessageText:
//
//  Virtual memory cannot be freed as base address is not the base of the region and a region size of zero was specified.
//
#define STATUS_FREE_VM_NOT_AT_BASE       ((LONG)0xC000009FL)

//
// MessageId: STATUS_MEMORY_NOT_ALLOCATED
//
// MessageText:
//
//  An attempt was made to free virtual memory which is not allocated.
//
#define STATUS_MEMORY_NOT_ALLOCATED      ((LONG)0xC00000A0L)

//
// MessageId: STATUS_WORKING_SET_QUOTA
//
// MessageText:
//
//  The working set is not big enough to allow the requested pages to be locked.
//
#define STATUS_WORKING_SET_QUOTA         ((LONG)0xC00000A1L)

//
// MessageId: STATUS_MEDIA_WRITE_PROTECTED
//
// MessageText:
//
//  {Write Protect Error}
//  The disk cannot be written to because it is write protected.
//  Please remove the write protection from the volume %hs in drive %hs.
//
#define STATUS_MEDIA_WRITE_PROTECTED     ((LONG)0xC00000A2L)

//
// MessageId: STATUS_DEVICE_NOT_READY
//
// MessageText:
//
//  {Drive Not Ready}
//  The drive is not ready for use; its door may be open.
//  Please check drive %hs and make sure that a disk is inserted and that the drive door is closed.
//
#define STATUS_DEVICE_NOT_READY          ((LONG)0xC00000A3L)

//
// MessageId: STATUS_INVALID_GROUP_ATTRIBUTES
//
// MessageText:
//
//  The specified attributes are invalid, or incompatible with the attributes for the group as a whole.
//
#define STATUS_INVALID_GROUP_ATTRIBUTES  ((LONG)0xC00000A4L)

//
// MessageId: STATUS_BAD_IMPERSONATION_LEVEL
//
// MessageText:
//
//  A specified impersonation level is invalid.
//  Also used to indicate a required impersonation level was not provided.
//
#define STATUS_BAD_IMPERSONATION_LEVEL   ((LONG)0xC00000A5L)

//
// MessageId: STATUS_CANT_OPEN_ANONYMOUS
//
// MessageText:
//
//  An attempt was made to open an Anonymous level token.
//  Anonymous tokens may not be opened.
//
#define STATUS_CANT_OPEN_ANONYMOUS       ((LONG)0xC00000A6L)

//
// MessageId: STATUS_BAD_VALIDATION_CLASS
//
// MessageText:
//
//  The validation information class requested was invalid.
//
#define STATUS_BAD_VALIDATION_CLASS      ((LONG)0xC00000A7L)

//
// MessageId: STATUS_BAD_TOKEN_TYPE
//
// MessageText:
//
//  The type of a token object is inappropriate for its attempted use.
//
#define STATUS_BAD_TOKEN_TYPE            ((LONG)0xC00000A8L)

//
// MessageId: STATUS_BAD_MASTER_BOOT_RECORD
//
// MessageText:
//
//  The type of a token object is inappropriate for its attempted use.
//
#define STATUS_BAD_MASTER_BOOT_RECORD    ((LONG)0xC00000A9L)

//
// MessageId: STATUS_INSTRUCTION_MISALIGNMENT
//
// MessageText:
//
//  An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references.
//
#define STATUS_INSTRUCTION_MISALIGNMENT  ((LONG)0xC00000AAL)

//
// MessageId: STATUS_INSTANCE_NOT_AVAILABLE
//
// MessageText:
//
//  The maximum named pipe instance count has been reached.
//
#define STATUS_INSTANCE_NOT_AVAILABLE    ((LONG)0xC00000ABL)

//
// MessageId: STATUS_PIPE_NOT_AVAILABLE
//
// MessageText:
//
//  An instance of a named pipe cannot be found in the listening state.
//
#define STATUS_PIPE_NOT_AVAILABLE        ((LONG)0xC00000ACL)

//
// MessageId: STATUS_INVALID_PIPE_STATE
//
// MessageText:
//
//  The named pipe is not in the connected or closing state.
//
#define STATUS_INVALID_PIPE_STATE        ((LONG)0xC00000ADL)

//
// MessageId: STATUS_PIPE_BUSY
//
// MessageText:
//
//  The specified pipe is set to complete operations and there are current I/O operations queued so it cannot be changed to queue operations.
//
#define STATUS_PIPE_BUSY                 ((LONG)0xC00000AEL)

//
// MessageId: STATUS_ILLEGAL_FUNCTION
//
// MessageText:
//
//  The specified handle is not open to the server end of the named pipe.
//
#define STATUS_ILLEGAL_FUNCTION          ((LONG)0xC00000AFL)

//
// MessageId: STATUS_PIPE_DISCONNECTED
//
// MessageText:
//
//  The specified named pipe is in the disconnected state.
//
#define STATUS_PIPE_DISCONNECTED         ((LONG)0xC00000B0L)

//
// MessageId: STATUS_PIPE_CLOSING
//
// MessageText:
//
//  The specified named pipe is in the closing state.
//
#define STATUS_PIPE_CLOSING              ((LONG)0xC00000B1L)

//
// MessageId: STATUS_PIPE_CONNECTED
//
// MessageText:
//
//  The specified named pipe is in the connected state.
//
#define STATUS_PIPE_CONNECTED            ((LONG)0xC00000B2L)

//
// MessageId: STATUS_PIPE_LISTENING
//
// MessageText:
//
//  The specified named pipe is in the listening state.
//
#define STATUS_PIPE_LISTENING            ((LONG)0xC00000B3L)

//
// MessageId: STATUS_INVALID_READ_MODE
//
// MessageText:
//
//  The specified named pipe is not in message mode.
//
#define STATUS_INVALID_READ_MODE         ((LONG)0xC00000B4L)

//
// MessageId: STATUS_IO_TIMEOUT
//
// MessageText:
//
//  {Device Timeout}
//  The specified I/O operation on %hs was not completed before the time-out period expired.
//
#define STATUS_IO_TIMEOUT                ((LONG)0xC00000B5L)

//
// MessageId: STATUS_FILE_FORCED_CLOSED
//
// MessageText:
//
//  The specified file has been closed by another process.
//
#define STATUS_FILE_FORCED_CLOSED        ((LONG)0xC00000B6L)

//
// MessageId: STATUS_PROFILING_NOT_STARTED
//
// MessageText:
//
//  Profiling not started.
//
#define STATUS_PROFILING_NOT_STARTED     ((LONG)0xC00000B7L)

//
// MessageId: STATUS_PROFILING_NOT_STOPPED
//
// MessageText:
//
//  Profiling not stopped.
//
#define STATUS_PROFILING_NOT_STOPPED     ((LONG)0xC00000B8L)

//
// MessageId: STATUS_COULD_NOT_INTERPRET
//
// MessageText:
//
//  The passed ACL did not contain the minimum required information.
//
#define STATUS_COULD_NOT_INTERPRET       ((LONG)0xC00000B9L)

//
// MessageId: STATUS_FILE_IS_A_DIRECTORY
//
// MessageText:
//
//  The file that was specified as a target is a directory and the caller specified that it could be anything but a directory.
//
#define STATUS_FILE_IS_A_DIRECTORY       ((LONG)0xC00000BAL)

//
// Network specific errors.
//
//
//
// MessageId: STATUS_NOT_SUPPORTED
//
// MessageText:
//
//  The request is not supported.
//
#define STATUS_NOT_SUPPORTED             ((LONG)0xC00000BBL)

//
// MessageId: STATUS_REMOTE_NOT_LISTENING
//
// MessageText:
//
//  This remote computer is not listening.
//
#define STATUS_REMOTE_NOT_LISTENING      ((LONG)0xC00000BCL)

//
// MessageId: STATUS_DUPLICATE_NAME
//
// MessageText:
//
//  A duplicate name exists on the network.
//
#define STATUS_DUPLICATE_NAME            ((LONG)0xC00000BDL)

//
// MessageId: STATUS_BAD_NETWORK_PATH
//
// MessageText:
//
//  The network path cannot be located.
//
#define STATUS_BAD_NETWORK_PATH          ((LONG)0xC00000BEL)

//
// MessageId: STATUS_NETWORK_BUSY
//
// MessageText:
//
//  The network is busy.
//
#define STATUS_NETWORK_BUSY              ((LONG)0xC00000BFL)

//
// MessageId: STATUS_DEVICE_DOES_NOT_EXIST
//
// MessageText:
//
//  This device does not exist.
//
#define STATUS_DEVICE_DOES_NOT_EXIST     ((LONG)0xC00000C0L)

//
// MessageId: STATUS_TOO_MANY_COMMANDS
//
// MessageText:
//
//  The network BIOS command limit has been reached.
//
#define STATUS_TOO_MANY_COMMANDS         ((LONG)0xC00000C1L)

//
// MessageId: STATUS_ADAPTER_HARDWARE_ERROR
//
// MessageText:
//
//  An I/O adapter hardware error has occurred.
//
#define STATUS_ADAPTER_HARDWARE_ERROR    ((LONG)0xC00000C2L)

//
// MessageId: STATUS_INVALID_NETWORK_RESPONSE
//
// MessageText:
//
//  The network responded incorrectly.
//
#define STATUS_INVALID_NETWORK_RESPONSE  ((LONG)0xC00000C3L)

//
// MessageId: STATUS_UNEXPECTED_NETWORK_ERROR
//
// MessageText:
//
//  An unexpected network error occurred.
//
#define STATUS_UNEXPECTED_NETWORK_ERROR  ((LONG)0xC00000C4L)

//
// MessageId: STATUS_BAD_REMOTE_ADAPTER
//
// MessageText:
//
//  The remote adapter is not compatible.
//
#define STATUS_BAD_REMOTE_ADAPTER        ((LONG)0xC00000C5L)

//
// MessageId: STATUS_PRINT_QUEUE_FULL
//
// MessageText:
//
//  The printer queue is full.
//
#define STATUS_PRINT_QUEUE_FULL          ((LONG)0xC00000C6L)

//
// MessageId: STATUS_NO_SPOOL_SPACE
//
// MessageText:
//
//  Space to store the file waiting to be printed is not available on the server.
//
#define STATUS_NO_SPOOL_SPACE            ((LONG)0xC00000C7L)

//
// MessageId: STATUS_PRINT_CANCELLED
//
// MessageText:
//
//  The requested print file has been canceled.
//
#define STATUS_PRINT_CANCELLED           ((LONG)0xC00000C8L)

//
// MessageId: STATUS_NETWORK_NAME_DELETED
//
// MessageText:
//
//  The network name was deleted.
//
#define STATUS_NETWORK_NAME_DELETED      ((LONG)0xC00000C9L)

//
// MessageId: STATUS_NETWORK_ACCESS_DENIED
//
// MessageText:
//
//  Network access is denied.
//
#define STATUS_NETWORK_ACCESS_DENIED     ((LONG)0xC00000CAL)

//
// MessageId: STATUS_BAD_DEVICE_TYPE
//
// MessageText:
//
//  {Incorrect Network Resource Type}
//  The specified device type (LPT, for example) conflicts with the actual device type on the remote resource.
//
#define STATUS_BAD_DEVICE_TYPE           ((LONG)0xC00000CBL)

//
// MessageId: STATUS_BAD_NETWORK_NAME
//
// MessageText:
//
//  {Network Name Not Found}
//  The specified share name cannot be found on the remote server.
//
#define STATUS_BAD_NETWORK_NAME          ((LONG)0xC00000CCL)

//
// MessageId: STATUS_TOO_MANY_NAMES
//
// MessageText:
//
//  The name limit for the local computer network adapter card was exceeded.
//
#define STATUS_TOO_MANY_NAMES            ((LONG)0xC00000CDL)

//
// MessageId: STATUS_TOO_MANY_SESSIONS
//
// MessageText:
//
//  The network BIOS session limit was exceeded.
//
#define STATUS_TOO_MANY_SESSIONS         ((LONG)0xC00000CEL)

//
// MessageId: STATUS_SHARING_PAUSED
//
// MessageText:
//
//  File sharing has been temporarily paused.
//
#define STATUS_SHARING_PAUSED            ((LONG)0xC00000CFL)

//
// MessageId: STATUS_REQUEST_NOT_ACCEPTED
//
// MessageText:
//
//  No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.
//
#define STATUS_REQUEST_NOT_ACCEPTED      ((LONG)0xC00000D0L)

//
// MessageId: STATUS_REDIRECTOR_PAUSED
//
// MessageText:
//
//  Print or disk redirection is temporarily paused.
//
#define STATUS_REDIRECTOR_PAUSED         ((LONG)0xC00000D1L)

//
// MessageId: STATUS_NET_WRITE_FAULT
//
// MessageText:
//
//  A network data fault occurred.
//
#define STATUS_NET_WRITE_FAULT           ((LONG)0xC00000D2L)

//
// MessageId: STATUS_PROFILING_AT_LIMIT
//
// MessageText:
//
//  The number of active profiling objects is at the maximum and no more may be started.
//
#define STATUS_PROFILING_AT_LIMIT        ((LONG)0xC00000D3L)

//
// MessageId: STATUS_NOT_SAME_DEVICE
//
// MessageText:
//
//  {Incorrect Volume}
//  The target file of a rename request is located on a different device than the source of the rename request.
//
#define STATUS_NOT_SAME_DEVICE           ((LONG)0xC00000D4L)

//
// MessageId: STATUS_FILE_RENAMED
//
// MessageText:
//
//  The file specified has been renamed and thus cannot be modified.
//
#define STATUS_FILE_RENAMED              ((LONG)0xC00000D5L)

//
// MessageId: STATUS_VIRTUAL_CIRCUIT_CLOSED
//
// MessageText:
//
//  {Network Request Timeout}
//  The session with a remote server has been disconnected because the time-out interval for a request has expired.
//
#define STATUS_VIRTUAL_CIRCUIT_CLOSED    ((LONG)0xC00000D6L)

//
// MessageId: STATUS_NO_SECURITY_ON_OBJECT
//
// MessageText:
//
//  Indicates an attempt was made to operate on the security of an object that does not have security associated with it.
//
#define STATUS_NO_SECURITY_ON_OBJECT     ((LONG)0xC00000D7L)

//
// MessageId: STATUS_CANT_WAIT
//
// MessageText:
//
//  Used to indicate that an operation cannot continue without blocking for I/O.
//
#define STATUS_CANT_WAIT                 ((LONG)0xC00000D8L)

//
// MessageId: STATUS_PIPE_EMPTY
//
// MessageText:
//
//  Used to indicate that a read operation was done on an empty pipe.
//
#define STATUS_PIPE_EMPTY                ((LONG)0xC00000D9L)

//
// MessageId: STATUS_CANT_ACCESS_DOMAIN_INFO
//
// MessageText:
//
//  Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.
//
#define STATUS_CANT_ACCESS_DOMAIN_INFO   ((LONG)0xC00000DAL)

//
// MessageId: STATUS_CANT_TERMINATE_SELF
//
// MessageText:
//
//  Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.
//
#define STATUS_CANT_TERMINATE_SELF       ((LONG)0xC00000DBL)

//
// MessageId: STATUS_INVALID_SERVER_STATE
//
// MessageText:
//
//  Indicates the Sam Server was in the wrong state to perform the desired operation.
//
#define STATUS_INVALID_SERVER_STATE      ((LONG)0xC00000DCL)

//
// MessageId: STATUS_INVALID_DOMAIN_STATE
//
// MessageText:
//
//  Indicates the Domain was in the wrong state to perform the desired operation.
//
#define STATUS_INVALID_DOMAIN_STATE      ((LONG)0xC00000DDL)

//
// MessageId: STATUS_INVALID_DOMAIN_ROLE
//
// MessageText:
//
//  This operation is only allowed for the Primary Domain Controller of the domain.
//
#define STATUS_INVALID_DOMAIN_ROLE       ((LONG)0xC00000DEL)

//
// MessageId: STATUS_NO_SUCH_DOMAIN
//
// MessageText:
//
//  The specified Domain did not exist.
//
#define STATUS_NO_SUCH_DOMAIN            ((LONG)0xC00000DFL)

//
// MessageId: STATUS_DOMAIN_EXISTS
//
// MessageText:
//
//  The specified Domain already exists.
//
#define STATUS_DOMAIN_EXISTS             ((LONG)0xC00000E0L)

//
// MessageId: STATUS_DOMAIN_LIMIT_EXCEEDED
//
// MessageText:
//
//  An attempt was made to exceed the limit on the number of domains per server for this release.
//
#define STATUS_DOMAIN_LIMIT_EXCEEDED     ((LONG)0xC00000E1L)

//
// MessageId: STATUS_OPLOCK_NOT_GRANTED
//
// MessageText:
//
//  Error status returned when oplock request is denied.
//
#define STATUS_OPLOCK_NOT_GRANTED        ((LONG)0xC00000E2L)

//
// MessageId: STATUS_INVALID_OPLOCK_PROTOCOL
//
// MessageText:
//
//  Error status returned when an invalid oplock acknowledgment is received by a file system.
//
#define STATUS_INVALID_OPLOCK_PROTOCOL   ((LONG)0xC00000E3L)

//
// MessageId: STATUS_INTERNAL_DB_CORRUPTION
//
// MessageText:
//
//  This error indicates that the requested operation cannot be completed due to a catastrophic media failure or on-disk data structure corruption.
//
#define STATUS_INTERNAL_DB_CORRUPTION    ((LONG)0xC00000E4L)

//
// MessageId: STATUS_INTERNAL_ERROR
//
// MessageText:
//
//  An internal error occurred.
//
#define STATUS_INTERNAL_ERROR            ((LONG)0xC00000E5L)

//
// MessageId: STATUS_GENERIC_NOT_MAPPED
//
// MessageText:
//
//  Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types.
//
#define STATUS_GENERIC_NOT_MAPPED        ((LONG)0xC00000E6L)

//
// MessageId: STATUS_BAD_DESCRIPTOR_FORMAT
//
// MessageText:
//
//  Indicates a security descriptor is not in the necessary format (absolute or self-relative).
//
#define STATUS_BAD_DESCRIPTOR_FORMAT     ((LONG)0xC00000E7L)

//
// Status codes raised by the Cache Manager which must be considered as
// "expected" by its callers.
//
//
// MessageId: STATUS_INVALID_USER_BUFFER
//
// MessageText:
//
//  An access to a user buffer failed at an "expected" point in time.
//  This code is defined since the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter.
//
#define STATUS_INVALID_USER_BUFFER       ((LONG)0xC00000E8L)

//
// MessageId: STATUS_UNEXPECTED_IO_ERROR
//
// MessageText:
//
//  If an I/O error is returned which is not defined in the standard FsRtl filter, it is converted to the following error which is guaranteed to be in the filter.
//  In this case information is lost, however, the filter correctly handles the exception.
//
#define STATUS_UNEXPECTED_IO_ERROR       ((LONG)0xC00000E9L)

//
// MessageId: STATUS_UNEXPECTED_MM_CREATE_ERR
//
// MessageText:
//
//  If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter.
//  In this case information is lost, however, the filter correctly handles the exception.
//
#define STATUS_UNEXPECTED_MM_CREATE_ERR  ((LONG)0xC00000EAL)

//
// MessageId: STATUS_UNEXPECTED_MM_MAP_ERROR
//
// MessageText:
//
//  If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter.
//  In this case information is lost, however, the filter correctly handles the exception.
//
#define STATUS_UNEXPECTED_MM_MAP_ERROR   ((LONG)0xC00000EBL)

//
// MessageId: STATUS_UNEXPECTED_MM_EXTEND_ERR
//
// MessageText:
//
//  If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter.
//  In this case information is lost, however, the filter correctly handles the exception.
//
#define STATUS_UNEXPECTED_MM_EXTEND_ERR  ((LONG)0xC00000ECL)

//
// MessageId: STATUS_NOT_LOGON_PROCESS
//
// MessageText:
//
//  The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.
//
#define STATUS_NOT_LOGON_PROCESS         ((LONG)0xC00000EDL)

//
// MessageId: STATUS_LOGON_SESSION_EXISTS
//
// MessageText:
//
//  An attempt has been made to start a new session manager or LSA logon session with an ID that is already in use.
//
#define STATUS_LOGON_SESSION_EXISTS      ((LONG)0xC00000EEL)

//
// MessageId: STATUS_INVALID_PARAMETER_1
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the first argument.
//
#define STATUS_INVALID_PARAMETER_1       ((LONG)0xC00000EFL)

//
// MessageId: STATUS_INVALID_PARAMETER_2
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the second argument.
//
#define STATUS_INVALID_PARAMETER_2       ((LONG)0xC00000F0L)

//
// MessageId: STATUS_INVALID_PARAMETER_3
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the third argument.
//
#define STATUS_INVALID_PARAMETER_3       ((LONG)0xC00000F1L)

//
// MessageId: STATUS_INVALID_PARAMETER_4
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the fourth argument.
//
#define STATUS_INVALID_PARAMETER_4       ((LONG)0xC00000F2L)

//
// MessageId: STATUS_INVALID_PARAMETER_5
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the fifth argument.
//
#define STATUS_INVALID_PARAMETER_5       ((LONG)0xC00000F3L)

//
// MessageId: STATUS_INVALID_PARAMETER_6
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the sixth argument.
//
#define STATUS_INVALID_PARAMETER_6       ((LONG)0xC00000F4L)

//
// MessageId: STATUS_INVALID_PARAMETER_7
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the seventh argument.
//
#define STATUS_INVALID_PARAMETER_7       ((LONG)0xC00000F5L)

//
// MessageId: STATUS_INVALID_PARAMETER_8
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the eighth argument.
//
#define STATUS_INVALID_PARAMETER_8       ((LONG)0xC00000F6L)

//
// MessageId: STATUS_INVALID_PARAMETER_9
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the ninth argument.
//
#define STATUS_INVALID_PARAMETER_9       ((LONG)0xC00000F7L)

//
// MessageId: STATUS_INVALID_PARAMETER_10
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the tenth argument.
//
#define STATUS_INVALID_PARAMETER_10      ((LONG)0xC00000F8L)

//
// MessageId: STATUS_INVALID_PARAMETER_11
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the eleventh argument.
//
#define STATUS_INVALID_PARAMETER_11      ((LONG)0xC00000F9L)

//
// MessageId: STATUS_INVALID_PARAMETER_12
//
// MessageText:
//
//  An invalid parameter was passed to a service or function as the twelfth argument.
//
#define STATUS_INVALID_PARAMETER_12      ((LONG)0xC00000FAL)

//
// MessageId: STATUS_REDIRECTOR_NOT_STARTED
//
// MessageText:
//
//  An attempt was made to access a network file, but the network software was not yet started.
//
#define STATUS_REDIRECTOR_NOT_STARTED    ((LONG)0xC00000FBL)

//
// MessageId: STATUS_REDIRECTOR_STARTED
//
// MessageText:
//
//  An attempt was made to start the redirector, but the redirector has already been started.
//
#define STATUS_REDIRECTOR_STARTED        ((LONG)0xC00000FCL)

//
// MessageId: STATUS_NO_SUCH_PACKAGE
//
// MessageText:
//
//  A specified authentication package is unknown.
//
#define STATUS_NO_SUCH_PACKAGE           ((LONG)0xC00000FEL)

//
// MessageId: STATUS_BAD_FUNCTION_TABLE
//
// MessageText:
//
//  A malformed function table was encountered during an unwind operation.
//
#define STATUS_BAD_FUNCTION_TABLE        ((LONG)0xC00000FFL)

//
// MessageId: STATUS_VARIABLE_NOT_FOUND
//
// MessageText:
//
//  Indicates the specified environment variable name was not found in the specified environment block.
//
#define STATUS_VARIABLE_NOT_FOUND        ((LONG)0xC0000100L)

//
// MessageId: STATUS_DIRECTORY_NOT_EMPTY
//
// MessageText:
//
//  Indicates that the directory trying to be deleted is not empty.
//
#define STATUS_DIRECTORY_NOT_EMPTY       ((LONG)0xC0000101L)

//
// MessageId: STATUS_FILE_CORRUPT_ERROR
//
// MessageText:
//
//  {Corrupt File}
//  The file or directory %hs is corrupt and unreadable.
//  Please run the Chkdsk utility.
//
#define STATUS_FILE_CORRUPT_ERROR        ((LONG)0xC0000102L)

//
// MessageId: STATUS_NOT_A_DIRECTORY
//
// MessageText:
//
//  A requested opened file is not a directory.
//
#define STATUS_NOT_A_DIRECTORY           ((LONG)0xC0000103L)

//
// MessageId: STATUS_BAD_LOGON_SESSION_STATE
//
// MessageText:
//
//  The logon session is not in a state that is consistent with the requested operation.
//
#define STATUS_BAD_LOGON_SESSION_STATE   ((LONG)0xC0000104L)

//
// MessageId: STATUS_LOGON_SESSION_COLLISION
//
// MessageText:
//
//  An internal LSA error has occurred. An authentication package has requested the creation of a Logon Session but the ID of an already existing Logon Session has been specified.
//
#define STATUS_LOGON_SESSION_COLLISION   ((LONG)0xC0000105L)

//
// MessageId: STATUS_NAME_TOO_LONG
//
// MessageText:
//
//  A specified name string is too long for its intended use.
//
#define STATUS_NAME_TOO_LONG             ((LONG)0xC0000106L)

//
// MessageId: STATUS_FILES_OPEN
//
// MessageText:
//
//  The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force.
//
#define STATUS_FILES_OPEN                ((LONG)0xC0000107L)

//
// MessageId: STATUS_CONNECTION_IN_USE
//
// MessageText:
//
//  The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force.
//
#define STATUS_CONNECTION_IN_USE         ((LONG)0xC0000108L)

//
// MessageId: STATUS_MESSAGE_NOT_FOUND
//
// MessageText:
//
//  RtlFindMessage could not locate the requested message ID in the message table resource.
//
#define STATUS_MESSAGE_NOT_FOUND         ((LONG)0xC0000109L)

//
// MessageId: STATUS_PROCESS_IS_TERMINATING
//
// MessageText:
//
//  An attempt was made to duplicate an object handle into or out of an exiting process.
//
#define STATUS_PROCESS_IS_TERMINATING    ((LONG)0xC000010AL)

//
// MessageId: STATUS_INVALID_LOGON_TYPE
//
// MessageText:
//
//  Indicates an invalid value has been provided for the LogonType requested.
//
#define STATUS_INVALID_LOGON_TYPE        ((LONG)0xC000010BL)

//
// MessageId: STATUS_NO_GUID_TRANSLATION
//
// MessageText:
//
//  Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system.
//  This causes the protection attempt to fail, which may cause a file creation attempt to fail.
//
#define STATUS_NO_GUID_TRANSLATION       ((LONG)0xC000010CL)

//
// MessageId: STATUS_CANNOT_IMPERSONATE
//
// MessageText:
//
//  Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from.
//
#define STATUS_CANNOT_IMPERSONATE        ((LONG)0xC000010DL)

//
// MessageId: STATUS_IMAGE_ALREADY_LOADED
//
// MessageText:
//
//  Indicates that the specified image is already loaded.
//
#define STATUS_IMAGE_ALREADY_LOADED      ((LONG)0xC000010EL)


//
// ============================================================
// NOTE: The following ABIOS error code should be reserved on
//       non ABIOS kernel. Eventually, I will remove the ifdef
//       ABIOS.
// ============================================================
//
//
// MessageId: STATUS_ABIOS_NOT_PRESENT
//
// MessageText:
//
//  STATUS_ABIOS_NOT_PRESENT
//
#define STATUS_ABIOS_NOT_PRESENT         ((LONG)0xC000010FL)

//
// MessageId: STATUS_ABIOS_LID_NOT_EXIST
//
// MessageText:
//
//  STATUS_ABIOS_LID_NOT_EXIST
//
#define STATUS_ABIOS_LID_NOT_EXIST       ((LONG)0xC0000110L)

//
// MessageId: STATUS_ABIOS_LID_ALREADY_OWNED
//
// MessageText:
//
//  STATUS_ABIOS_LID_ALREADY_OWNED
//
#define STATUS_ABIOS_LID_ALREADY_OWNED   ((LONG)0xC0000111L)

//
// MessageId: STATUS_ABIOS_NOT_LID_OWNER
//
// MessageText:
//
//  STATUS_ABIOS_NOT_LID_OWNER
//
#define STATUS_ABIOS_NOT_LID_OWNER       ((LONG)0xC0000112L)

//
// MessageId: STATUS_ABIOS_INVALID_COMMAND
//
// MessageText:
//
//  STATUS_ABIOS_INVALID_COMMAND
//
#define STATUS_ABIOS_INVALID_COMMAND     ((LONG)0xC0000113L)

//
// MessageId: STATUS_ABIOS_INVALID_LID
//
// MessageText:
//
//  STATUS_ABIOS_INVALID_LID
//
#define STATUS_ABIOS_INVALID_LID         ((LONG)0xC0000114L)

//
// MessageId: STATUS_ABIOS_SELECTOR_NOT_AVAILABLE
//
// MessageText:
//
//  STATUS_ABIOS_SELECTOR_NOT_AVAILABLE
//
#define STATUS_ABIOS_SELECTOR_NOT_AVAILABLE ((LONG)0xC0000115L)

//
// MessageId: STATUS_ABIOS_INVALID_SELECTOR
//
// MessageText:
//
//  STATUS_ABIOS_INVALID_SELECTOR
//
#define STATUS_ABIOS_INVALID_SELECTOR    ((LONG)0xC0000116L)

//
// MessageId: STATUS_NO_LDT
//
// MessageText:
//
//  Indicates that an attempt was made to change the size of the LDT for a process that has no LDT.
//
#define STATUS_NO_LDT                    ((LONG)0xC0000117L)

//
// MessageId: STATUS_INVALID_LDT_SIZE
//
// MessageText:
//
//  Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors.
//
#define STATUS_INVALID_LDT_SIZE          ((LONG)0xC0000118L)

//
// MessageId: STATUS_INVALID_LDT_OFFSET
//
// MessageText:
//
//  Indicates that the starting value for the LDT information was not an integral multiple of the selector size.
//
#define STATUS_INVALID_LDT_OFFSET        ((LONG)0xC0000119L)

//
// MessageId: STATUS_INVALID_LDT_DESCRIPTOR
//
// MessageText:
//
//  Indicates that the user supplied an invalid descriptor when trying to set up Ldt descriptors.
//
#define STATUS_INVALID_LDT_DESCRIPTOR    ((LONG)0xC000011AL)

//
// MessageId: STATUS_INVALID_IMAGE_NE_FORMAT
//
// MessageText:
//
//  The specified image file did not have the correct format. It appears to be NE format.
//
#define STATUS_INVALID_IMAGE_NE_FORMAT   ((LONG)0xC000011BL)

//
// MessageId: STATUS_RXACT_INVALID_STATE
//
// MessageText:
//
//  Indicates that the transaction state of a registry sub-tree is incompatible with the requested operation.
//  For example, a request has been made to start a new transaction with one already in progress,
//  or a request has been made to apply a transaction when one is not currently in progress.
//
#define STATUS_RXACT_INVALID_STATE       ((LONG)0xC000011CL)

//
// MessageId: STATUS_RXACT_COMMIT_FAILURE
//
// MessageText:
//
//  Indicates an error has occurred during a registry transaction commit.
//  The database has been left in an unknown, but probably inconsistent, state.
//  The state of the registry transaction is left as COMMITTING.
//
#define STATUS_RXACT_COMMIT_FAILURE      ((LONG)0xC000011DL)

//
// MessageId: STATUS_MAPPED_FILE_SIZE_ZERO
//
// MessageText:
//
//  An attempt was made to map a file of size zero with the maximum size specified as zero.
//
#define STATUS_MAPPED_FILE_SIZE_ZERO     ((LONG)0xC000011EL)

//
// MessageId: STATUS_TOO_MANY_OPENED_FILES
//
// MessageText:
//
//  Too many files are opened on a remote server.
//  This error should only be returned by the Windows redirector on a remote drive.
//
#define STATUS_TOO_MANY_OPENED_FILES     ((LONG)0xC000011FL)

//
// MessageId: STATUS_CANCELLED
//
// MessageText:
//
//  The I/O request was canceled.
//
#define STATUS_CANCELLED                 ((LONG)0xC0000120L)

//
// MessageId: STATUS_CANNOT_DELETE
//
// MessageText:
//
//  An attempt has been made to remove a file or directory that cannot be deleted.
//
#define STATUS_CANNOT_DELETE             ((LONG)0xC0000121L)

//
// MessageId: STATUS_INVALID_COMPUTER_NAME
//
// MessageText:
//
//  Indicates a name specified as a remote computer name is syntactically invalid.
//
#define STATUS_INVALID_COMPUTER_NAME     ((LONG)0xC0000122L)

//
// MessageId: STATUS_FILE_DELETED
//
// MessageText:
//
//  An I/O request other than close was performed on a file after it has been deleted,
//  which can only happen to a request which did not complete before the last handle was closed via NtClose.
//
#define STATUS_FILE_DELETED              ((LONG)0xC0000123L)

//
// MessageId: STATUS_SPECIAL_ACCOUNT
//
// MessageText:
//
//  Indicates an operation has been attempted on a built-in (special) SAM account which is incompatible with built-in accounts.
//  For example, built-in accounts cannot be deleted.
//
#define STATUS_SPECIAL_ACCOUNT           ((LONG)0xC0000124L)

//
// MessageId: STATUS_SPECIAL_GROUP
//
// MessageText:
//
//  The operation requested may not be performed on the specified group because it is a built-in special group.
//
#define STATUS_SPECIAL_GROUP             ((LONG)0xC0000125L)

//
// MessageId: STATUS_SPECIAL_USER
//
// MessageText:
//
//  The operation requested may not be performed on the specified user because it is a built-in special user.
//
#define STATUS_SPECIAL_USER              ((LONG)0xC0000126L)

//
// MessageId: STATUS_MEMBERS_PRIMARY_GROUP
//
// MessageText:
//
//  Indicates a member cannot be removed from a group because the group is currently the member's primary group.
//
#define STATUS_MEMBERS_PRIMARY_GROUP     ((LONG)0xC0000127L)

//
// MessageId: STATUS_FILE_CLOSED
//
// MessageText:
//
//  An I/O request other than close and several other special case operations was attempted using a file object that had already been closed.
//
#define STATUS_FILE_CLOSED               ((LONG)0xC0000128L)

//
// MessageId: STATUS_TOO_MANY_THREADS
//
// MessageText:
//
//  Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads.
//
#define STATUS_TOO_MANY_THREADS          ((LONG)0xC0000129L)

//
// MessageId: STATUS_THREAD_NOT_IN_PROCESS
//
// MessageText:
//
//  An attempt was made to operate on a thread within a specific process, but the thread specified is not in the process specified.
//
#define STATUS_THREAD_NOT_IN_PROCESS     ((LONG)0xC000012AL)

//
// MessageId: STATUS_TOKEN_ALREADY_IN_USE
//
// MessageText:
//
//  An attempt was made to establish a token for use as a primary token but the token is already in use. A token can only be the primary token of one process at a time.
//
#define STATUS_TOKEN_ALREADY_IN_USE      ((LONG)0xC000012BL)

//
// MessageId: STATUS_PAGEFILE_QUOTA_EXCEEDED
//
// MessageText:
//
//  Page file quota was exceeded.
//
#define STATUS_PAGEFILE_QUOTA_EXCEEDED   ((LONG)0xC000012CL)

//
// MessageId: STATUS_COMMITMENT_LIMIT
//
// MessageText:
//
//  {Out of Virtual Memory}
//  Your system is low on virtual memory. To ensure that Windows runs properly, increase the size of your virtual memory paging file. For more information, see Help.
//
#define STATUS_COMMITMENT_LIMIT          ((LONG)0xC000012DL)

//
// MessageId: STATUS_INVALID_IMAGE_LE_FORMAT
//
// MessageText:
//
//  The specified image file did not have the correct format, it appears to be LE format.
//
#define STATUS_INVALID_IMAGE_LE_FORMAT   ((LONG)0xC000012EL)

//
// MessageId: STATUS_INVALID_IMAGE_NOT_MZ
//
// MessageText:
//
//  The specified image file did not have the correct format, it did not have an initial MZ.
//
#define STATUS_INVALID_IMAGE_NOT_MZ      ((LONG)0xC000012FL)

//
// MessageId: STATUS_INVALID_IMAGE_PROTECT
//
// MessageText:
//
//  The specified image file did not have the correct format, it did not have a proper e_lfarlc in the MZ header.
//
#define STATUS_INVALID_IMAGE_PROTECT     ((LONG)0xC0000130L)

//
// MessageId: STATUS_INVALID_IMAGE_WIN_16
//
// MessageText:
//
//  The specified image file did not have the correct format, it appears to be a 16-bit Windows image.
//
#define STATUS_INVALID_IMAGE_WIN_16      ((LONG)0xC0000131L)

//
// MessageId: STATUS_LOGON_SERVER_CONFLICT
//
// MessageText:
//
//  The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.
//
#define STATUS_LOGON_SERVER_CONFLICT     ((LONG)0xC0000132L)

//
// MessageId: STATUS_TIME_DIFFERENCE_AT_DC
//
// MessageText:
//
//  The time at the Primary Domain Controller is different than the time at the Backup Domain Controller or member server by too large an amount.
//
#define STATUS_TIME_DIFFERENCE_AT_DC     ((LONG)0xC0000133L)

//
// MessageId: STATUS_SYNCHRONIZATION_REQUIRED
//
// MessageText:
//
//  The SAM database on a Windows Server is significantly out of synchronization with the copy on the Domain Controller. A complete synchronization is required.
//
#define STATUS_SYNCHRONIZATION_REQUIRED  ((LONG)0xC0000134L)

//
// MessageId: STATUS_OPEN_FAILED
//
// MessageText:
//
//  The NtCreateFile API failed. This error should never be returned to an application, it is a place holder for the Windows Lan Manager Redirector to use in its internal error mapping routines.
//
#define STATUS_OPEN_FAILED               ((LONG)0xC0000136L)

//
// MessageId: STATUS_IO_PRIVILEGE_FAILED
//
// MessageText:
//
//  {Privilege Failed}
//  The I/O permissions for the process could not be changed.
//
#define STATUS_IO_PRIVILEGE_FAILED       ((LONG)0xC0000137L)



//
// MessageId: STATUS_LOCAL_DISCONNECT
//
// MessageText:
//
//  {Virtual Circuit Closed}
//  The network transport on your computer has closed a network connection. There may or may not be I/O requests outstanding.
//
#define STATUS_LOCAL_DISCONNECT          ((LONG)0xC000013BL)

//
// MessageId: STATUS_REMOTE_DISCONNECT
//
// MessageText:
//
//  {Virtual Circuit Closed}
//  The network transport on a remote computer has closed a network connection. There may or may not be I/O requests outstanding.
//
#define STATUS_REMOTE_DISCONNECT         ((LONG)0xC000013CL)

//
// MessageId: STATUS_REMOTE_RESOURCES
//
// MessageText:
//
//  {Insufficient Resources on Remote Computer}
//  The remote computer has insufficient resources to complete the network request. For instance, there may not be enough memory available on the remote computer to carry out the request at this time.
//
#define STATUS_REMOTE_RESOURCES          ((LONG)0xC000013DL)

//
// MessageId: STATUS_LINK_FAILED
//
// MessageText:
//
//  {Virtual Circuit Closed}
//  An existing connection (virtual circuit) has been broken at the remote computer. There is probably something wrong with the network software protocol or the network hardware on the remote computer.
//
#define STATUS_LINK_FAILED               ((LONG)0xC000013EL)

//
// MessageId: STATUS_LINK_TIMEOUT
//
// MessageText:
//
//  {Virtual Circuit Closed}
//  The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer.
//
#define STATUS_LINK_TIMEOUT              ((LONG)0xC000013FL)

//
// MessageId: STATUS_INVALID_CONNECTION
//
// MessageText:
//
//  The connection handle given to the transport was invalid.
//
#define STATUS_INVALID_CONNECTION        ((LONG)0xC0000140L)

//
// MessageId: STATUS_INVALID_ADDRESS
//
// MessageText:
//
//  The address handle given to the transport was invalid.
//
#define STATUS_INVALID_ADDRESS           ((LONG)0xC0000141L)

//
// MessageId: STATUS_MISSING_SYSTEMFILE
//
// MessageText:
//
//  {Missing System File}
//  The required system file %hs is bad or missing.
//
#define STATUS_MISSING_SYSTEMFILE        ((LONG)0xC0000143L)

//
// MessageId: STATUS_UNHANDLED_EXCEPTION
//
// MessageText:
//
//  {Application Error}
//  The exception %s (0x%08lx) occurred in the application at location 0x%08lx.
//
#define STATUS_UNHANDLED_EXCEPTION       ((LONG)0xC0000144L)

//
// MessageId: STATUS_APP_INIT_FAILURE
//
// MessageText:
//
//  {Application Error}
//  The application failed to initialize properly (0x%lx). Click on OK to terminate the application.
//
#define STATUS_APP_INIT_FAILURE          ((LONG)0xC0000145L)

//
// MessageId: STATUS_PAGEFILE_CREATE_FAILED
//
// MessageText:
//
//  {Unable to Create Paging File}
//  The creation of the paging file %hs failed (%lx). The requested size was %ld.
//
#define STATUS_PAGEFILE_CREATE_FAILED    ((LONG)0xC0000146L)

//
// MessageId: STATUS_NO_PAGEFILE
//
// MessageText:
//
//  {No Paging File Specified}
//  No paging file was specified in the system configuration.
//
#define STATUS_NO_PAGEFILE               ((LONG)0xC0000147L)

//
// MessageId: STATUS_INVALID_LEVEL
//
// MessageText:
//
//  {Incorrect System Call Level}
//  An invalid level was passed into the specified system call.
//
#define STATUS_INVALID_LEVEL             ((LONG)0xC0000148L)

//
// MessageId: STATUS_WRONG_PASSWORD_CORE
//
// MessageText:
//
//  {Incorrect Password to LAN Manager Server}
//  You specified an incorrect password to a LAN Manager 2.x or MS-NET server.
//
#define STATUS_WRONG_PASSWORD_CORE       ((LONG)0xC0000149L)

//
// MessageId: STATUS_ILLEGAL_FLOAT_CONTEXT
//
// MessageText:
//
//  {EXCEPTION}
//  A real-mode application issued a floating-point instruction and floating-point hardware is not present.
//
#define STATUS_ILLEGAL_FLOAT_CONTEXT     ((LONG)0xC000014AL)

//
// MessageId: STATUS_PIPE_BROKEN
//
// MessageText:
//
//  The pipe operation has failed because the other end of the pipe has been closed.
//
#define STATUS_PIPE_BROKEN               ((LONG)0xC000014BL)

//
// MessageId: STATUS_REGISTRY_CORRUPT
//
// MessageText:
//
//  {The Registry Is Corrupt}
//  The structure of one of the files that contains Registry data is corrupt, or the image of the file in memory is corrupt, or the file could not be recovered because the alternate copy or log was absent or corrupt.
//
#define STATUS_REGISTRY_CORRUPT          ((LONG)0xC000014CL)

//
// MessageId: STATUS_REGISTRY_IO_FAILED
//
// MessageText:
//
//  An I/O operation initiated by the Registry failed unrecoverably.
//  The Registry could not read in, or write out, or flush, one of the files that contain the system's image of the Registry.
//
#define STATUS_REGISTRY_IO_FAILED        ((LONG)0xC000014DL)

//
// MessageId: STATUS_NO_EVENT_PAIR
//
// MessageText:
//
//  An event pair synchronization operation was performed using the thread specific client/server event pair object, but no event pair object was associated with the thread.
//
#define STATUS_NO_EVENT_PAIR             ((LONG)0xC000014EL)

//
// MessageId: STATUS_UNRECOGNIZED_VOLUME
//
// MessageText:
//
//  The volume does not contain a recognized file system.
//  Please make sure that all required file system drivers are loaded and that the volume is not corrupt.
//
#define STATUS_UNRECOGNIZED_VOLUME       ((LONG)0xC000014FL)

//
// MessageId: STATUS_SERIAL_NO_DEVICE_INITED
//
// MessageText:
//
//  No serial device was successfully initialized. The serial driver will unload.
//
#define STATUS_SERIAL_NO_DEVICE_INITED   ((LONG)0xC0000150L)

//
// MessageId: STATUS_NO_SUCH_ALIAS
//
// MessageText:
//
//  The specified local group does not exist.
//
#define STATUS_NO_SUCH_ALIAS             ((LONG)0xC0000151L)

//
// MessageId: STATUS_MEMBER_NOT_IN_ALIAS
//
// MessageText:
//
//  The specified account name is not a member of the local group.
//
#define STATUS_MEMBER_NOT_IN_ALIAS       ((LONG)0xC0000152L)

//
// MessageId: STATUS_MEMBER_IN_ALIAS
//
// MessageText:
//
//  The specified account name is already a member of the local group.
//
#define STATUS_MEMBER_IN_ALIAS           ((LONG)0xC0000153L)

//
// MessageId: STATUS_ALIAS_EXISTS
//
// MessageText:
//
//  The specified local group already exists.
//
#define STATUS_ALIAS_EXISTS              ((LONG)0xC0000154L)

//
// MessageId: STATUS_LOGON_NOT_GRANTED
//
// MessageText:
//
//  A requested type of logon (e.g., Interactive, Network, Service) is not granted by the target system's local security policy.
//  Please ask the system administrator to grant the necessary form of logon.
//
#define STATUS_LOGON_NOT_GRANTED         ((LONG)0xC0000155L)

//
// MessageId: STATUS_TOO_MANY_SECRETS
//
// MessageText:
//
//  The maximum number of secrets that may be stored in a single system has been exceeded. The length and number of secrets is limited to satisfy United States State Department export restrictions.
//
#define STATUS_TOO_MANY_SECRETS          ((LONG)0xC0000156L)

//
// MessageId: STATUS_SECRET_TOO_LONG
//
// MessageText:
//
//  The length of a secret exceeds the maximum length allowed. The length and number of secrets is limited to satisfy United States State Department export restrictions.
//
#define STATUS_SECRET_TOO_LONG           ((LONG)0xC0000157L)

//
// MessageId: STATUS_INTERNAL_DB_ERROR
//
// MessageText:
//
//  The Local Security Authority (LSA) database contains an internal inconsistency.
//
#define STATUS_INTERNAL_DB_ERROR         ((LONG)0xC0000158L)

//
// MessageId: STATUS_FULLSCREEN_MODE
//
// MessageText:
//
//  The requested operation cannot be performed in fullscreen mode.
//
#define STATUS_FULLSCREEN_MODE           ((LONG)0xC0000159L)

//
// MessageId: STATUS_TOO_MANY_CONTEXT_IDS
//
// MessageText:
//
//  During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation.
//  Remove the user from some global or local groups to reduce the number of security ids to incorporate into the security context.
//
#define STATUS_TOO_MANY_CONTEXT_IDS      ((LONG)0xC000015AL)

//
// MessageId: STATUS_LOGON_TYPE_NOT_GRANTED
//
// MessageText:
//
//  A user has requested a type of logon (e.g., interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network.
//
#define STATUS_LOGON_TYPE_NOT_GRANTED    ((LONG)0xC000015BL)

//
// MessageId: STATUS_NOT_REGISTRY_FILE
//
// MessageText:
//
//  The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file.
//
#define STATUS_NOT_REGISTRY_FILE         ((LONG)0xC000015CL)

//
// MessageId: STATUS_NT_CROSS_ENCRYPTION_REQUIRED
//
// MessageText:
//
//  An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password.
//
#define STATUS_NT_CROSS_ENCRYPTION_REQUIRED ((LONG)0xC000015DL)

//
// MessageId: STATUS_DOMAIN_CTRLR_CONFIG_ERROR
//
// MessageText:
//
//  A Windows Server has an incorrect configuration.
//
#define STATUS_DOMAIN_CTRLR_CONFIG_ERROR ((LONG)0xC000015EL)

//
// MessageId: STATUS_FT_MISSING_MEMBER
//
// MessageText:
//
//  An attempt was made to explicitly access the secondary copy of information via a device control to the Fault Tolerance driver and the secondary copy is not present in the system.
//
#define STATUS_FT_MISSING_MEMBER         ((LONG)0xC000015FL)

//
// MessageId: STATUS_ILL_FORMED_SERVICE_ENTRY
//
// MessageText:
//
//  A configuration registry node representing a driver service entry was ill-formed and did not contain required value entries.
//
#define STATUS_ILL_FORMED_SERVICE_ENTRY  ((LONG)0xC0000160L)

//
// MessageId: STATUS_ILLEGAL_CHARACTER
//
// MessageText:
//
//  An illegal character was encountered. For a multi-byte character set this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE.
//
#define STATUS_ILLEGAL_CHARACTER         ((LONG)0xC0000161L)

//
// MessageId: STATUS_UNMAPPABLE_CHARACTER
//
// MessageText:
//
//  No mapping for the Unicode character exists in the target multi-byte code page.
//
#define STATUS_UNMAPPABLE_CHARACTER      ((LONG)0xC0000162L)

//
// MessageId: STATUS_UNDEFINED_CHARACTER
//
// MessageText:
//
//  The Unicode character is not defined in the Unicode character set installed on the system.
//
#define STATUS_UNDEFINED_CHARACTER       ((LONG)0xC0000163L)

//
// MessageId: STATUS_FLOPPY_VOLUME
//
// MessageText:
//
//  The paging file cannot be created on a floppy diskette.
//
#define STATUS_FLOPPY_VOLUME             ((LONG)0xC0000164L)

//
// MessageId: STATUS_FLOPPY_ID_MARK_NOT_FOUND
//
// MessageText:
//
//  {Floppy Disk Error}
//  While accessing a floppy disk, an ID address mark was not found.
//
#define STATUS_FLOPPY_ID_MARK_NOT_FOUND  ((LONG)0xC0000165L)

//
// MessageId: STATUS_FLOPPY_WRONG_CYLINDER
//
// MessageText:
//
//  {Floppy Disk Error}
//  While accessing a floppy disk, the track address from the sector ID field was found to be different than the track address maintained by the controller.
//
#define STATUS_FLOPPY_WRONG_CYLINDER     ((LONG)0xC0000166L)

//
// MessageId: STATUS_FLOPPY_UNKNOWN_ERROR
//
// MessageText:
//
//  {Floppy Disk Error}
//  The floppy disk controller reported an error that is not recognized by the floppy disk driver.
//
#define STATUS_FLOPPY_UNKNOWN_ERROR      ((LONG)0xC0000167L)

//
// MessageId: STATUS_FLOPPY_BAD_REGISTERS
//
// MessageText:
//
//  {Floppy Disk Error}
//  While accessing a floppy-disk, the controller returned inconsistent results via its registers.
//
#define STATUS_FLOPPY_BAD_REGISTERS      ((LONG)0xC0000168L)

//
// MessageId: STATUS_DISK_RECALIBRATE_FAILED
//
// MessageText:
//
//  {Hard Disk Error}
//  While accessing the hard disk, a recalibrate operation failed, even after retries.
//
#define STATUS_DISK_RECALIBRATE_FAILED   ((LONG)0xC0000169L)

//
// MessageId: STATUS_DISK_OPERATION_FAILED
//
// MessageText:
//
//  {Hard Disk Error}
//  While accessing the hard disk, a disk operation failed even after retries.
//
#define STATUS_DISK_OPERATION_FAILED     ((LONG)0xC000016AL)

//
// MessageId: STATUS_DISK_RESET_FAILED
//
// MessageText:
//
//  {Hard Disk Error}
//  While accessing the hard disk, a disk controller reset was needed, but even that failed.
//
#define STATUS_DISK_RESET_FAILED         ((LONG)0xC000016BL)

//
// MessageId: STATUS_SHARED_IRQ_BUSY
//
// MessageText:
//
//  An attempt was made to open a device that was sharing an IRQ with other devices.
//  At least one other device that uses that IRQ was already opened.
//  Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use.
//
#define STATUS_SHARED_IRQ_BUSY           ((LONG)0xC000016CL)

//
// MessageId: STATUS_FT_ORPHANING
//
// MessageText:
//
//  {FT Orphaning}
//  A disk that is part of a fault-tolerant volume can no longer be accessed.
//
#define STATUS_FT_ORPHANING              ((LONG)0xC000016DL)

//
// MessageId: STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT
//
// MessageText:
//
//  The system bios failed to connect a system interrupt to the device or bus for
//  which the device is connected.
//
#define STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT ((LONG)0xC000016EL)

//
// MessageId: STATUS_PARTITION_FAILURE
//
// MessageText:
//
//  Tape could not be partitioned.
//
#define STATUS_PARTITION_FAILURE         ((LONG)0xC0000172L)

//
// MessageId: STATUS_INVALID_BLOCK_LENGTH
//
// MessageText:
//
//  When accessing a new tape of a multivolume partition, the current blocksize is incorrect.
//
#define STATUS_INVALID_BLOCK_LENGTH      ((LONG)0xC0000173L)

//
// MessageId: STATUS_DEVICE_NOT_PARTITIONED
//
// MessageText:
//
//  Tape partition information could not be found when loading a tape.
//
#define STATUS_DEVICE_NOT_PARTITIONED    ((LONG)0xC0000174L)

//
// MessageId: STATUS_UNABLE_TO_LOCK_MEDIA
//
// MessageText:
//
//  Attempt to lock the eject media mechanism fails.
//
#define STATUS_UNABLE_TO_LOCK_MEDIA      ((LONG)0xC0000175L)

//
// MessageId: STATUS_UNABLE_TO_UNLOAD_MEDIA
//
// MessageText:
//
//  Unload media fails.
//
#define STATUS_UNABLE_TO_UNLOAD_MEDIA    ((LONG)0xC0000176L)

//
// MessageId: STATUS_EOM_OVERFLOW
//
// MessageText:
//
//  Physical end of tape was detected.
//
#define STATUS_EOM_OVERFLOW              ((LONG)0xC0000177L)

//
// MessageId: STATUS_NO_MEDIA
//
// MessageText:
//
//  {No Media}
//  There is no media in the drive.
//  Please insert media into drive %hs.
//
#define STATUS_NO_MEDIA                  ((LONG)0xC0000178L)

//
// MessageId: STATUS_NO_SUCH_MEMBER
//
// MessageText:
//
//  A member could not be added to or removed from the local group because the member does not exist.
//
#define STATUS_NO_SUCH_MEMBER            ((LONG)0xC000017AL)

//
// MessageId: STATUS_INVALID_MEMBER
//
// MessageText:
//
//  A new member could not be added to a local group because the member has the wrong account type.
//
#define STATUS_INVALID_MEMBER            ((LONG)0xC000017BL)

//
// MessageId: STATUS_KEY_DELETED
//
// MessageText:
//
//  Illegal operation attempted on a registry key which has been marked for deletion.
//
#define STATUS_KEY_DELETED               ((LONG)0xC000017CL)

//
// MessageId: STATUS_NO_LOG_SPACE
//
// MessageText:
//
//  System could not allocate required space in a registry log.
//
#define STATUS_NO_LOG_SPACE              ((LONG)0xC000017DL)

//
// MessageId: STATUS_TOO_MANY_SIDS
//
// MessageText:
//
//  Too many Sids have been specified.
//
#define STATUS_TOO_MANY_SIDS             ((LONG)0xC000017EL)

//
// MessageId: STATUS_LM_CROSS_ENCRYPTION_REQUIRED
//
// MessageText:
//
//  An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password.
//
#define STATUS_LM_CROSS_ENCRYPTION_REQUIRED ((LONG)0xC000017FL)

//
// MessageId: STATUS_KEY_HAS_CHILDREN
//
// MessageText:
//
//  An attempt was made to create a symbolic link in a registry key that already has subkeys or values.
//
#define STATUS_KEY_HAS_CHILDREN          ((LONG)0xC0000180L)

//
// MessageId: STATUS_CHILD_MUST_BE_VOLATILE
//
// MessageText:
//
//  An attempt was made to create a Stable subkey under a Volatile parent key.
//
#define STATUS_CHILD_MUST_BE_VOLATILE    ((LONG)0xC0000181L)

//
// MessageId: STATUS_DEVICE_CONFIGURATION_ERROR
//
// MessageText:
//
//  The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect.
//
#define STATUS_DEVICE_CONFIGURATION_ERROR ((LONG)0xC0000182L)

//
// MessageId: STATUS_DRIVER_INTERNAL_ERROR
//
// MessageText:
//
//  An error was detected between two drivers or within an I/O driver.
//
#define STATUS_DRIVER_INTERNAL_ERROR     ((LONG)0xC0000183L)

//
// MessageId: STATUS_INVALID_DEVICE_STATE
//
// MessageText:
//
//  The device is not in a valid state to perform this request.
//
#define STATUS_INVALID_DEVICE_STATE      ((LONG)0xC0000184L)

//
// MessageId: STATUS_IO_DEVICE_ERROR
//
// MessageText:
//
//  The I/O device reported an I/O error.
//
#define STATUS_IO_DEVICE_ERROR           ((LONG)0xC0000185L)

//
// MessageId: STATUS_DEVICE_PROTOCOL_ERROR
//
// MessageText:
//
//  A protocol error was detected between the driver and the device.
//
#define STATUS_DEVICE_PROTOCOL_ERROR     ((LONG)0xC0000186L)

//
// MessageId: STATUS_BACKUP_CONTROLLER
//
// MessageText:
//
//  This operation is only allowed for the Primary Domain Controller of the domain.
//
#define STATUS_BACKUP_CONTROLLER         ((LONG)0xC0000187L)

//
// MessageId: STATUS_LOG_FILE_FULL
//
// MessageText:
//
//  Log file space is insufficient to support this operation.
//
#define STATUS_LOG_FILE_FULL             ((LONG)0xC0000188L)

//
// MessageId: STATUS_TOO_LATE
//
// MessageText:
//
//  A write operation was attempted to a volume after it was dismounted.
//
#define STATUS_TOO_LATE                  ((LONG)0xC0000189L)

//
// MessageId: STATUS_NO_TRUST_LSA_SECRET
//
// MessageText:
//
//  The workstation does not have a trust secret for the primary domain in the local LSA database.
//
#define STATUS_NO_TRUST_LSA_SECRET       ((LONG)0xC000018AL)

//
// MessageId: STATUS_NO_TRUST_SAM_ACCOUNT
//
// MessageText:
//
//  The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.
//
#define STATUS_NO_TRUST_SAM_ACCOUNT      ((LONG)0xC000018BL)

//
// MessageId: STATUS_TRUSTED_DOMAIN_FAILURE
//
// MessageText:
//
//  The logon request failed because the trust relationship between the primary domain and the trusted domain failed.
//
#define STATUS_TRUSTED_DOMAIN_FAILURE    ((LONG)0xC000018CL)

//
// MessageId: STATUS_TRUSTED_RELATIONSHIP_FAILURE
//
// MessageText:
//
//  The logon request failed because the trust relationship between this workstation and the primary domain failed.
//
#define STATUS_TRUSTED_RELATIONSHIP_FAILURE ((LONG)0xC000018DL)

//
// MessageId: STATUS_EVENTLOG_FILE_CORRUPT
//
// MessageText:
//
//  The Eventlog log file is corrupt.
//
#define STATUS_EVENTLOG_FILE_CORRUPT     ((LONG)0xC000018EL)

//
// MessageId: STATUS_EVENTLOG_CANT_START
//
// MessageText:
//
//  No Eventlog log file could be opened. The Eventlog service did not start.
//
#define STATUS_EVENTLOG_CANT_START       ((LONG)0xC000018FL)

//
// MessageId: STATUS_TRUST_FAILURE
//
// MessageText:
//
//  The network logon failed. This may be because the validation authority can't be reached.
//
#define STATUS_TRUST_FAILURE             ((LONG)0xC0000190L)

//
// MessageId: STATUS_MUTANT_LIMIT_EXCEEDED
//
// MessageText:
//
//  An attempt was made to acquire a mutant such that its maximum count would have been exceeded.
//
#define STATUS_MUTANT_LIMIT_EXCEEDED     ((LONG)0xC0000191L)

//
// MessageId: STATUS_NETLOGON_NOT_STARTED
//
// MessageText:
//
//  An attempt was made to logon, but the netlogon service was not started.
//
#define STATUS_NETLOGON_NOT_STARTED      ((LONG)0xC0000192L)

//
// MessageId: STATUS_ACCOUNT_EXPIRED
//
// MessageText:
//
//  The user's account has expired.
//
#define STATUS_ACCOUNT_EXPIRED           ((LONG)0xC0000193L)    // ntsubauth

//
// MessageId: STATUS_POSSIBLE_DEADLOCK
//
// MessageText:
//
//  {EXCEPTION}
//  Possible deadlock condition.
//
#define STATUS_POSSIBLE_DEADLOCK         ((LONG)0xC0000194L)

//
// MessageId: STATUS_NETWORK_CREDENTIAL_CONFLICT
//
// MessageText:
//
//  Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.
//
#define STATUS_NETWORK_CREDENTIAL_CONFLICT ((LONG)0xC0000195L)

//
// MessageId: STATUS_REMOTE_SESSION_LIMIT
//
// MessageText:
//
//  An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.
//
#define STATUS_REMOTE_SESSION_LIMIT      ((LONG)0xC0000196L)

//
// MessageId: STATUS_EVENTLOG_FILE_CHANGED
//
// MessageText:
//
//  The log file has changed between reads.
//
#define STATUS_EVENTLOG_FILE_CHANGED     ((LONG)0xC0000197L)

//
// MessageId: STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT
//
// MessageText:
//
//  The account used is an Interdomain Trust account. Use your global user account or local user account to access this server.
//
#define STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT ((LONG)0xC0000198L)

//
// MessageId: STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
//
// MessageText:
//
//  The account used is a Computer Account. Use your global user account or local user account to access this server.
//
#define STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT ((LONG)0xC0000199L)

//
// MessageId: STATUS_NOLOGON_SERVER_TRUST_ACCOUNT
//
// MessageText:
//
//  The account used is an Server Trust account. Use your global user account or local user account to access this server.
//
#define STATUS_NOLOGON_SERVER_TRUST_ACCOUNT ((LONG)0xC000019AL)

//
// MessageId: STATUS_DOMAIN_TRUST_INCONSISTENT
//
// MessageText:
//
//  The name or SID of the domain specified is inconsistent with the trust information for that domain.
//
#define STATUS_DOMAIN_TRUST_INCONSISTENT ((LONG)0xC000019BL)

//
// MessageId: STATUS_FS_DRIVER_REQUIRED
//
// MessageText:
//
//  A volume has been accessed for which a file system driver is required that has not yet been loaded.
//
#define STATUS_FS_DRIVER_REQUIRED        ((LONG)0xC000019CL)

//
// MessageId: STATUS_NO_USER_SESSION_KEY
//
// MessageText:
//
//  There is no user session key for the specified logon session.
//
#define STATUS_NO_USER_SESSION_KEY       ((LONG)0xC0000202L)

//
// MessageId: STATUS_USER_SESSION_DELETED
//
// MessageText:
//
//  The remote user session has been deleted.
//
#define STATUS_USER_SESSION_DELETED      ((LONG)0xC0000203L)

//
// MessageId: STATUS_RESOURCE_LANG_NOT_FOUND
//
// MessageText:
//
//  Indicates the specified resource language ID cannot be found in the
//  image file.
//
#define STATUS_RESOURCE_LANG_NOT_FOUND   ((LONG)0xC0000204L)

//
// MessageId: STATUS_INSUFF_SERVER_RESOURCES
//
// MessageText:
//
//  Insufficient server resources exist to complete the request.
//
#define STATUS_INSUFF_SERVER_RESOURCES   ((LONG)0xC0000205L)

//
// MessageId: STATUS_INVALID_BUFFER_SIZE
//
// MessageText:
//
//  The size of the buffer is invalid for the specified operation.
//
#define STATUS_INVALID_BUFFER_SIZE       ((LONG)0xC0000206L)

//
// MessageId: STATUS_INVALID_ADDRESS_COMPONENT
//
// MessageText:
//
//  The transport rejected the network address specified as invalid.
//
#define STATUS_INVALID_ADDRESS_COMPONENT ((LONG)0xC0000207L)

//
// MessageId: STATUS_INVALID_ADDRESS_WILDCARD
//
// MessageText:
//
//  The transport rejected the network address specified due to an invalid use of a wildcard.
//
#define STATUS_INVALID_ADDRESS_WILDCARD  ((LONG)0xC0000208L)

//
// MessageId: STATUS_TOO_MANY_ADDRESSES
//
// MessageText:
//
//  The transport address could not be opened because all the available addresses are in use.
//
#define STATUS_TOO_MANY_ADDRESSES        ((LONG)0xC0000209L)

//
// MessageId: STATUS_ADDRESS_ALREADY_EXISTS
//
// MessageText:
//
//  The transport address could not be opened because it already exists.
//
#define STATUS_ADDRESS_ALREADY_EXISTS    ((LONG)0xC000020AL)

//
// MessageId: STATUS_ADDRESS_CLOSED
//
// MessageText:
//
//  The transport address is now closed.
//
#define STATUS_ADDRESS_CLOSED            ((LONG)0xC000020BL)

//
// MessageId: STATUS_CONNECTION_DISCONNECTED
//
// MessageText:
//
//  The transport connection is now disconnected.
//
#define STATUS_CONNECTION_DISCONNECTED   ((LONG)0xC000020CL)

//
// MessageId: STATUS_CONNECTION_RESET
//
// MessageText:
//
//  The transport connection has been reset.
//
#define STATUS_CONNECTION_RESET          ((LONG)0xC000020DL)

//
// MessageId: STATUS_TOO_MANY_NODES
//
// MessageText:
//
//  The transport cannot dynamically acquire any more nodes.
//
#define STATUS_TOO_MANY_NODES            ((LONG)0xC000020EL)

//
// MessageId: STATUS_TRANSACTION_ABORTED
//
// MessageText:
//
//  The transport aborted a pending transaction.
//
#define STATUS_TRANSACTION_ABORTED       ((LONG)0xC000020FL)

//
// MessageId: STATUS_TRANSACTION_TIMED_OUT
//
// MessageText:
//
//  The transport timed out a request waiting for a response.
//
#define STATUS_TRANSACTION_TIMED_OUT     ((LONG)0xC0000210L)

//
// MessageId: STATUS_TRANSACTION_NO_RELEASE
//
// MessageText:
//
//  The transport did not receive a release for a pending response.
//
#define STATUS_TRANSACTION_NO_RELEASE    ((LONG)0xC0000211L)

//
// MessageId: STATUS_TRANSACTION_NO_MATCH
//
// MessageText:
//
//  The transport did not find a transaction matching the specific
//  token.
//
#define STATUS_TRANSACTION_NO_MATCH      ((LONG)0xC0000212L)

//
// MessageId: STATUS_TRANSACTION_RESPONDED
//
// MessageText:
//
//  The transport had previously responded to a transaction request.
//
#define STATUS_TRANSACTION_RESPONDED     ((LONG)0xC0000213L)

//
// MessageId: STATUS_TRANSACTION_INVALID_ID
//
// MessageText:
//
//  The transport does not recognized the transaction request identifier specified.
//
#define STATUS_TRANSACTION_INVALID_ID    ((LONG)0xC0000214L)

//
// MessageId: STATUS_TRANSACTION_INVALID_TYPE
//
// MessageText:
//
//  The transport does not recognize the transaction request type specified.
//
#define STATUS_TRANSACTION_INVALID_TYPE  ((LONG)0xC0000215L)

//
// MessageId: STATUS_NOT_SERVER_SESSION
//
// MessageText:
//
//  The transport can only process the specified request on the server side of a session.
//
#define STATUS_NOT_SERVER_SESSION        ((LONG)0xC0000216L)

//
// MessageId: STATUS_NOT_CLIENT_SESSION
//
// MessageText:
//
//  The transport can only process the specified request on the client side of a session.
//
#define STATUS_NOT_CLIENT_SESSION        ((LONG)0xC0000217L)

//
// MessageId: STATUS_CANNOT_LOAD_REGISTRY_FILE
//
// MessageText:
//
//  {Registry File Failure}
//  The registry cannot load the hive (file):
//  %hs
//  or its log or alternate.
//  It is corrupt, absent, or not writable.
//
#define STATUS_CANNOT_LOAD_REGISTRY_FILE ((LONG)0xC0000218L)

//
// MessageId: STATUS_DEBUG_ATTACH_FAILED
//
// MessageText:
//
//  {Unexpected Failure in DebugActiveProcess}
//  An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error.
//
#define STATUS_DEBUG_ATTACH_FAILED       ((LONG)0xC0000219L)

//
// MessageId: STATUS_SYSTEM_PROCESS_TERMINATED
//
// MessageText:
//
//  {Fatal System Error}
//  The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x).
//  The system has been shut down.
//
#define STATUS_SYSTEM_PROCESS_TERMINATED ((LONG)0xC000021AL)

//
// MessageId: STATUS_DATA_NOT_ACCEPTED
//
// MessageText:
//
//  {Data Not Accepted}
//  The TDI client could not handle the data received during an indication.
//
#define STATUS_DATA_NOT_ACCEPTED         ((LONG)0xC000021BL)

//
// MessageId: STATUS_NO_BROWSER_SERVERS_FOUND
//
// MessageText:
//
//  {Unable to Retrieve Browser Server List}
//  The list of servers for this workgroup is not currently available.
//
#define STATUS_NO_BROWSER_SERVERS_FOUND  ((LONG)0xC000021CL)

//
// MessageId: STATUS_VDM_HARD_ERROR
//
// MessageText:
//
//  NTVDM encountered a hard error.
//
#define STATUS_VDM_HARD_ERROR            ((LONG)0xC000021DL)

//
// MessageId: STATUS_DRIVER_CANCEL_TIMEOUT
//
// MessageText:
//
//  {Cancel Timeout}
//  The driver %hs failed to complete a cancelled I/O request in the allotted time.
//
#define STATUS_DRIVER_CANCEL_TIMEOUT     ((LONG)0xC000021EL)

//
// MessageId: STATUS_REPLY_MESSAGE_MISMATCH
//
// MessageText:
//
//  {Reply Message Mismatch}
//  An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message.
//
#define STATUS_REPLY_MESSAGE_MISMATCH    ((LONG)0xC000021FL)

//
// MessageId: STATUS_MAPPED_ALIGNMENT
//
// MessageText:
//
//  {Mapped View Alignment Incorrect}
//  An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity.
//
#define STATUS_MAPPED_ALIGNMENT          ((LONG)0xC0000220L)

//
// MessageId: STATUS_IMAGE_CHECKSUM_MISMATCH
//
// MessageText:
//
//  {Bad Image Checksum}
//  The image %hs is possibly corrupt. The header checksum does not match the computed checksum.
//
#define STATUS_IMAGE_CHECKSUM_MISMATCH   ((LONG)0xC0000221L)

//
// MessageId: STATUS_LOST_WRITEBEHIND_DATA
//
// MessageText:
//
//  {Delayed Write Failed}
//  Windows was unable to save all the data for the file %hs. The data has been lost.
//  This error may be caused by a failure of your computer hardware or network connection. Please try to save this file elsewhere.
//
#define STATUS_LOST_WRITEBEHIND_DATA     ((LONG)0xC0000222L)

//
// MessageId: STATUS_CLIENT_SERVER_PARAMETERS_INVALID
//
// MessageText:
//
//  The parameter(s) passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window.
//
#define STATUS_CLIENT_SERVER_PARAMETERS_INVALID ((LONG)0xC0000223L)

//
// MessageId: STATUS_PASSWORD_MUST_CHANGE
//
// MessageText:
//
//  The user's password must be changed before logging on the first time.
//
#define STATUS_PASSWORD_MUST_CHANGE      ((LONG)0xC0000224L)    // ntsubauth

//
// MessageId: STATUS_NOT_FOUND
//
// MessageText:
//
//  The object was not found.
//
#define STATUS_NOT_FOUND                 ((LONG)0xC0000225L)

//
// MessageId: STATUS_NOT_TINY_STREAM
//
// MessageText:
//
//  The stream is not a tiny stream.
//
#define STATUS_NOT_TINY_STREAM           ((LONG)0xC0000226L)

//
// MessageId: STATUS_RECOVERY_FAILURE
//
// MessageText:
//
//  A transaction recover failed.
//
#define STATUS_RECOVERY_FAILURE          ((LONG)0xC0000227L)

//
// MessageId: STATUS_STACK_OVERFLOW_READ
//
// MessageText:
//
//  The request must be handled by the stack overflow code.
//
#define STATUS_STACK_OVERFLOW_READ       ((LONG)0xC0000228L)

//
// MessageId: STATUS_FAIL_CHECK
//
// MessageText:
//
//  A consistency check failed.
//
#define STATUS_FAIL_CHECK                ((LONG)0xC0000229L)

//
// MessageId: STATUS_DUPLICATE_OBJECTID
//
// MessageText:
//
//  The attempt to insert the ID in the index failed because the ID is already in the index.
//
#define STATUS_DUPLICATE_OBJECTID        ((LONG)0xC000022AL)

//
// MessageId: STATUS_OBJECTID_EXISTS
//
// MessageText:
//
//  The attempt to set the object's ID failed because the object already has an ID.
//
#define STATUS_OBJECTID_EXISTS           ((LONG)0xC000022BL)

//
// MessageId: STATUS_CONVERT_TO_LARGE
//
// MessageText:
//
//  Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing onode is moved or the extent stream is converted to a large stream.
//
#define STATUS_CONVERT_TO_LARGE          ((LONG)0xC000022CL)

//
// MessageId: STATUS_RETRY
//
// MessageText:
//
//  The request needs to be retried.
//
#define STATUS_RETRY                     ((LONG)0xC000022DL)

//
// MessageId: STATUS_FOUND_OUT_OF_SCOPE
//
// MessageText:
//
//  The attempt to find the object found an object matching by ID on the volume but it is out of the scope of the handle used for the operation.
//
#define STATUS_FOUND_OUT_OF_SCOPE        ((LONG)0xC000022EL)

//
// MessageId: STATUS_ALLOCATE_BUCKET
//
// MessageText:
//
//  The bucket array must be grown. Retry transaction after doing so.
//
#define STATUS_ALLOCATE_BUCKET           ((LONG)0xC000022FL)

//
// MessageId: STATUS_PROPSET_NOT_FOUND
//
// MessageText:
//
//  The property set specified does not exist on the object.
//
#define STATUS_PROPSET_NOT_FOUND         ((LONG)0xC0000230L)

//
// MessageId: STATUS_MARSHALL_OVERFLOW
//
// MessageText:
//
//  The user/kernel marshalling buffer has overflowed.
//
#define STATUS_MARSHALL_OVERFLOW         ((LONG)0xC0000231L)

//
// MessageId: STATUS_INVALID_VARIANT
//
// MessageText:
//
//  The supplied variant structure contains invalid data.
//
#define STATUS_INVALID_VARIANT           ((LONG)0xC0000232L)

//
// MessageId: STATUS_DOMAIN_CONTROLLER_NOT_FOUND
//
// MessageText:
//
//  Could not find a domain controller for this domain.
//
#define STATUS_DOMAIN_CONTROLLER_NOT_FOUND ((LONG)0xC0000233L)

//
// MessageId: STATUS_ACCOUNT_LOCKED_OUT
//
// MessageText:
//
//  The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested.
//
#define STATUS_ACCOUNT_LOCKED_OUT        ((LONG)0xC0000234L)    // ntsubauth

//
// MessageId: STATUS_HANDLE_NOT_CLOSABLE
//
// MessageText:
//
//  NtClose was called on a handle that was protected from close via NtSetInformationObject.
//
#define STATUS_HANDLE_NOT_CLOSABLE       ((LONG)0xC0000235L)

//
// MessageId: STATUS_CONNECTION_REFUSED
//
// MessageText:
//
//  The transport connection attempt was refused by the remote system.
//
#define STATUS_CONNECTION_REFUSED        ((LONG)0xC0000236L)

//
// MessageId: STATUS_GRACEFUL_DISCONNECT
//
// MessageText:
//
//  The transport connection was gracefully closed.
//
#define STATUS_GRACEFUL_DISCONNECT       ((LONG)0xC0000237L)

//
// MessageId: STATUS_ADDRESS_ALREADY_ASSOCIATED
//
// MessageText:
//
//  The transport endpoint already has an address associated with it.
//
#define STATUS_ADDRESS_ALREADY_ASSOCIATED ((LONG)0xC0000238L)

//
// MessageId: STATUS_ADDRESS_NOT_ASSOCIATED
//
// MessageText:
//
//  An address has not yet been associated with the transport endpoint.
//
#define STATUS_ADDRESS_NOT_ASSOCIATED    ((LONG)0xC0000239L)

//
// MessageId: STATUS_CONNECTION_INVALID
//
// MessageText:
//
//  An operation was attempted on a nonexistent transport connection.
//
#define STATUS_CONNECTION_INVALID        ((LONG)0xC000023AL)

//
// MessageId: STATUS_CONNECTION_ACTIVE
//
// MessageText:
//
//  An invalid operation was attempted on an active transport connection.
//
#define STATUS_CONNECTION_ACTIVE         ((LONG)0xC000023BL)

//
// MessageId: STATUS_NETWORK_UNREACHABLE
//
// MessageText:
//
//  The remote network is not reachable by the transport.
//
#define STATUS_NETWORK_UNREACHABLE       ((LONG)0xC000023CL)

//
// MessageId: STATUS_HOST_UNREACHABLE
//
// MessageText:
//
//  The remote system is not reachable by the transport.
//
#define STATUS_HOST_UNREACHABLE          ((LONG)0xC000023DL)

//
// MessageId: STATUS_PROTOCOL_UNREACHABLE
//
// MessageText:
//
//  The remote system does not support the transport protocol.
//
#define STATUS_PROTOCOL_UNREACHABLE      ((LONG)0xC000023EL)

//
// MessageId: STATUS_PORT_UNREACHABLE
//
// MessageText:
//
//  No service is operating at the destination port of the transport on the remote system.
//
#define STATUS_PORT_UNREACHABLE          ((LONG)0xC000023FL)

//
// MessageId: STATUS_REQUEST_ABORTED
//
// MessageText:
//
//  The request was aborted.
//
#define STATUS_REQUEST_ABORTED           ((LONG)0xC0000240L)

//
// MessageId: STATUS_CONNECTION_ABORTED
//
// MessageText:
//
//  The transport connection was aborted by the local system.
//
#define STATUS_CONNECTION_ABORTED        ((LONG)0xC0000241L)

//
// MessageId: STATUS_BAD_COMPRESSION_BUFFER
//
// MessageText:
//
//  The specified buffer contains ill-formed data.
//
#define STATUS_BAD_COMPRESSION_BUFFER    ((LONG)0xC0000242L)

//
// MessageId: STATUS_USER_MAPPED_FILE
//
// MessageText:
//
//  The requested operation cannot be performed on a file with a user mapped section open.
//
#define STATUS_USER_MAPPED_FILE          ((LONG)0xC0000243L)

//
// MessageId: STATUS_AUDIT_FAILED
//
// MessageText:
//
//  {Audit Failed}
//  An attempt to generate a security audit failed.
//
#define STATUS_AUDIT_FAILED              ((LONG)0xC0000244L)

//
// MessageId: STATUS_TIMER_RESOLUTION_NOT_SET
//
// MessageText:
//
//  The timer resolution was not previously set by the current process.
//
#define STATUS_TIMER_RESOLUTION_NOT_SET  ((LONG)0xC0000245L)

//
// MessageId: STATUS_CONNECTION_COUNT_LIMIT
//
// MessageText:
//
//  A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.
//
#define STATUS_CONNECTION_COUNT_LIMIT    ((LONG)0xC0000246L)

//
// MessageId: STATUS_LOGIN_TIME_RESTRICTION
//
// MessageText:
//
//  Attempting to login during an unauthorized time of day for this account.
//
#define STATUS_LOGIN_TIME_RESTRICTION    ((LONG)0xC0000247L)

//
// MessageId: STATUS_LOGIN_WKSTA_RESTRICTION
//
// MessageText:
//
//  The account is not authorized to login from this station.
//
#define STATUS_LOGIN_WKSTA_RESTRICTION   ((LONG)0xC0000248L)

//
// MessageId: STATUS_IMAGE_MP_UP_MISMATCH
//
// MessageText:
//
//  {UP/MP Image Mismatch}
//  The image %hs has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine.
//  Please reinstall the image file.
//
#define STATUS_IMAGE_MP_UP_MISMATCH      ((LONG)0xC0000249L)

//
// MessageId: STATUS_INSUFFICIENT_LOGON_INFO
//
// MessageText:
//
//  There is insufficient account information to log you on.
//
#define STATUS_INSUFFICIENT_LOGON_INFO   ((LONG)0xC0000250L)

//
// MessageId: STATUS_BAD_DLL_ENTRYPOINT
//
// MessageText:
//
//  {Invalid DLL Entrypoint}
//  The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state.
//  The entrypoint should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly.
//
#define STATUS_BAD_DLL_ENTRYPOINT        ((LONG)0xC0000251L)

//
// MessageId: STATUS_BAD_SERVICE_ENTRYPOINT
//
// MessageText:
//
//  {Invalid Service Callback Entrypoint}
//  The %hs service is not written correctly. The stack pointer has been left in an inconsistent state.
//  The callback entrypoint should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly.
//
#define STATUS_BAD_SERVICE_ENTRYPOINT    ((LONG)0xC0000252L)

//
// MessageId: STATUS_LPC_REPLY_LOST
//
// MessageText:
//
//  The server received the messages but did not send a reply.
//
#define STATUS_LPC_REPLY_LOST            ((LONG)0xC0000253L)

//
// MessageId: STATUS_IP_ADDRESS_CONFLICT1
//
// MessageText:
//
//  There is an IP address conflict with another system on the network
//
#define STATUS_IP_ADDRESS_CONFLICT1      ((LONG)0xC0000254L)

//
// MessageId: STATUS_IP_ADDRESS_CONFLICT2
//
// MessageText:
//
//  There is an IP address conflict with another system on the network
//
#define STATUS_IP_ADDRESS_CONFLICT2      ((LONG)0xC0000255L)

//
// MessageId: STATUS_REGISTRY_QUOTA_LIMIT
//
// MessageText:
//
//  {Low On Registry Space}
//  The system has reached the maximum size allowed for the system part of the registry.  Additional storage requests will be ignored.
//
#define STATUS_REGISTRY_QUOTA_LIMIT      ((LONG)0xC0000256L)

//
// MessageId: STATUS_PATH_NOT_COVERED
//
// MessageText:
//
//  The contacted server does not support the indicated part of the DFS namespace.
//
#define STATUS_PATH_NOT_COVERED          ((LONG)0xC0000257L)

//
// MessageId: STATUS_NO_CALLBACK_ACTIVE
//
// MessageText:
//
//  A callback return system service cannot be executed when no callback is active.
//
#define STATUS_NO_CALLBACK_ACTIVE        ((LONG)0xC0000258L)

//
// MessageId: STATUS_LICENSE_QUOTA_EXCEEDED
//
// MessageText:
//
//  The service being accessed is licensed for a particular number of connections.
//  No more connections can be made to the service at this time because there are already as many connections as the service can accept.
//
#define STATUS_LICENSE_QUOTA_EXCEEDED    ((LONG)0xC0000259L)

//
// MessageId: STATUS_PWD_TOO_SHORT
//
// MessageText:
//
//  The password provided is too short to meet the policy of your user account.
//  Please choose a longer password.
//
#define STATUS_PWD_TOO_SHORT             ((LONG)0xC000025AL)

//
// MessageId: STATUS_PWD_TOO_RECENT
//
// MessageText:
//
//  The policy of your user account does not allow you to change passwords too frequently.
//  This is done to prevent users from changing back to a familiar, but potentially discovered, password.
//  If you feel your password has been compromised then please contact your administrator immediately to have a new one assigned.
//
#define STATUS_PWD_TOO_RECENT            ((LONG)0xC000025BL)

//
// MessageId: STATUS_PWD_HISTORY_CONFLICT
//
// MessageText:
//
//  You have attempted to change your password to one that you have used in the past.
//  The policy of your user account does not allow this. Please select a password that you have not previously used.
//
#define STATUS_PWD_HISTORY_CONFLICT      ((LONG)0xC000025CL)

//
// MessageId: STATUS_PLUGPLAY_NO_DEVICE
//
// MessageText:
//
//  You have attempted to load a legacy device driver while its device instance had been disabled.
//
#define STATUS_PLUGPLAY_NO_DEVICE        ((LONG)0xC000025EL)

//
// MessageId: STATUS_UNSUPPORTED_COMPRESSION
//
// MessageText:
//
//  The specified compression format is unsupported.
//
#define STATUS_UNSUPPORTED_COMPRESSION   ((LONG)0xC000025FL)

//
// MessageId: STATUS_INVALID_HW_PROFILE
//
// MessageText:
//
//  The specified hardware profile configuration is invalid.
//
#define STATUS_INVALID_HW_PROFILE        ((LONG)0xC0000260L)

//
// MessageId: STATUS_INVALID_PLUGPLAY_DEVICE_PATH
//
// MessageText:
//
//  The specified Plug and Play registry device path is invalid.
//
#define STATUS_INVALID_PLUGPLAY_DEVICE_PATH ((LONG)0xC0000261L)

//
// MessageId: STATUS_DRIVER_ORDINAL_NOT_FOUND
//
// MessageText:
//
//  {Driver Entry Point Not Found}
//  The %hs device driver could not locate the ordinal %ld in driver %hs.
//
#define STATUS_DRIVER_ORDINAL_NOT_FOUND  ((LONG)0xC0000262L)

//
// MessageId: STATUS_DRIVER_ENTRYPOINT_NOT_FOUND
//
// MessageText:
//
//  {Driver Entry Point Not Found}
//  The %hs device driver could not locate the entry point %hs in driver %hs.
//
#define STATUS_DRIVER_ENTRYPOINT_NOT_FOUND ((LONG)0xC0000263L)

//
// MessageId: STATUS_RESOURCE_NOT_OWNED
//
// MessageText:
//
//  {Application Error}
//  The application attempted to release a resource it did not own. Click on OK to terminate the application.
//
#define STATUS_RESOURCE_NOT_OWNED        ((LONG)0xC0000264L)

//
// MessageId: STATUS_TOO_MANY_LINKS
//
// MessageText:
//
//  An attempt was made to create more links on a file than the file system supports.
//
#define STATUS_TOO_MANY_LINKS            ((LONG)0xC0000265L)

//
// MessageId: STATUS_QUOTA_LIST_INCONSISTENT
//
// MessageText:
//
//  The specified quota list is internally inconsistent with its descriptor.
//
#define STATUS_QUOTA_LIST_INCONSISTENT   ((LONG)0xC0000266L)

//
// MessageId: STATUS_FILE_IS_OFFLINE
//
// MessageText:
//
//  The specified file has been relocated to offline storage.
//
#define STATUS_FILE_IS_OFFLINE           ((LONG)0xC0000267L)

//
// MessageId: STATUS_EVALUATION_EXPIRATION
//
// MessageText:
//
//  {Windows Evaluation Notification}
//  The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour. To restore access to this installation of Windows, please upgrade this installation using a licensed distribution of this product.
//
#define STATUS_EVALUATION_EXPIRATION     ((LONG)0xC0000268L)

//
// MessageId: STATUS_ILLEGAL_DLL_RELOCATION
//
// MessageText:
//
//  {Illegal System DLL Relocation}
//  The system DLL %hs was relocated in memory. The application will not run properly.
//  The relocation occurred because the DLL %hs occupied an address range reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.
//
#define STATUS_ILLEGAL_DLL_RELOCATION    ((LONG)0xC0000269L)

//
// MessageId: STATUS_LICENSE_VIOLATION
//
// MessageText:
//
//  {License Violation}
//  The system has detected tampering with your registered product type. This is a violation of your software license. Tampering with product type is not permitted.
//
#define STATUS_LICENSE_VIOLATION         ((LONG)0xC000026AL)

//
// MessageId: STATUS_DLL_INIT_FAILED_LOGOFF
//
// MessageText:
//
//  {DLL Initialization Failed}
//  The application failed to initialize because the window station is shutting down.
//
#define STATUS_DLL_INIT_FAILED_LOGOFF    ((LONG)0xC000026BL)

//
// MessageId: STATUS_DRIVER_UNABLE_TO_LOAD
//
// MessageText:
//
//  {Unable to Load Device Driver}
//  %hs device driver could not be loaded.
//  Error Status was 0x%x
//
#define STATUS_DRIVER_UNABLE_TO_LOAD     ((LONG)0xC000026CL)

//
// MessageId: STATUS_DFS_UNAVAILABLE
//
// MessageText:
//
//  DFS is unavailable on the contacted server.
//
#define STATUS_DFS_UNAVAILABLE           ((LONG)0xC000026DL)

//
// MessageId: STATUS_VOLUME_DISMOUNTED
//
// MessageText:
//
//  An operation was attempted to a volume after it was dismounted.
//
#define STATUS_VOLUME_DISMOUNTED         ((LONG)0xC000026EL)

//
// MessageId: STATUS_WX86_INTERNAL_ERROR
//
// MessageText:
//
//  An internal error occurred in the Win32 x86 emulation subsystem.
//
#define STATUS_WX86_INTERNAL_ERROR       ((LONG)0xC000026FL)

//
// MessageId: STATUS_WX86_FLOAT_STACK_CHECK
//
// MessageText:
//
//  Win32 x86 emulation subsystem Floating-point stack check.
//
#define STATUS_WX86_FLOAT_STACK_CHECK    ((LONG)0xC0000270L)

//
// MessageId: STATUS_VALIDATE_CONTINUE
//
// MessageText:
//
//  The validation process needs to continue on to the next step.
//
#define STATUS_VALIDATE_CONTINUE         ((LONG)0xC0000271L)

//
// MessageId: STATUS_NO_MATCH
//
// MessageText:
//
//  There was no match for the specified key in the index.
//
#define STATUS_NO_MATCH                  ((LONG)0xC0000272L)

//
// MessageId: STATUS_NO_MORE_MATCHES
//
// MessageText:
//
//  There are no more matches for the current index enumeration.
//
#define STATUS_NO_MORE_MATCHES           ((LONG)0xC0000273L)

//
// MessageId: STATUS_NOT_A_REPARSE_POINT
//
// MessageText:
//
//  The NTFS file or directory is not a reparse point.
//
#define STATUS_NOT_A_REPARSE_POINT       ((LONG)0xC0000275L)

//
// MessageId: STATUS_IO_REPARSE_TAG_INVALID
//
// MessageText:
//
//  The Windows I/O reparse tag passed for the NTFS reparse point is invalid.
//
#define STATUS_IO_REPARSE_TAG_INVALID    ((LONG)0xC0000276L)

//
// MessageId: STATUS_IO_REPARSE_TAG_MISMATCH
//
// MessageText:
//
//  The Windows I/O reparse tag does not match the one present in the NTFS reparse point.
//
#define STATUS_IO_REPARSE_TAG_MISMATCH   ((LONG)0xC0000277L)

//
// MessageId: STATUS_IO_REPARSE_DATA_INVALID
//
// MessageText:
//
//  The user data passed for the NTFS reparse point is invalid.
//
#define STATUS_IO_REPARSE_DATA_INVALID   ((LONG)0xC0000278L)

//
// MessageId: STATUS_IO_REPARSE_TAG_NOT_HANDLED
//
// MessageText:
//
//  The layered file system driver for this IO tag did not handle it when needed.
//
#define STATUS_IO_REPARSE_TAG_NOT_HANDLED ((LONG)0xC0000279L)

//
// MessageId: STATUS_REPARSE_POINT_NOT_RESOLVED
//
// MessageText:
//
//  The NTFS symbolic link could not be resolved even though the initial file name is valid.
//
#define STATUS_REPARSE_POINT_NOT_RESOLVED ((LONG)0xC0000280L)

//
// MessageId: STATUS_DIRECTORY_IS_A_REPARSE_POINT
//
// MessageText:
//
//  The NTFS directory is a reparse point.
//
#define STATUS_DIRECTORY_IS_A_REPARSE_POINT ((LONG)0xC0000281L)

//
// MessageId: STATUS_RANGE_LIST_CONFLICT
//
// MessageText:
//
//  The range could not be added to the range list because of a conflict.
//
#define STATUS_RANGE_LIST_CONFLICT       ((LONG)0xC0000282L)

//
// MessageId: STATUS_SOURCE_ELEMENT_EMPTY
//
// MessageText:
//
//  The specified medium changer source element contains no media.
//
#define STATUS_SOURCE_ELEMENT_EMPTY      ((LONG)0xC0000283L)

//
// MessageId: STATUS_DESTINATION_ELEMENT_FULL
//
// MessageText:
//
//  The specified medium changer destination element already contains media.
//
#define STATUS_DESTINATION_ELEMENT_FULL  ((LONG)0xC0000284L)

//
// MessageId: STATUS_ILLEGAL_ELEMENT_ADDRESS
//
// MessageText:
//
//  The specified medium changer element does not exist.
//
#define STATUS_ILLEGAL_ELEMENT_ADDRESS   ((LONG)0xC0000285L)

//
// MessageId: STATUS_MAGAZINE_NOT_PRESENT
//
// MessageText:
//
//  The specified element is contained within a magazine that is no longer present.
//
#define STATUS_MAGAZINE_NOT_PRESENT      ((LONG)0xC0000286L)

//
// MessageId: STATUS_REINITIALIZATION_NEEDED
//
// MessageText:
//
//  The device requires reinitialization due to hardware errors.
//
#define STATUS_REINITIALIZATION_NEEDED   ((LONG)0xC0000287L)

//
// MessageId: STATUS_DEVICE_REQUIRES_CLEANING
//
// MessageText:
//
//  The device has indicated that cleaning is necessary.
//
#define STATUS_DEVICE_REQUIRES_CLEANING  ((LONG)0x80000288L)

//
// MessageId: STATUS_DEVICE_DOOR_OPEN
//
// MessageText:
//
//  The device has indicated that it's door is open. Further operations require it closed and secured.
//
#define STATUS_DEVICE_DOOR_OPEN          ((LONG)0x80000289L)

//
// MessageId: STATUS_ENCRYPTION_FAILED
//
// MessageText:
//
//  The file encryption attempt failed.
//
#define STATUS_ENCRYPTION_FAILED         ((LONG)0xC000028AL)

//
// MessageId: STATUS_DECRYPTION_FAILED
//
// MessageText:
//
//  The file decryption attempt failed.
//
#define STATUS_DECRYPTION_FAILED         ((LONG)0xC000028BL)

//
// MessageId: STATUS_RANGE_NOT_FOUND
//
// MessageText:
//
//  The specified range could not be found in the range list.
//
#define STATUS_RANGE_NOT_FOUND           ((LONG)0xC000028CL)

//
// MessageId: STATUS_NO_RECOVERY_POLICY
//
// MessageText:
//
//  There is no encryption recovery policy configured for this system.
//
#define STATUS_NO_RECOVERY_POLICY        ((LONG)0xC000028DL)

//
// MessageId: STATUS_NO_EFS
//
// MessageText:
//
//  The required encryption driver is not loaded for this system.
//
#define STATUS_NO_EFS                    ((LONG)0xC000028EL)

//
// MessageId: STATUS_WRONG_EFS
//
// MessageText:
//
//  The file was encrypted with a different encryption driver than is currently loaded.
//
#define STATUS_WRONG_EFS                 ((LONG)0xC000028FL)

//
// MessageId: STATUS_NO_USER_KEYS
//
// MessageText:
//
//  There are no EFS keys defined for the user.
//
#define STATUS_NO_USER_KEYS              ((LONG)0xC0000290L)

//
// MessageId: STATUS_FILE_NOT_ENCRYPTED
//
// MessageText:
//
//  The specified file is not encrypted.
//
#define STATUS_FILE_NOT_ENCRYPTED        ((LONG)0xC0000291L)

//
// MessageId: STATUS_NOT_EXPORT_FORMAT
//
// MessageText:
//
//  The specified file is not in the defined EFS export format.
//
#define STATUS_NOT_EXPORT_FORMAT         ((LONG)0xC0000292L)

//
// MessageId: STATUS_FILE_ENCRYPTED
//
// MessageText:
//
//  The specified file is encrypted and the user does not have the ability to decrypt it.
//
#define STATUS_FILE_ENCRYPTED            ((LONG)0xC0000293L)

//
// MessageId: STATUS_WAKE_SYSTEM
//
// MessageText:
//
//  The system has awoken
//
#define STATUS_WAKE_SYSTEM               ((LONG)0x40000294L)

//
// MessageId: STATUS_WMI_GUID_NOT_FOUND
//
// MessageText:
//
//  The guid passed was not recognized as valid by a WMI data provider.
//
#define STATUS_WMI_GUID_NOT_FOUND        ((LONG)0xC0000295L)

//
// MessageId: STATUS_WMI_INSTANCE_NOT_FOUND
//
// MessageText:
//
//  The instance name passed was not recognized as valid by a WMI data provider.
//
#define STATUS_WMI_INSTANCE_NOT_FOUND    ((LONG)0xC0000296L)

//
// MessageId: STATUS_WMI_ITEMID_NOT_FOUND
//
// MessageText:
//
//  The data item id passed was not recognized as valid by a WMI data provider.
//
#define STATUS_WMI_ITEMID_NOT_FOUND      ((LONG)0xC0000297L)

//
// MessageId: STATUS_WMI_TRY_AGAIN
//
// MessageText:
//
//  The WMI request could not be completed and should be retried.
//
#define STATUS_WMI_TRY_AGAIN             ((LONG)0xC0000298L)

//
// MessageId: STATUS_SHARED_POLICY
//
// MessageText:
//
//  The policy object is shared and can only be modified at the root
//
#define STATUS_SHARED_POLICY             ((LONG)0xC0000299L)

//
// MessageId: STATUS_POLICY_OBJECT_NOT_FOUND
//
// MessageText:
//
//  The policy object does not exist when it should
//
#define STATUS_POLICY_OBJECT_NOT_FOUND   ((LONG)0xC000029AL)

//
// MessageId: STATUS_POLICY_ONLY_IN_DS
//
// MessageText:
//
//  The requested policy information only lives in the Ds
//
#define STATUS_POLICY_ONLY_IN_DS         ((LONG)0xC000029BL)

//
// MessageId: STATUS_VOLUME_NOT_UPGRADED
//
// MessageText:
//
//  The volume must be upgraded to enable this feature
//
#define STATUS_VOLUME_NOT_UPGRADED       ((LONG)0xC000029CL)

//
// MessageId: STATUS_REMOTE_STORAGE_NOT_ACTIVE
//
// MessageText:
//
//  The remote storage service is not operational at this time.
//
#define STATUS_REMOTE_STORAGE_NOT_ACTIVE ((LONG)0xC000029DL)

//
// MessageId: STATUS_REMOTE_STORAGE_MEDIA_ERROR
//
// MessageText:
//
//  The remote storage service encountered a media error.
//
#define STATUS_REMOTE_STORAGE_MEDIA_ERROR ((LONG)0xC000029EL)

//
// MessageId: STATUS_NO_TRACKING_SERVICE
//
// MessageText:
//
//  The tracking (workstation) service is not running.
//
#define STATUS_NO_TRACKING_SERVICE       ((LONG)0xC000029FL)

//
// MessageId: STATUS_SERVER_SID_MISMATCH
//
// MessageText:
//
//  The server process is running under a SID different than that required by client.
//
#define STATUS_SERVER_SID_MISMATCH       ((LONG)0xC00002A0L)

//
// Directory Service specific Errors
//
//
// MessageId: STATUS_DS_NO_ATTRIBUTE_OR_VALUE
//
// MessageText:
//
//  The specified directory service attribute or value does not exist.
//
#define STATUS_DS_NO_ATTRIBUTE_OR_VALUE  ((LONG)0xC00002A1L)

//
// MessageId: STATUS_DS_INVALID_ATTRIBUTE_SYNTAX
//
// MessageText:
//
//  The attribute syntax specified to the directory service is invalid.
//
#define STATUS_DS_INVALID_ATTRIBUTE_SYNTAX ((LONG)0xC00002A2L)

//
// MessageId: STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED
//
// MessageText:
//
//  The attribute type specified to the directory service is not defined.
//
#define STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED ((LONG)0xC00002A3L)

//
// MessageId: STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS
//
// MessageText:
//
//  The specified directory service attribute or value already exists.
//
#define STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS ((LONG)0xC00002A4L)

//
// MessageId: STATUS_DS_BUSY
//
// MessageText:
//
//  The directory service is busy.
//
#define STATUS_DS_BUSY                   ((LONG)0xC00002A5L)

//
// MessageId: STATUS_DS_UNAVAILABLE
//
// MessageText:
//
//  The directory service is not available.
//
#define STATUS_DS_UNAVAILABLE            ((LONG)0xC00002A6L)

//
// MessageId: STATUS_DS_NO_RIDS_ALLOCATED
//
// MessageText:
//
//  The directory service was unable to allocate a relative identifier.
//
#define STATUS_DS_NO_RIDS_ALLOCATED      ((LONG)0xC00002A7L)

//
// MessageId: STATUS_DS_NO_MORE_RIDS
//
// MessageText:
//
//  The directory service has exhausted the pool of relative identifiers.
//
#define STATUS_DS_NO_MORE_RIDS           ((LONG)0xC00002A8L)

//
// MessageId: STATUS_DS_INCORRECT_ROLE_OWNER
//
// MessageText:
//
//  The requested operation could not be performed because the directory service is not the master for that type of operation.
//
#define STATUS_DS_INCORRECT_ROLE_OWNER   ((LONG)0xC00002A9L)

//
// MessageId: STATUS_DS_RIDMGR_INIT_ERROR
//
// MessageText:
//
//  The directory service was unable to initialize the subsystem that allocates relative identifiers.
//
#define STATUS_DS_RIDMGR_INIT_ERROR      ((LONG)0xC00002AAL)

//
// MessageId: STATUS_DS_OBJ_CLASS_VIOLATION
//
// MessageText:
//
//  The requested operation did not satisfy one or more constraints associated with the class of the object.
//
#define STATUS_DS_OBJ_CLASS_VIOLATION    ((LONG)0xC00002ABL)

//
// MessageId: STATUS_DS_CANT_ON_NON_LEAF
//
// MessageText:
//
//  The directory service can perform the requested operation only on a leaf object.
//
#define STATUS_DS_CANT_ON_NON_LEAF       ((LONG)0xC00002ACL)

//
// MessageId: STATUS_DS_CANT_ON_RDN
//
// MessageText:
//
//  The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object.
//
#define STATUS_DS_CANT_ON_RDN            ((LONG)0xC00002ADL)

//
// MessageId: STATUS_DS_CANT_MOD_OBJ_CLASS
//
// MessageText:
//
//  The directory service detected an attempt to modify the object class of an object.
//
#define STATUS_DS_CANT_MOD_OBJ_CLASS     ((LONG)0xC00002AEL)

//
// MessageId: STATUS_DS_CROSS_DOM_MOVE_FAILED
//
// MessageText:
//
//  An error occurred while performing a cross domain move operation.
//
#define STATUS_DS_CROSS_DOM_MOVE_FAILED  ((LONG)0xC00002AFL)

//
// MessageId: STATUS_DS_GC_NOT_AVAILABLE
//
// MessageText:
//
//  Unable to Contact the Global Catalog Server.
//
#define STATUS_DS_GC_NOT_AVAILABLE       ((LONG)0xC00002B0L)

//
// MessageId: STATUS_DIRECTORY_SERVICE_REQUIRED
//
// MessageText:
//
//  The requested operation requires a directory service, and none was available.
//
#define STATUS_DIRECTORY_SERVICE_REQUIRED ((LONG)0xC00002B1L)

//
// MessageId: STATUS_REPARSE_ATTRIBUTE_CONFLICT
//
// MessageText:
//
//  The reparse attribute cannot be set as it is incompatible with an existing attribute.
//
#define STATUS_REPARSE_ATTRIBUTE_CONFLICT ((LONG)0xC00002B2L)

//
// MessageId: STATUS_CANT_ENABLE_DENY_ONLY
//
// MessageText:
//
//  A group marked use for deny only  can not be enabled.
//
#define STATUS_CANT_ENABLE_DENY_ONLY     ((LONG)0xC00002B3L)

//
// MessageId: STATUS_DEVICE_REMOVED
//
// MessageText:
//
//  The device has been removed.
//
#define STATUS_DEVICE_REMOVED            ((LONG)0xC00002B6L)

//
// MessageId: STATUS_JOURNAL_DELETE_IN_PROGRESS
//
// MessageText:
//
//  The volume change journal is being deleted.
//
#define STATUS_JOURNAL_DELETE_IN_PROGRESS ((LONG)0xC00002B7L)

//
// MessageId: STATUS_JOURNAL_NOT_ACTIVE
//
// MessageText:
//
//  The volume change journal is not active.
//
#define STATUS_JOURNAL_NOT_ACTIVE        ((LONG)0xC00002B8L)

//
// MessageId: STATUS_NOINTERFACE
//
// MessageText:
//
//  The requested interface is not supported.
//
#define STATUS_NOINTERFACE               ((LONG)0xC00002B9L)

//
// MessageId: STATUS_DS_ADMIN_LIMIT_EXCEEDED
//
// MessageText:
//
//  A directory service resource limit has been exceeded.
//
#define STATUS_DS_ADMIN_LIMIT_EXCEEDED   ((LONG)0xC00002C1L)

//
// MessageId: STATUS_DRIVER_FAILED_SLEEP
//
// MessageText:
//
//  {System Standby Failed}
//  The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode.
//
#define STATUS_DRIVER_FAILED_SLEEP       ((LONG)0xC00002C2L)

//
// MessageId: STATUS_MUTUAL_AUTHENTICATION_FAILED
//
// MessageText:
//
//  Mutual Authentication failed. The server's password is out of date at the domain controller.
//
#define STATUS_MUTUAL_AUTHENTICATION_FAILED ((LONG)0xC00002C3L)

//
// MessageId: STATUS_CORRUPT_SYSTEM_FILE
//
// MessageText:
//
//  The system file %1 has become corrupt and has been replaced.
//
#define STATUS_CORRUPT_SYSTEM_FILE       ((LONG)0xC00002C4L)

//
// MessageId: STATUS_DATATYPE_MISALIGNMENT_ERROR
//
// MessageText:
//
//  {EXCEPTION}
//  Alignment Error
//  A datatype misalignment error was detected in a load or store instruction.
//
#define STATUS_DATATYPE_MISALIGNMENT_ERROR ((LONG)0xC00002C5L)    

//
// MessageId: STATUS_WMI_READ_ONLY
//
// MessageText:
//
//  The WMI data item or data block is read only.
//
#define STATUS_WMI_READ_ONLY             ((LONG)0xC00002C6L)

//
// MessageId: STATUS_WMI_SET_FAILURE
//
// MessageText:
//
//  The WMI data item or data block could not be changed.
//
#define STATUS_WMI_SET_FAILURE           ((LONG)0xC00002C7L)

//
// MessageId: STATUS_COMMITMENT_MINIMUM
//
// MessageText:
//
//  {Virtual Memory Minimum Too Low}
//  Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file.
//  During this process, memory requests for some applications may be denied. For more information, see Help.
//
#define STATUS_COMMITMENT_MINIMUM        ((LONG)0xC00002C8L)

//
// MessageId: STATUS_TRANSPORT_FULL
//
// MessageText:
//
//  The medium changer's transport element contains media, which is causing the operation to fail.
//
#define STATUS_TRANSPORT_FULL            ((LONG)0xC00002CAL)

//
// MessageId: STATUS_DS_SAM_INIT_FAILURE
//
// MessageText:
//
//  Security Accounts Manager initialization failed because of the following error:
//  %hs
//  Error Status: 0x%x.
//  Please click OK to shutdown this system and reboot into Directory Services Restore Mode, check the event log for more detailed information.
//
#define STATUS_DS_SAM_INIT_FAILURE       ((LONG)0xC00002CBL)

//
// MessageId: STATUS_ONLY_IF_CONNECTED
//
// MessageText:
//
//  This operation is supported only when you are connected to the server.
//
#define STATUS_ONLY_IF_CONNECTED         ((LONG)0xC00002CCL)

//
// MessageId: STATUS_DS_SENSITIVE_GROUP_VIOLATION
//
// MessageText:
//
//  Only an administrator can modify the membership list of an administrative group.
//
#define STATUS_DS_SENSITIVE_GROUP_VIOLATION ((LONG)0xC00002CDL)

//
// MessageId: STATUS_PNP_RESTART_ENUMERATION
//
// MessageText:
//
//  A device was removed so enumeration must be restarted.
//
#define STATUS_PNP_RESTART_ENUMERATION   ((LONG)0xC00002CEL)

//
// MessageId: STATUS_JOURNAL_ENTRY_DELETED
//
// MessageText:
//
//  The journal entry has been deleted from the journal.
//
#define STATUS_JOURNAL_ENTRY_DELETED     ((LONG)0xC00002CFL)

//
// MessageId: STATUS_DS_CANT_MOD_PRIMARYGROUPID
//
// MessageText:
//
//  Cannot change the primary group ID of a domain controller account.
//
#define STATUS_DS_CANT_MOD_PRIMARYGROUPID ((LONG)0xC00002D0L)

//
// MessageId: STATUS_SYSTEM_IMAGE_BAD_SIGNATURE
//
// MessageText:
//
//  {Fatal System Error}
//  The system image %s is not properly signed.
//  The file has been replaced with the signed file.
//  The system has been shut down.
//
#define STATUS_SYSTEM_IMAGE_BAD_SIGNATURE ((LONG)0xC00002D1L)

//
// MessageId: STATUS_PNP_REBOOT_REQUIRED
//
// MessageText:
//
//  Device will not start without a reboot.
//
#define STATUS_PNP_REBOOT_REQUIRED       ((LONG)0xC00002D2L)

//
// MessageId: STATUS_POWER_STATE_INVALID
//
// MessageText:
//
//  Current device power state cannot support this request.
//
#define STATUS_POWER_STATE_INVALID       ((LONG)0xC00002D3L)

//
// MessageId: STATUS_DS_INVALID_GROUP_TYPE
//
// MessageText:
//
//  The specified group type is invalid.
//
#define STATUS_DS_INVALID_GROUP_TYPE     ((LONG)0xC00002D4L)

//
// MessageId: STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN
//
// MessageText:
//
//  In mixed domain no nesting of global group if group is security enabled.
//
#define STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN ((LONG)0xC00002D5L)

//
// MessageId: STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN
//
// MessageText:
//
//  In mixed domain, cannot nest local groups with other local groups, if the group is security enabled.
//
#define STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN ((LONG)0xC00002D6L)

//
// MessageId: STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER
//
// MessageText:
//
//  A global group cannot have a local group as a member.
//
#define STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER ((LONG)0xC00002D7L)

//
// MessageId: STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER
//
// MessageText:
//
//  A global group cannot have a universal group as a member.
//
#define STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER ((LONG)0xC00002D8L)

//
// MessageId: STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER
//
// MessageText:
//
//  A universal group cannot have a local group as a member.
//
#define STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER ((LONG)0xC00002D9L)

//
// MessageId: STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER
//
// MessageText:
//
//  A global group cannot have a cross domain member.
//
#define STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER ((LONG)0xC00002DAL)

//
// MessageId: STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER
//
// MessageText:
//
//  A local group cannot have another cross domain local group as a member.
//
#define STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER ((LONG)0xC00002DBL)

//
// MessageId: STATUS_DS_HAVE_PRIMARY_MEMBERS
//
// MessageText:
//
//  Can not change to security disabled group because of having primary members in this group.
//
#define STATUS_DS_HAVE_PRIMARY_MEMBERS   ((LONG)0xC00002DCL)

//
// MessageId: STATUS_WMI_NOT_SUPPORTED
//
// MessageText:
//
//  The WMI operation is not supported by the data block or method.
//
#define STATUS_WMI_NOT_SUPPORTED         ((LONG)0xC00002DDL)

//
// MessageId: STATUS_INSUFFICIENT_POWER
//
// MessageText:
//
//  There is not enough power to complete the requested operation.
//
#define STATUS_INSUFFICIENT_POWER        ((LONG)0xC00002DEL)

//
// MessageId: STATUS_SAM_NEED_BOOTKEY_PASSWORD
//
// MessageText:
//
//  Security Account Manager needs to get the boot password.
//
#define STATUS_SAM_NEED_BOOTKEY_PASSWORD ((LONG)0xC00002DFL)

//
// MessageId: STATUS_SAM_NEED_BOOTKEY_FLOPPY
//
// MessageText:
//
//  Security Account Manager needs to get the boot key from floppy disk.
//
#define STATUS_SAM_NEED_BOOTKEY_FLOPPY   ((LONG)0xC00002E0L)

//
// MessageId: STATUS_DS_CANT_START
//
// MessageText:
//
//  Directory Service can not start.
//
#define STATUS_DS_CANT_START             ((LONG)0xC00002E1L)

//
// MessageId: STATUS_DS_INIT_FAILURE
//
// MessageText:
//
//  Directory Services could not start because of the following error:
//  %hs
//  Error Status: 0x%x.
//  Please click OK to shutdown this system and reboot into Directory Services Restore Mode, check the event log for more detailed information.
//
#define STATUS_DS_INIT_FAILURE           ((LONG)0xC00002E2L)

//
// MessageId: STATUS_SAM_INIT_FAILURE
//
// MessageText:
//
//  Security Accounts Manager initialization failed because of the following error:
//  %hs
//  Error Status: 0x%x.
//  Please click OK to shutdown this system and reboot into Safe Mode, check the event log for more detailed information.
//
#define STATUS_SAM_INIT_FAILURE          ((LONG)0xC00002E3L)

//
// MessageId: STATUS_DS_GC_REQUIRED
//
// MessageText:
//
//  The requested operation can be performed only on a global catalog server.
//
#define STATUS_DS_GC_REQUIRED            ((LONG)0xC00002E4L)

//
// MessageId: STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY
//
// MessageText:
//
//  A local group can only be a member of other local groups in the same domain.
//
#define STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY ((LONG)0xC00002E5L)

//
// MessageId: STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS
//
// MessageText:
//
//  Foreign security principals cannot be members of universal groups.
//
#define STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS ((LONG)0xC00002E6L)

//
// MessageId: STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED
//
// MessageText:
//
//  Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.
//
#define STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED ((LONG)0xC00002E7L)

//
// MessageId: STATUS_MULTIPLE_FAULT_VIOLATION
//
// MessageText:
//
//  STATUS_MULTIPLE_FAULT_VIOLATION
//
#define STATUS_MULTIPLE_FAULT_VIOLATION  ((LONG)0xC00002E8L)

//
// MessageId: STATUS_CURRENT_DOMAIN_NOT_ALLOWED
//
// MessageText:
//
//  This operation can not be performed on the current domain.
//
#define STATUS_CURRENT_DOMAIN_NOT_ALLOWED ((LONG)0xC00002E9L)

//
// MessageId: STATUS_CANNOT_MAKE
//
// MessageText:
//
//  The directory or file cannot be created.
//
#define STATUS_CANNOT_MAKE               ((LONG)0xC00002EAL)

//
// MessageId: STATUS_SYSTEM_SHUTDOWN
//
// MessageText:
//
//  The system is in the process of shutting down.
//
#define STATUS_SYSTEM_SHUTDOWN           ((LONG)0xC00002EBL)

//
// MessageId: STATUS_DS_INIT_FAILURE_CONSOLE
//
// MessageText:
//
//  Directory Services could not start because of the following error:
//  %hs
//  Error Status: 0x%x.
//  Please click OK to shutdown the system. You can use the recovery console to diagnose the system further.
//
#define STATUS_DS_INIT_FAILURE_CONSOLE   ((LONG)0xC00002ECL)

//
// MessageId: STATUS_DS_SAM_INIT_FAILURE_CONSOLE
//
// MessageText:
//
//  Security Accounts Manager initialization failed because of the following error:
//  %hs
//  Error Status: 0x%x.
//  Please click OK to shutdown the system. You can use the recovery console to diagnose the system further.
//
#define STATUS_DS_SAM_INIT_FAILURE_CONSOLE ((LONG)0xC00002EDL)

//
// MessageId: STATUS_UNFINISHED_CONTEXT_DELETED
//
// MessageText:
//
//  A security context was deleted before the context was completed.  This is considered a logon failure.
//
#define STATUS_UNFINISHED_CONTEXT_DELETED ((LONG)0xC00002EEL)

//
// MessageId: STATUS_NO_TGT_REPLY
//
// MessageText:
//
//  The client is trying to negotiate a context and the server requires user-to-user but didn't send a TGT reply.
//
#define STATUS_NO_TGT_REPLY              ((LONG)0xC00002EFL)

//
// MessageId: STATUS_OBJECTID_NOT_FOUND
//
// MessageText:
//
//  An object ID was not found in the file.
//
#define STATUS_OBJECTID_NOT_FOUND        ((LONG)0xC00002F0L)

//
// MessageId: STATUS_NO_IP_ADDRESSES
//
// MessageText:
//
//  Unable to accomplish the requested task because the local machine does not have any IP addresses.
//
#define STATUS_NO_IP_ADDRESSES           ((LONG)0xC00002F1L)

//
// MessageId: STATUS_WRONG_CREDENTIAL_HANDLE
//
// MessageText:
//
//  The supplied credential handle does not match the credential associated with the security context.
//
#define STATUS_WRONG_CREDENTIAL_HANDLE   ((LONG)0xC00002F2L)

//
// MessageId: STATUS_CRYPTO_SYSTEM_INVALID
//
// MessageText:
//
//  The crypto system or checksum function is invalid because a required function is unavailable.
//
#define STATUS_CRYPTO_SYSTEM_INVALID     ((LONG)0xC00002F3L)

//
// MessageId: STATUS_MAX_REFERRALS_EXCEEDED
//
// MessageText:
//
//  The number of maximum ticket referrals has been exceeded.
//
#define STATUS_MAX_REFERRALS_EXCEEDED    ((LONG)0xC00002F4L)

//
// MessageId: STATUS_MUST_BE_KDC
//
// MessageText:
//
//  The local machine must be a Kerberos KDC (domain controller) and it is not.
//
#define STATUS_MUST_BE_KDC               ((LONG)0xC00002F5L)

//
// MessageId: STATUS_STRONG_CRYPTO_NOT_SUPPORTED
//
// MessageText:
//
//  The other end of the security negotiation is requires strong crypto but it is not supported on the local machine.
//
#define STATUS_STRONG_CRYPTO_NOT_SUPPORTED ((LONG)0xC00002F6L)

//
// MessageId: STATUS_TOO_MANY_PRINCIPALS
//
// MessageText:
//
//  The KDC reply contained more than one principal name.
//
#define STATUS_TOO_MANY_PRINCIPALS       ((LONG)0xC00002F7L)

//
// MessageId: STATUS_NO_PA_DATA
//
// MessageText:
//
//  Expected to find PA data for a hint of what etype to use, but it was not found.
//
#define STATUS_NO_PA_DATA                ((LONG)0xC00002F8L)

//
// MessageId: STATUS_PKINIT_NAME_MISMATCH
//
// MessageText:
//
//  The client certificate does not contain a valid UPN, or does not match the client name 
//  in the logon request.  Please contact your administrator.
//
#define STATUS_PKINIT_NAME_MISMATCH      ((LONG)0xC00002F9L)

//
// MessageId: STATUS_SMARTCARD_LOGON_REQUIRED
//
// MessageText:
//
//  Smartcard logon is required and was not used.
//
#define STATUS_SMARTCARD_LOGON_REQUIRED  ((LONG)0xC00002FAL)

//
// MessageId: STATUS_KDC_INVALID_REQUEST
//
// MessageText:
//
//  An invalid request was sent to the KDC.
//
#define STATUS_KDC_INVALID_REQUEST       ((LONG)0xC00002FBL)

//
// MessageId: STATUS_KDC_UNABLE_TO_REFER
//
// MessageText:
//
//  The KDC was unable to generate a referral for the service requested.
//
#define STATUS_KDC_UNABLE_TO_REFER       ((LONG)0xC00002FCL)

//
// MessageId: STATUS_KDC_UNKNOWN_ETYPE
//
// MessageText:
//
//  The encryption type requested is not supported by the KDC.
//
#define STATUS_KDC_UNKNOWN_ETYPE         ((LONG)0xC00002FDL)

//
// MessageId: STATUS_SHUTDOWN_IN_PROGRESS
//
// MessageText:
//
//  A system shutdown is in progress.
//
#define STATUS_SHUTDOWN_IN_PROGRESS      ((LONG)0xC00002FEL)

//
// MessageId: STATUS_SERVER_SHUTDOWN_IN_PROGRESS
//
// MessageText:
//
//  The server machine is shutting down.
//
#define STATUS_SERVER_SHUTDOWN_IN_PROGRESS ((LONG)0xC00002FFL)

//
// MessageId: STATUS_NOT_SUPPORTED_ON_SBS
//
// MessageText:
//
//  This operation is not supported on a computer running Windows Server 2003 for Small Business Server
//
#define STATUS_NOT_SUPPORTED_ON_SBS      ((LONG)0xC0000300L)

//
// MessageId: STATUS_WMI_GUID_DISCONNECTED
//
// MessageText:
//
//  The WMI GUID is no longer available
//
#define STATUS_WMI_GUID_DISCONNECTED     ((LONG)0xC0000301L)

//
// MessageId: STATUS_WMI_ALREADY_DISABLED
//
// MessageText:
//
//  Collection or events for the WMI GUID is already disabled.
//
#define STATUS_WMI_ALREADY_DISABLED      ((LONG)0xC0000302L)

//
// MessageId: STATUS_WMI_ALREADY_ENABLED
//
// MessageText:
//
//  Collection or events for the WMI GUID is already enabled.
//
#define STATUS_WMI_ALREADY_ENABLED       ((LONG)0xC0000303L)

//
// MessageId: STATUS_MFT_TOO_FRAGMENTED
//
// MessageText:
//
//  The Master File Table on the volume is too fragmented to complete this operation.
//
#define STATUS_MFT_TOO_FRAGMENTED        ((LONG)0xC0000304L)

//
// MessageId: STATUS_COPY_PROTECTION_FAILURE
//
// MessageText:
//
//  Copy protection failure.
//
#define STATUS_COPY_PROTECTION_FAILURE   ((LONG)0xC0000305L)

//
// MessageId: STATUS_CSS_AUTHENTICATION_FAILURE
//
// MessageText:
//
//  Copy protection error - DVD CSS Authentication failed.
//
#define STATUS_CSS_AUTHENTICATION_FAILURE ((LONG)0xC0000306L)

//
// MessageId: STATUS_CSS_KEY_NOT_PRESENT
//
// MessageText:
//
//  Copy protection error - The given sector does not contain a valid key.
//
#define STATUS_CSS_KEY_NOT_PRESENT       ((LONG)0xC0000307L)

//
// MessageId: STATUS_CSS_KEY_NOT_ESTABLISHED
//
// MessageText:
//
//  Copy protection error - DVD session key not established.
//
#define STATUS_CSS_KEY_NOT_ESTABLISHED   ((LONG)0xC0000308L)

//
// MessageId: STATUS_CSS_SCRAMBLED_SECTOR
//
// MessageText:
//
//  Copy protection error - The read failed because the sector is encrypted.
//
#define STATUS_CSS_SCRAMBLED_SECTOR      ((LONG)0xC0000309L)

//
// MessageId: STATUS_CSS_REGION_MISMATCH
//
// MessageText:
//
//  Copy protection error - The given DVD's region does not correspond to the
//  region setting of the drive.
//
#define STATUS_CSS_REGION_MISMATCH       ((LONG)0xC000030AL)

//
// MessageId: STATUS_CSS_RESETS_EXHAUSTED
//
// MessageText:
//
//  Copy protection error - The drive's region setting may be permanent.
//
#define STATUS_CSS_RESETS_EXHAUSTED      ((LONG)0xC000030BL)

/*++

 MessageId's 0x030c - 0x031f (inclusive) are reserved for future **STORAGE**
 copy protection errors.

--*/
//
// MessageId: STATUS_PKINIT_FAILURE
//
// MessageText:
//
//  The kerberos protocol encountered an error while validating the KDC certificate during smartcard Logon.  There
//  is more information in the system event log.
//
#define STATUS_PKINIT_FAILURE            ((LONG)0xC0000320L)

//
// MessageId: STATUS_SMARTCARD_SUBSYSTEM_FAILURE
//
// MessageText:
//
//  The kerberos protocol encountered an error while attempting to utilize the smartcard subsystem.
//
#define STATUS_SMARTCARD_SUBSYSTEM_FAILURE ((LONG)0xC0000321L)

//
// MessageId: STATUS_NO_KERB_KEY
//
// MessageText:
//
//  The target server does not have acceptable kerberos credentials.
//
#define STATUS_NO_KERB_KEY               ((LONG)0xC0000322L)

/*++

 MessageId's 0x0323 - 0x034f (inclusive) are reserved for other future copy
 protection errors.

--*/
//
// MessageId: STATUS_HOST_DOWN
//
// MessageText:
//
//  The transport determined that the remote system is down.
//
#define STATUS_HOST_DOWN                 ((LONG)0xC0000350L)

//
// MessageId: STATUS_UNSUPPORTED_PREAUTH
//
// MessageText:
//
//  An unsupported preauthentication mechanism was presented to the kerberos package.
//
#define STATUS_UNSUPPORTED_PREAUTH       ((LONG)0xC0000351L)

//
// MessageId: STATUS_EFS_ALG_BLOB_TOO_BIG
//
// MessageText:
//
//  The encryption algorithm used on the source file needs a bigger key buffer than the one used on the destination file.
//
#define STATUS_EFS_ALG_BLOB_TOO_BIG      ((LONG)0xC0000352L)

//
// MessageId: STATUS_PORT_NOT_SET
//
// MessageText:
//
//  An attempt to remove a processes DebugPort was made, but a port was not already associated with the process.
//
#define STATUS_PORT_NOT_SET              ((LONG)0xC0000353L)

//
// MessageId: STATUS_DEBUGGER_INACTIVE
//
// MessageText:
//
//  An attempt to do an operation on a debug port failed because the port is in the process of being deleted.
//
#define STATUS_DEBUGGER_INACTIVE         ((LONG)0xC0000354L)

//
// MessageId: STATUS_DS_VERSION_CHECK_FAILURE
//
// MessageText:
//
//  This version of Windows is not compatible with the behavior version of directory forest, domain or domain controller.
//
#define STATUS_DS_VERSION_CHECK_FAILURE  ((LONG)0xC0000355L)

//
// MessageId: STATUS_AUDITING_DISABLED
//
// MessageText:
//
//  The specified event is currently not being audited.
//
#define STATUS_AUDITING_DISABLED         ((LONG)0xC0000356L)

//
// MessageId: STATUS_PRENT4_MACHINE_ACCOUNT
//
// MessageText:
//
//  The machine account was created pre-NT4.  The account needs to be recreated.
//
#define STATUS_PRENT4_MACHINE_ACCOUNT    ((LONG)0xC0000357L)

//
// MessageId: STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER
//
// MessageText:
//
//  A account group can not have a universal group as a member.
//
#define STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER ((LONG)0xC0000358L)

//
// MessageId: STATUS_INVALID_IMAGE_WIN_32
//
// MessageText:
//
//  The specified image file did not have the correct format, it appears to be a 32-bit Windows image.
//
#define STATUS_INVALID_IMAGE_WIN_32      ((LONG)0xC0000359L)

//
// MessageId: STATUS_INVALID_IMAGE_WIN_64
//
// MessageText:
//
//  The specified image file did not have the correct format, it appears to be a 64-bit Windows image.
//
#define STATUS_INVALID_IMAGE_WIN_64      ((LONG)0xC000035AL)

//
// MessageId: STATUS_BAD_BINDINGS
//
// MessageText:
//
//  Client's supplied SSPI channel bindings were incorrect.
//
#define STATUS_BAD_BINDINGS              ((LONG)0xC000035BL)

//
// MessageId: STATUS_NETWORK_SESSION_EXPIRED
//
// MessageText:
//
//  The client's session has expired, so the client must reauthenticate to continue accessing the remote resources.
//
#define STATUS_NETWORK_SESSION_EXPIRED   ((LONG)0xC000035CL)

//
// MessageId: STATUS_APPHELP_BLOCK
//
// MessageText:
//
//  AppHelp dialog canceled thus preventing the application from starting.
//
#define STATUS_APPHELP_BLOCK             ((LONG)0xC000035DL)

//
// MessageId: STATUS_ALL_SIDS_FILTERED
//
// MessageText:
//
//  The SID filtering operation removed all SIDs.
//
#define STATUS_ALL_SIDS_FILTERED         ((LONG)0xC000035EL)

//
// MessageId: STATUS_NOT_SAFE_MODE_DRIVER
//
// MessageText:
//
//  The driver was not loaded because the system is booting into safe mode.
//
#define STATUS_NOT_SAFE_MODE_DRIVER      ((LONG)0xC000035FL)

//
// MessageId: STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT
//
// MessageText:
//
//  Access to %1 has been restricted by your Administrator by the default software restriction policy level.
//
#define STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT ((LONG)0xC0000361L)

//
// MessageId: STATUS_ACCESS_DISABLED_BY_POLICY_PATH
//
// MessageText:
//
//  Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3
//
#define STATUS_ACCESS_DISABLED_BY_POLICY_PATH ((LONG)0xC0000362L)

//
// MessageId: STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER
//
// MessageText:
//
//  Access to %1 has been restricted by your Administrator by software publisher policy.
//
#define STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER ((LONG)0xC0000363L)

//
// MessageId: STATUS_ACCESS_DISABLED_BY_POLICY_OTHER
//
// MessageText:
//
//  Access to %1 has been restricted by your Administrator by policy rule %2.
//
#define STATUS_ACCESS_DISABLED_BY_POLICY_OTHER ((LONG)0xC0000364L)

//
// MessageId: STATUS_FAILED_DRIVER_ENTRY
//
// MessageText:
//
//  The driver was not loaded because it failed it's initialization call.
//
#define STATUS_FAILED_DRIVER_ENTRY       ((LONG)0xC0000365L)

//
// MessageId: STATUS_DEVICE_ENUMERATION_ERROR
//
// MessageText:
//
//  The "%hs" encountered an error while applying power or reading the device configuration.
//  This may be caused by a failure of your hardware or by a poor connection.
//
#define STATUS_DEVICE_ENUMERATION_ERROR  ((LONG)0xC0000366L)

//
// MessageId: STATUS_WAIT_FOR_OPLOCK
//
// MessageText:
//
//  An operation is blocked waiting for an oplock.
//
#define STATUS_WAIT_FOR_OPLOCK           ((LONG)0x00000367L)

//
// MessageId: STATUS_MOUNT_POINT_NOT_RESOLVED
//
// MessageText:
//
//  The create operation failed because the name contained at least one mount point which resolves to a volume to which the specified device object is not attached.
//
#define STATUS_MOUNT_POINT_NOT_RESOLVED  ((LONG)0xC0000368L)

//
// MessageId: STATUS_INVALID_DEVICE_OBJECT_PARAMETER
//
// MessageText:
//
//  The device object parameter is either not a valid device object or is not attached to the volume specified by the file name.
//
#define STATUS_INVALID_DEVICE_OBJECT_PARAMETER ((LONG)0xC0000369L)

//
// MessageId: STATUS_MCA_OCCURED
//
// MessageText:
//
//  A Machine Check Error has occurred. Please check the system eventlog for additional information.
//
#define STATUS_MCA_OCCURED               ((LONG)0xC000036AL)

//
// MessageId: STATUS_DRIVER_BLOCKED_CRITICAL
//
// MessageText:
//
//  Driver %2 has been blocked from loading.
//
#define STATUS_DRIVER_BLOCKED_CRITICAL   ((LONG)0xC000036BL)

//
// MessageId: STATUS_DRIVER_BLOCKED
//
// MessageText:
//
//  Driver %2 has been blocked from loading.
//
#define STATUS_DRIVER_BLOCKED            ((LONG)0xC000036CL)

//
// MessageId: STATUS_DRIVER_DATABASE_ERROR
//
// MessageText:
//
//  There was error [%2] processing the driver database.
//
#define STATUS_DRIVER_DATABASE_ERROR     ((LONG)0xC000036DL)

//
// MessageId: STATUS_SYSTEM_HIVE_TOO_LARGE
//
// MessageText:
//
//  System hive size has exceeded its limit.
//
#define STATUS_SYSTEM_HIVE_TOO_LARGE     ((LONG)0xC000036EL)

//
// MessageId: STATUS_INVALID_IMPORT_OF_NON_DLL
//
// MessageText:
//
//  A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.
//
#define STATUS_INVALID_IMPORT_OF_NON_DLL ((LONG)0xC000036FL)

//
// MessageId: STATUS_DS_SHUTTING_DOWN
//
// MessageText:
//
//  The Directory Service is shuting down.
//
#define STATUS_DS_SHUTTING_DOWN          ((LONG)0x40000370L)

//
// MessageId: STATUS_SMARTCARD_WRONG_PIN
//
// MessageText:
//
//  An incorrect PIN was presented to the smart card
//
#define STATUS_SMARTCARD_WRONG_PIN       ((LONG)0xC0000380L)

//
// MessageId: STATUS_SMARTCARD_CARD_BLOCKED
//
// MessageText:
//
//  The smart card is blocked
//
#define STATUS_SMARTCARD_CARD_BLOCKED    ((LONG)0xC0000381L)

//
// MessageId: STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED
//
// MessageText:
//
//  No PIN was presented to the smart card
//
#define STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED ((LONG)0xC0000382L)

//
// MessageId: STATUS_SMARTCARD_NO_CARD
//
// MessageText:
//
//  No smart card available
//
#define STATUS_SMARTCARD_NO_CARD         ((LONG)0xC0000383L)

//
// MessageId: STATUS_SMARTCARD_NO_KEY_CONTAINER
//
// MessageText:
//
//  The requested key container does not exist on the smart card
//
#define STATUS_SMARTCARD_NO_KEY_CONTAINER ((LONG)0xC0000384L)

//
// MessageId: STATUS_SMARTCARD_NO_CERTIFICATE
//
// MessageText:
//
//  The requested certificate does not exist on the smart card
//
#define STATUS_SMARTCARD_NO_CERTIFICATE  ((LONG)0xC0000385L)

//
// MessageId: STATUS_SMARTCARD_NO_KEYSET
//
// MessageText:
//
//  The requested keyset does not exist
//
#define STATUS_SMARTCARD_NO_KEYSET       ((LONG)0xC0000386L)

//
// MessageId: STATUS_SMARTCARD_IO_ERROR
//
// MessageText:
//
//  A communication error with the smart card has been detected.
//
#define STATUS_SMARTCARD_IO_ERROR        ((LONG)0xC0000387L)

//
// MessageId: STATUS_DOWNGRADE_DETECTED
//
// MessageText:
//
//  The system detected a possible attempt to compromise security. Please ensure that you can contact the server that authenticated you.
//
#define STATUS_DOWNGRADE_DETECTED        ((LONG)0xC0000388L)

//
// MessageId: STATUS_SMARTCARD_CERT_REVOKED
//
// MessageText:
//
//  The smartcard certificate used for authentication has been revoked.
//  Please contact your system administrator.  There may be additional information in the
//  event log.
//
#define STATUS_SMARTCARD_CERT_REVOKED    ((LONG)0xC0000389L)

//
// MessageId: STATUS_ISSUING_CA_UNTRUSTED
//
// MessageText:
//
//  An untrusted certificate authority was detected While processing the
//  smartcard certificate used for authentication.  Please contact your system
//  administrator.
//
#define STATUS_ISSUING_CA_UNTRUSTED      ((LONG)0xC000038AL)

//
// MessageId: STATUS_REVOCATION_OFFLINE_C
//
// MessageText:
//
//  The revocation status of the smartcard certificate used for
//  authentication could not be determined. Please contact your system administrator.
//
#define STATUS_REVOCATION_OFFLINE_C      ((LONG)0xC000038BL)

//
// MessageId: STATUS_PKINIT_CLIENT_FAILURE
//
// MessageText:
//
//  The smartcard certificate used for authentication was not trusted.  Please
//  contact your system administrator.
//
#define STATUS_PKINIT_CLIENT_FAILURE     ((LONG)0xC000038CL)

//
// MessageId: STATUS_SMARTCARD_CERT_EXPIRED
//
// MessageText:
//
//  The smartcard certificate used for authentication has expired.  Please
//  contact your system administrator.
//
#define STATUS_SMARTCARD_CERT_EXPIRED    ((LONG)0xC000038DL)

//
// MessageId: STATUS_DRIVER_FAILED_PRIOR_UNLOAD
//
// MessageText:
//
//  The driver could not be loaded because a previous version of the driver is still in memory.
//
#define STATUS_DRIVER_FAILED_PRIOR_UNLOAD ((LONG)0xC000038EL)

//
// MessageId: STATUS_SMARTCARD_SILENT_CONTEXT
//
// MessageText:
//
//  The smartcard provider could not perform the action since the context was acquired as silent.
//
#define STATUS_SMARTCARD_SILENT_CONTEXT  ((LONG)0xC000038FL)

 /* MessageId up to 0x400 is reserved for smart cards */
//
// MessageId: STATUS_PER_USER_TRUST_QUOTA_EXCEEDED
//
// MessageText:
//
//  The current user's delegated trust creation quota has been exceeded.
//
#define STATUS_PER_USER_TRUST_QUOTA_EXCEEDED ((LONG)0xC0000401L)

//
// MessageId: STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED
//
// MessageText:
//
//  The total delegated trust creation quota has been exceeded.
//
#define STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED ((LONG)0xC0000402L)

//
// MessageId: STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED
//
// MessageText:
//
//  The current user's delegated trust deletion quota has been exceeded.
//
#define STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED ((LONG)0xC0000403L)

//
// MessageId: STATUS_DS_NAME_NOT_UNIQUE
//
// MessageText:
//
//  The requested name already exists as a unique identifier.
//
#define STATUS_DS_NAME_NOT_UNIQUE        ((LONG)0xC0000404L)

//
// MessageId: STATUS_DS_DUPLICATE_ID_FOUND
//
// MessageText:
//
//  The requested object has a non-unique identifier and cannot be retrieved.
//
#define STATUS_DS_DUPLICATE_ID_FOUND     ((LONG)0xC0000405L)

//
// MessageId: STATUS_DS_GROUP_CONVERSION_ERROR
//
// MessageText:
//
//  The group cannot be converted due to attribute restrictions on the requested group type.
//
#define STATUS_DS_GROUP_CONVERSION_ERROR ((LONG)0xC0000406L)

//
// MessageId: STATUS_VOLSNAP_PREPARE_HIBERNATE
//
// MessageText:
//
//  {Volume Shadow Copy Service}
//  Please wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.
//
#define STATUS_VOLSNAP_PREPARE_HIBERNATE ((LONG)0xC0000407L)

//
// MessageId: STATUS_USER2USER_REQUIRED
//
// MessageText:
//
//  Kerberos sub-protocol User2User is required.
//
#define STATUS_USER2USER_REQUIRED        ((LONG)0xC0000408L)

//
// MessageId: STATUS_NO_S4U_PROT_SUPPORT
//
// MessageText:
//
//  The Kerberos subsystem encountered an error.  A service for user protocol request was made 
//  against a domain controller which does not support service for user.
//
#define STATUS_NO_S4U_PROT_SUPPORT       ((LONG)0xC000040AL)

//
// MessageId: STATUS_CROSSREALM_DELEGATION_FAILURE
//
// MessageText:
//
//  An attempt was made by this server to make a Kerberos constrained delegation request for a target
//  outside of the server's realm.  This is not supported, and indicates a misconfiguration on this
//  server's allowed to delegate to list.  Please contact your administrator.
//
#define STATUS_CROSSREALM_DELEGATION_FAILURE ((LONG)0xC000040BL)

//
// MessageId: STATUS_REVOCATION_OFFLINE_KDC
//
// MessageText:
//
//  The revocation status of the domain controller certificate used for smartcard
//  authentication could not be determined.  There is additional information in the system event
//  log. Please contact your system administrator.
//
#define STATUS_REVOCATION_OFFLINE_KDC    ((LONG)0xC000040CL)

//
// MessageId: STATUS_ISSUING_CA_UNTRUSTED_KDC
//
// MessageText:
//
//  An untrusted certificate authority was detected while processing the
//  domain controller certificate used for authentication.  There is additional information in
//  the system event log.  Please contact your system administrator.
//
#define STATUS_ISSUING_CA_UNTRUSTED_KDC  ((LONG)0xC000040DL)

//
// MessageId: STATUS_KDC_CERT_EXPIRED
//
// MessageText:
//
//  The domain controller certificate used for smartcard logon has expired.
//  Please contact your system administrator with the contents of your system event log.
//
#define STATUS_KDC_CERT_EXPIRED          ((LONG)0xC000040EL)

//
// MessageId: STATUS_KDC_CERT_REVOKED
//
// MessageText:
//
//  The domain controller certificate used for smartcard logon has been revoked.
//  Please contact your system administrator with the contents of your system event log.
//
#define STATUS_KDC_CERT_REVOKED          ((LONG)0xC000040FL)

//
// MessageId: STATUS_PARAMETER_QUOTA_EXCEEDED
//
// MessageText:
//
//  Data present in one of the parameters is more than the function can operate on.
//
#define STATUS_PARAMETER_QUOTA_EXCEEDED  ((LONG)0xC0000410L)

//
// MessageId: STATUS_HIBERNATION_FAILURE
//
// MessageText:
//
//  The system has failed to hibernate (The error code is %hs).  Hibernation will be disabled until the system is restarted.
//
#define STATUS_HIBERNATION_FAILURE       ((LONG)0xC0000411L)

//
// MessageId: STATUS_DELAY_LOAD_FAILED
//
// MessageText:
//
//  An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.
//
#define STATUS_DELAY_LOAD_FAILED         ((LONG)0xC0000412L)

//
// MessageId: STATUS_AUTHENTICATION_FIREWALL_FAILED
//
// MessageText:
//
//  Logon Failure: The machine you are logging onto is protected by an authentication firewall.  The specified account is not allowed to authenticate to the machine.
//
#define STATUS_AUTHENTICATION_FIREWALL_FAILED ((LONG)0xC0000413L)

//
// MessageId: STATUS_VDM_DISALLOWED
//
// MessageText:
//
//  %hs is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator.
//
#define STATUS_VDM_DISALLOWED            ((LONG)0xC0000414L)

//
// MessageId: STATUS_HUNG_DISPLAY_DRIVER_THREAD
//
// MessageText:
//
//  {Display Driver Stopped Responding}
//  The %hs display driver has stopped working normally.  Save your work and reboot the system to restore full display functionality.
//  The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft.
//
#define STATUS_HUNG_DISPLAY_DRIVER_THREAD ((LONG)0xC0000415L)

/*++

 MessageId=0x0423 Facility=System Severity=ERROR SymbolicName=STATUS_CALLBACK_POP_STACK
 Language=English
 An exception has occurred in a user mode callback and the kernel callback frame should be removed.
 .

--*/

#define STATUS_CALLBACK_POP_STACK        ((LONG)0xC0000423L)

/*++

 MessageId=0x0424 Facility=System Severity=ERROR SymbolicName=STATUS_INCOMPATIBLE_DRIVER_BLOCKED
 Language=English
 %1 has been blocked from loading due to incompatibility with this system. Please contact your software
 vendor for a compatible version of the driver.
 .

--*/

#define STATUS_INCOMPATIBLE_DRIVER_BLOCKED   ((LONG)0xC0000424L)

//
// MessageId: STATUS_ENCOUNTERED_WRITE_IN_PROGRESS
//
// MessageText:
//
//  The attempted write operation encountered a write already in progress for some portion of the range.
//
#define STATUS_ENCOUNTERED_WRITE_IN_PROGRESS ((LONG)0xC0000433L)

//
// MessageId: STATUS_WOW_ASSERTION
//
// MessageText:
//
//  WOW Assertion Error.
//
#define STATUS_WOW_ASSERTION             ((LONG)0xC0009898L)

//
// MessageId: DBG_NO_STATE_CHANGE
//
// MessageText:
//
//  Debugger did not perform a state change.
//
#define DBG_NO_STATE_CHANGE              ((LONG)0xC0010001L)

//
// MessageId: DBG_APP_NOT_IDLE
//
// MessageText:
//
//  Debugger has found the application is not idle.
//
#define DBG_APP_NOT_IDLE                 ((LONG)0xC0010002L)

//
// MessageId: RPC_NT_INVALID_STRING_BINDING
//
// MessageText:
//
//  The string binding is invalid.
//
#define RPC_NT_INVALID_STRING_BINDING    ((LONG)0xC0020001L)

//
// MessageId: RPC_NT_WRONG_KIND_OF_BINDING
//
// MessageText:
//
//  The binding handle is not the correct type.
//
#define RPC_NT_WRONG_KIND_OF_BINDING     ((LONG)0xC0020002L)

//
// MessageId: RPC_NT_INVALID_BINDING
//
// MessageText:
//
//  The binding handle is invalid.
//
#define RPC_NT_INVALID_BINDING           ((LONG)0xC0020003L)

//
// MessageId: RPC_NT_PROTSEQ_NOT_SUPPORTED
//
// MessageText:
//
//  The RPC protocol sequence is not supported.
//
#define RPC_NT_PROTSEQ_NOT_SUPPORTED     ((LONG)0xC0020004L)

//
// MessageId: RPC_NT_INVALID_RPC_PROTSEQ
//
// MessageText:
//
//  The RPC protocol sequence is invalid.
//
#define RPC_NT_INVALID_RPC_PROTSEQ       ((LONG)0xC0020005L)

//
// MessageId: RPC_NT_INVALID_STRING_UUID
//
// MessageText:
//
//  The string UUID is invalid.
//
#define RPC_NT_INVALID_STRING_UUID       ((LONG)0xC0020006L)

//
// MessageId: RPC_NT_INVALID_ENDPOINT_FORMAT
//
// MessageText:
//
//  The endpoint format is invalid.
//
#define RPC_NT_INVALID_ENDPOINT_FORMAT   ((LONG)0xC0020007L)

//
// MessageId: RPC_NT_INVALID_NET_ADDR
//
// MessageText:
//
//  The network address is invalid.
//
#define RPC_NT_INVALID_NET_ADDR          ((LONG)0xC0020008L)

//
// MessageId: RPC_NT_NO_ENDPOINT_FOUND
//
// MessageText:
//
//  No endpoint was found.
//
#define RPC_NT_NO_ENDPOINT_FOUND         ((LONG)0xC0020009L)

//
// MessageId: RPC_NT_INVALID_TIMEOUT
//
// MessageText:
//
//  The timeout value is invalid.
//
#define RPC_NT_INVALID_TIMEOUT           ((LONG)0xC002000AL)

//
// MessageId: RPC_NT_OBJECT_NOT_FOUND
//
// MessageText:
//
//  The object UUID was not found.
//
#define RPC_NT_OBJECT_NOT_FOUND          ((LONG)0xC002000BL)

//
// MessageId: RPC_NT_ALREADY_REGISTERED
//
// MessageText:
//
//  The object UUID has already been registered.
//
#define RPC_NT_ALREADY_REGISTERED        ((LONG)0xC002000CL)

//
// MessageId: RPC_NT_TYPE_ALREADY_REGISTERED
//
// MessageText:
//
//  The type UUID has already been registered.
//
#define RPC_NT_TYPE_ALREADY_REGISTERED   ((LONG)0xC002000DL)

//
// MessageId: RPC_NT_ALREADY_LISTENING
//
// MessageText:
//
//  The RPC server is already listening.
//
#define RPC_NT_ALREADY_LISTENING         ((LONG)0xC002000EL)

//
// MessageId: RPC_NT_NO_PROTSEQS_REGISTERED
//
// MessageText:
//
//  No protocol sequences have been registered.
//
#define RPC_NT_NO_PROTSEQS_REGISTERED    ((LONG)0xC002000FL)

//
// MessageId: RPC_NT_NOT_LISTENING
//
// MessageText:
//
//  The RPC server is not listening.
//
#define RPC_NT_NOT_LISTENING             ((LONG)0xC0020010L)

//
// MessageId: RPC_NT_UNKNOWN_MGR_TYPE
//
// MessageText:
//
//  The manager type is unknown.
//
#define RPC_NT_UNKNOWN_MGR_TYPE          ((LONG)0xC0020011L)

//
// MessageId: RPC_NT_UNKNOWN_IF
//
// MessageText:
//
//  The interface is unknown.
//
#define RPC_NT_UNKNOWN_IF                ((LONG)0xC0020012L)

//
// MessageId: RPC_NT_NO_BINDINGS
//
// MessageText:
//
//  There are no bindings.
//
#define RPC_NT_NO_BINDINGS               ((LONG)0xC0020013L)

//
// MessageId: RPC_NT_NO_PROTSEQS
//
// MessageText:
//
//  There are no protocol sequences.
//
#define RPC_NT_NO_PROTSEQS               ((LONG)0xC0020014L)

//
// MessageId: RPC_NT_CANT_CREATE_ENDPOINT
//
// MessageText:
//
//  The endpoint cannot be created.
//
#define RPC_NT_CANT_CREATE_ENDPOINT      ((LONG)0xC0020015L)

//
// MessageId: RPC_NT_OUT_OF_RESOURCES
//
// MessageText:
//
//  Not enough resources are available to complete this operation.
//
#define RPC_NT_OUT_OF_RESOURCES          ((LONG)0xC0020016L)

//
// MessageId: RPC_NT_SERVER_UNAVAILABLE
//
// MessageText:
//
//  The RPC server is unavailable.
//
#define RPC_NT_SERVER_UNAVAILABLE        ((LONG)0xC0020017L)

//
// MessageId: RPC_NT_SERVER_TOO_BUSY
//
// MessageText:
//
//  The RPC server is too busy to complete this operation.
//
#define RPC_NT_SERVER_TOO_BUSY           ((LONG)0xC0020018L)

//
// MessageId: RPC_NT_INVALID_NETWORK_OPTIONS
//
// MessageText:
//
//  The network options are invalid.
//
#define RPC_NT_INVALID_NETWORK_OPTIONS   ((LONG)0xC0020019L)

//
// MessageId: RPC_NT_NO_CALL_ACTIVE
//
// MessageText:
//
//  There are no remote procedure calls active on this thread.
//
#define RPC_NT_NO_CALL_ACTIVE            ((LONG)0xC002001AL)

//
// MessageId: RPC_NT_CALL_FAILED
//
// MessageText:
//
//  The remote procedure call failed.
//
#define RPC_NT_CALL_FAILED               ((LONG)0xC002001BL)

//
// MessageId: RPC_NT_CALL_FAILED_DNE
//
// MessageText:
//
//  The remote procedure call failed and did not execute.
//
#define RPC_NT_CALL_FAILED_DNE           ((LONG)0xC002001CL)

//
// MessageId: RPC_NT_PROTOCOL_ERROR
//
// MessageText:
//
//  An RPC protocol error occurred.
//
#define RPC_NT_PROTOCOL_ERROR            ((LONG)0xC002001DL)

//
// MessageId: RPC_NT_UNSUPPORTED_TRANS_SYN
//
// MessageText:
//
//  The transfer syntax is not supported by the RPC server.
//
#define RPC_NT_UNSUPPORTED_TRANS_SYN     ((LONG)0xC002001FL)

//
// MessageId: RPC_NT_UNSUPPORTED_TYPE
//
// MessageText:
//
//  The type UUID is not supported.
//
#define RPC_NT_UNSUPPORTED_TYPE          ((LONG)0xC0020021L)

//
// MessageId: RPC_NT_INVALID_TAG
//
// MessageText:
//
//  The tag is invalid.
//
#define RPC_NT_INVALID_TAG               ((LONG)0xC0020022L)

//
// MessageId: RPC_NT_INVALID_BOUND
//
// MessageText:
//
//  The array bounds are invalid.
//
#define RPC_NT_INVALID_BOUND             ((LONG)0xC0020023L)

//
// MessageId: RPC_NT_NO_ENTRY_NAME
//
// MessageText:
//
//  The binding does not contain an entry name.
//
#define RPC_NT_NO_ENTRY_NAME             ((LONG)0xC0020024L)

//
// MessageId: RPC_NT_INVALID_NAME_SYNTAX
//
// MessageText:
//
//  The name syntax is invalid.
//
#define RPC_NT_INVALID_NAME_SYNTAX       ((LONG)0xC0020025L)

//
// MessageId: RPC_NT_UNSUPPORTED_NAME_SYNTAX
//
// MessageText:
//
//  The name syntax is not supported.
//
#define RPC_NT_UNSUPPORTED_NAME_SYNTAX   ((LONG)0xC0020026L)

//
// MessageId: RPC_NT_UUID_NO_ADDRESS
//
// MessageText:
//
//  No network address is available to use to construct a UUID.
//
#define RPC_NT_UUID_NO_ADDRESS           ((LONG)0xC0020028L)

//
// MessageId: RPC_NT_DUPLICATE_ENDPOINT
//
// MessageText:
//
//  The endpoint is a duplicate.
//
#define RPC_NT_DUPLICATE_ENDPOINT        ((LONG)0xC0020029L)

//
// MessageId: RPC_NT_UNKNOWN_AUTHN_TYPE
//
// MessageText:
//
//  The authentication type is unknown.
//
#define RPC_NT_UNKNOWN_AUTHN_TYPE        ((LONG)0xC002002AL)

//
// MessageId: RPC_NT_MAX_CALLS_TOO_SMALL
//
// MessageText:
//
//  The maximum number of calls is too small.
//
#define RPC_NT_MAX_CALLS_TOO_SMALL       ((LONG)0xC002002BL)

//
// MessageId: RPC_NT_STRING_TOO_LONG
//
// MessageText:
//
//  The string is too long.
//
#define RPC_NT_STRING_TOO_LONG           ((LONG)0xC002002CL)

//
// MessageId: RPC_NT_PROTSEQ_NOT_FOUND
//
// MessageText:
//
//  The RPC protocol sequence was not found.
//
#define RPC_NT_PROTSEQ_NOT_FOUND         ((LONG)0xC002002DL)

//
// MessageId: RPC_NT_PROCNUM_OUT_OF_RANGE
//
// MessageText:
//
//  The procedure number is out of range.
//
#define RPC_NT_PROCNUM_OUT_OF_RANGE      ((LONG)0xC002002EL)

//
// MessageId: RPC_NT_BINDING_HAS_NO_AUTH
//
// MessageText:
//
//  The binding does not contain any authentication information.
//
#define RPC_NT_BINDING_HAS_NO_AUTH       ((LONG)0xC002002FL)

//
// MessageId: RPC_NT_UNKNOWN_AUTHN_SERVICE
//
// MessageText:
//
//  The authentication service is unknown.
//
#define RPC_NT_UNKNOWN_AUTHN_SERVICE     ((LONG)0xC0020030L)

//
// MessageId: RPC_NT_UNKNOWN_AUTHN_LEVEL
//
// MessageText:
//
//  The authentication level is unknown.
//
#define RPC_NT_UNKNOWN_AUTHN_LEVEL       ((LONG)0xC0020031L)

//
// MessageId: RPC_NT_INVALID_AUTH_IDENTITY
//
// MessageText:
//
//  The security context is invalid.
//
#define RPC_NT_INVALID_AUTH_IDENTITY     ((LONG)0xC0020032L)

//
// MessageId: RPC_NT_UNKNOWN_AUTHZ_SERVICE
//
// MessageText:
//
//  The authorization service is unknown.
//
#define RPC_NT_UNKNOWN_AUTHZ_SERVICE     ((LONG)0xC0020033L)

//
// MessageId: EPT_NT_INVALID_ENTRY
//
// MessageText:
//
//  The entry is invalid.
//
#define EPT_NT_INVALID_ENTRY             ((LONG)0xC0020034L)

//
// MessageId: EPT_NT_CANT_PERFORM_OP
//
// MessageText:
//
//  The operation cannot be performed.
//
#define EPT_NT_CANT_PERFORM_OP           ((LONG)0xC0020035L)

//
// MessageId: EPT_NT_NOT_REGISTERED
//
// MessageText:
//
//  There are no more endpoints available from the endpoint mapper.
//
#define EPT_NT_NOT_REGISTERED            ((LONG)0xC0020036L)

//
// MessageId: RPC_NT_NOTHING_TO_EXPORT
//
// MessageText:
//
//  No interfaces have been exported.
//
#define RPC_NT_NOTHING_TO_EXPORT         ((LONG)0xC0020037L)

//
// MessageId: RPC_NT_INCOMPLETE_NAME
//
// MessageText:
//
//  The entry name is incomplete.
//
#define RPC_NT_INCOMPLETE_NAME           ((LONG)0xC0020038L)

//
// MessageId: RPC_NT_INVALID_VERS_OPTION
//
// MessageText:
//
//  The version option is invalid.
//
#define RPC_NT_INVALID_VERS_OPTION       ((LONG)0xC0020039L)

//
// MessageId: RPC_NT_NO_MORE_MEMBERS
//
// MessageText:
//
//  There are no more members.
//
#define RPC_NT_NO_MORE_MEMBERS           ((LONG)0xC002003AL)

//
// MessageId: RPC_NT_NOT_ALL_OBJS_UNEXPORTED
//
// MessageText:
//
//  There is nothing to unexport.
//
#define RPC_NT_NOT_ALL_OBJS_UNEXPORTED   ((LONG)0xC002003BL)

//
// MessageId: RPC_NT_INTERFACE_NOT_FOUND
//
// MessageText:
//
//  The interface was not found.
//
#define RPC_NT_INTERFACE_NOT_FOUND       ((LONG)0xC002003CL)

//
// MessageId: RPC_NT_ENTRY_ALREADY_EXISTS
//
// MessageText:
//
//  The entry already exists.
//
#define RPC_NT_ENTRY_ALREADY_EXISTS      ((LONG)0xC002003DL)

//
// MessageId: RPC_NT_ENTRY_NOT_FOUND
//
// MessageText:
//
//  The entry is not found.
//
#define RPC_NT_ENTRY_NOT_FOUND           ((LONG)0xC002003EL)

//
// MessageId: RPC_NT_NAME_SERVICE_UNAVAILABLE
//
// MessageText:
//
//  The name service is unavailable.
//
#define RPC_NT_NAME_SERVICE_UNAVAILABLE  ((LONG)0xC002003FL)

//
// MessageId: RPC_NT_INVALID_NAF_ID
//
// MessageText:
//
//  The network address family is invalid.
//
#define RPC_NT_INVALID_NAF_ID            ((LONG)0xC0020040L)

//
// MessageId: RPC_NT_CANNOT_SUPPORT
//
// MessageText:
//
//  The requested operation is not supported.
//
#define RPC_NT_CANNOT_SUPPORT            ((LONG)0xC0020041L)

//
// MessageId: RPC_NT_NO_CONTEXT_AVAILABLE
//
// MessageText:
//
//  No security context is available to allow impersonation.
//
#define RPC_NT_NO_CONTEXT_AVAILABLE      ((LONG)0xC0020042L)

//
// MessageId: RPC_NT_INTERNAL_ERROR
//
// MessageText:
//
//  An internal error occurred in RPC.
//
#define RPC_NT_INTERNAL_ERROR            ((LONG)0xC0020043L)

//
// MessageId: RPC_NT_ZERO_DIVIDE
//
// MessageText:
//
//  The RPC server attempted an integer divide by zero.
//
#define RPC_NT_ZERO_DIVIDE               ((LONG)0xC0020044L)

//
// MessageId: RPC_NT_ADDRESS_ERROR
//
// MessageText:
//
//  An addressing error occurred in the RPC server.
//
#define RPC_NT_ADDRESS_ERROR             ((LONG)0xC0020045L)

//
// MessageId: RPC_NT_FP_DIV_ZERO
//
// MessageText:
//
//  A floating point operation at the RPC server caused a divide by zero.
//
#define RPC_NT_FP_DIV_ZERO               ((LONG)0xC0020046L)

//
// MessageId: RPC_NT_FP_UNDERFLOW
//
// MessageText:
//
//  A floating point underflow occurred at the RPC server.
//
#define RPC_NT_FP_UNDERFLOW              ((LONG)0xC0020047L)

//
// MessageId: RPC_NT_FP_OVERFLOW
//
// MessageText:
//
//  A floating point overflow occurred at the RPC server.
//
#define RPC_NT_FP_OVERFLOW               ((LONG)0xC0020048L)

//
// MessageId: RPC_NT_NO_MORE_ENTRIES
//
// MessageText:
//
//  The list of RPC servers available for auto-handle binding has been exhausted.
//
#define RPC_NT_NO_MORE_ENTRIES           ((LONG)0xC0030001L)

//
// MessageId: RPC_NT_SS_CHAR_TRANS_OPEN_FAIL
//
// MessageText:
//
//  The file designated by DCERPCCHARTRANS cannot be opened.
//
#define RPC_NT_SS_CHAR_TRANS_OPEN_FAIL   ((LONG)0xC0030002L)

//
// MessageId: RPC_NT_SS_CHAR_TRANS_SHORT_FILE
//
// MessageText:
//
//  The file containing the character translation table has fewer than 512 bytes.
//
#define RPC_NT_SS_CHAR_TRANS_SHORT_FILE  ((LONG)0xC0030003L)

//
// MessageId: RPC_NT_SS_IN_NULL_CONTEXT
//
// MessageText:
//
//  A null context handle is passed as an [in] parameter.
//
#define RPC_NT_SS_IN_NULL_CONTEXT        ((LONG)0xC0030004L)

//
// MessageId: RPC_NT_SS_CONTEXT_MISMATCH
//
// MessageText:
//
//  The context handle does not match any known context handles.
//
#define RPC_NT_SS_CONTEXT_MISMATCH       ((LONG)0xC0030005L)

//
// MessageId: RPC_NT_SS_CONTEXT_DAMAGED
//
// MessageText:
//
//  The context handle changed during a call.
//
#define RPC_NT_SS_CONTEXT_DAMAGED        ((LONG)0xC0030006L)

//
// MessageId: RPC_NT_SS_HANDLES_MISMATCH
//
// MessageText:
//
//  The binding handles passed to a remote procedure call do not match.
//
#define RPC_NT_SS_HANDLES_MISMATCH       ((LONG)0xC0030007L)

//
// MessageId: RPC_NT_SS_CANNOT_GET_CALL_HANDLE
//
// MessageText:
//
//  The stub is unable to get the call handle.
//
#define RPC_NT_SS_CANNOT_GET_CALL_HANDLE ((LONG)0xC0030008L)

//
// MessageId: RPC_NT_NULL_REF_POINTER
//
// MessageText:
//
//  A null reference pointer was passed to the stub.
//
#define RPC_NT_NULL_REF_POINTER          ((LONG)0xC0030009L)

//
// MessageId: RPC_NT_ENUM_VALUE_OUT_OF_RANGE
//
// MessageText:
//
//  The enumeration value is out of range.
//
#define RPC_NT_ENUM_VALUE_OUT_OF_RANGE   ((LONG)0xC003000AL)

//
// MessageId: RPC_NT_BYTE_COUNT_TOO_SMALL
//
// MessageText:
//
//  The byte count is too small.
//
#define RPC_NT_BYTE_COUNT_TOO_SMALL      ((LONG)0xC003000BL)

//
// MessageId: RPC_NT_BAD_STUB_DATA
//
// MessageText:
//
//  The stub received bad data.
//
#define RPC_NT_BAD_STUB_DATA             ((LONG)0xC003000CL)

//
// MessageId: RPC_NT_CALL_IN_PROGRESS
//
// MessageText:
//
//  A remote procedure call is already in progress for this thread.
//
#define RPC_NT_CALL_IN_PROGRESS          ((LONG)0xC0020049L)

//
// MessageId: RPC_NT_NO_MORE_BINDINGS
//
// MessageText:
//
//  There are no more bindings.
//
#define RPC_NT_NO_MORE_BINDINGS          ((LONG)0xC002004AL)

//
// MessageId: RPC_NT_GROUP_MEMBER_NOT_FOUND
//
// MessageText:
//
//  The group member was not found.
//
#define RPC_NT_GROUP_MEMBER_NOT_FOUND    ((LONG)0xC002004BL)

//
// MessageId: EPT_NT_CANT_CREATE
//
// MessageText:
//
//  The endpoint mapper database entry could not be created.
//
#define EPT_NT_CANT_CREATE               ((LONG)0xC002004CL)

//
// MessageId: RPC_NT_INVALID_OBJECT
//
// MessageText:
//
//  The object UUID is the nil UUID.
//
#define RPC_NT_INVALID_OBJECT            ((LONG)0xC002004DL)

//
// MessageId: RPC_NT_NO_INTERFACES
//
// MessageText:
//
//  No interfaces have been registered.
//
#define RPC_NT_NO_INTERFACES             ((LONG)0xC002004FL)

//
// MessageId: RPC_NT_CALL_CANCELLED
//
// MessageText:
//
//  The remote procedure call was cancelled.
//
#define RPC_NT_CALL_CANCELLED            ((LONG)0xC0020050L)

//
// MessageId: RPC_NT_BINDING_INCOMPLETE
//
// MessageText:
//
//  The binding handle does not contain all required information.
//
#define RPC_NT_BINDING_INCOMPLETE        ((LONG)0xC0020051L)

//
// MessageId: RPC_NT_COMM_FAILURE
//
// MessageText:
//
//  A communications failure occurred during a remote procedure call.
//
#define RPC_NT_COMM_FAILURE              ((LONG)0xC0020052L)

//
// MessageId: RPC_NT_UNSUPPORTED_AUTHN_LEVEL
//
// MessageText:
//
//  The requested authentication level is not supported.
//
#define RPC_NT_UNSUPPORTED_AUTHN_LEVEL   ((LONG)0xC0020053L)

//
// MessageId: RPC_NT_NO_PRINC_NAME
//
// MessageText:
//
//  No principal name registered.
//
#define RPC_NT_NO_PRINC_NAME             ((LONG)0xC0020054L)

//
// MessageId: RPC_NT_NOT_RPC_ERROR
//
// MessageText:
//
//  The error specified is not a valid Windows RPC error code.
//
#define RPC_NT_NOT_RPC_ERROR             ((LONG)0xC0020055L)

//
// MessageId: RPC_NT_UUID_LOCAL_ONLY
//
// MessageText:
//
//  A UUID that is valid only on this computer has been allocated.
//
#define RPC_NT_UUID_LOCAL_ONLY           ((LONG)0x40020056L)

//
// MessageId: RPC_NT_SEC_PKG_ERROR
//
// MessageText:
//
//  A security package specific error occurred.
//
#define RPC_NT_SEC_PKG_ERROR             ((LONG)0xC0020057L)

//
// MessageId: RPC_NT_NOT_CANCELLED
//
// MessageText:
//
//  Thread is not cancelled.
//
#define RPC_NT_NOT_CANCELLED             ((LONG)0xC0020058L)

//
// MessageId: RPC_NT_INVALID_ES_ACTION
//
// MessageText:
//
//  Invalid operation on the encoding/decoding handle.
//
#define RPC_NT_INVALID_ES_ACTION         ((LONG)0xC0030059L)

//
// MessageId: RPC_NT_WRONG_ES_VERSION
//
// MessageText:
//
//  Incompatible version of the serializing package.
//
#define RPC_NT_WRONG_ES_VERSION          ((LONG)0xC003005AL)

//
// MessageId: RPC_NT_WRONG_STUB_VERSION
//
// MessageText:
//
//  Incompatible version of the RPC stub.
//
#define RPC_NT_WRONG_STUB_VERSION        ((LONG)0xC003005BL)

//
// MessageId: RPC_NT_INVALID_PIPE_OBJECT
//
// MessageText:
//
//  The RPC pipe object is invalid or corrupted.
//
#define RPC_NT_INVALID_PIPE_OBJECT       ((LONG)0xC003005CL)

//
// MessageId: RPC_NT_INVALID_PIPE_OPERATION
//
// MessageText:
//
//  An invalid operation was attempted on an RPC pipe object.
//
#define RPC_NT_INVALID_PIPE_OPERATION    ((LONG)0xC003005DL)

//
// MessageId: RPC_NT_WRONG_PIPE_VERSION
//
// MessageText:
//
//  Unsupported RPC pipe version.
//
#define RPC_NT_WRONG_PIPE_VERSION        ((LONG)0xC003005EL)

//
// MessageId: RPC_NT_PIPE_CLOSED
//
// MessageText:
//
//  The RPC pipe object has already been closed.
//
#define RPC_NT_PIPE_CLOSED               ((LONG)0xC003005FL)

//
// MessageId: RPC_NT_PIPE_DISCIPLINE_ERROR
//
// MessageText:
//
//  The RPC call completed before all pipes were processed.
//
#define RPC_NT_PIPE_DISCIPLINE_ERROR     ((LONG)0xC0030060L)

//
// MessageId: RPC_NT_PIPE_EMPTY
//
// MessageText:
//
//  No more data is available from the RPC pipe.
//
#define RPC_NT_PIPE_EMPTY                ((LONG)0xC0030061L)

//
// MessageId: RPC_NT_INVALID_ASYNC_HANDLE
//
// MessageText:
//
//  Invalid asynchronous remote procedure call handle.
//
#define RPC_NT_INVALID_ASYNC_HANDLE      ((LONG)0xC0020062L)

//
// MessageId: RPC_NT_INVALID_ASYNC_CALL
//
// MessageText:
//
//  Invalid asynchronous RPC call handle for this operation.
//
#define RPC_NT_INVALID_ASYNC_CALL        ((LONG)0xC0020063L)

//
// MessageId: RPC_NT_SEND_INCOMPLETE
//
// MessageText:
//
//  Some data remains to be sent in the request buffer.
//
#define RPC_NT_SEND_INCOMPLETE           ((LONG)0x400200AFL)

//
// MessageId: STATUS_ACPI_INVALID_OPCODE
//
// MessageText:
//
//  An attempt was made to run an invalid AML opcode
//
#define STATUS_ACPI_INVALID_OPCODE       ((LONG)0xC0140001L)

//
// MessageId: STATUS_ACPI_STACK_OVERFLOW
//
// MessageText:
//
//  The AML Interpreter Stack has overflowed
//
#define STATUS_ACPI_STACK_OVERFLOW       ((LONG)0xC0140002L)

//
// MessageId: STATUS_ACPI_ASSERT_FAILED
//
// MessageText:
//
//  An inconsistent state has occurred
//
#define STATUS_ACPI_ASSERT_FAILED        ((LONG)0xC0140003L)

//
// MessageId: STATUS_ACPI_INVALID_INDEX
//
// MessageText:
//
//  An attempt was made to access an array outside of its bounds
//
#define STATUS_ACPI_INVALID_INDEX        ((LONG)0xC0140004L)

//
// MessageId: STATUS_ACPI_INVALID_ARGUMENT
//
// MessageText:
//
//  A required argument was not specified
//
#define STATUS_ACPI_INVALID_ARGUMENT     ((LONG)0xC0140005L)

//
// MessageId: STATUS_ACPI_FATAL
//
// MessageText:
//
//  A fatal error has occurred
//
#define STATUS_ACPI_FATAL                ((LONG)0xC0140006L)

//
// MessageId: STATUS_ACPI_INVALID_SUPERNAME
//
// MessageText:
//
//  An invalid SuperName was specified
//
#define STATUS_ACPI_INVALID_SUPERNAME    ((LONG)0xC0140007L)

//
// MessageId: STATUS_ACPI_INVALID_ARGTYPE
//
// MessageText:
//
//  An argument with an incorrect type was specified
//
#define STATUS_ACPI_INVALID_ARGTYPE      ((LONG)0xC0140008L)

//
// MessageId: STATUS_ACPI_INVALID_OBJTYPE
//
// MessageText:
//
//  An object with an incorrect type was specified
//
#define STATUS_ACPI_INVALID_OBJTYPE      ((LONG)0xC0140009L)

//
// MessageId: STATUS_ACPI_INVALID_TARGETTYPE
//
// MessageText:
//
//  A target with an incorrect type was specified
//
#define STATUS_ACPI_INVALID_TARGETTYPE   ((LONG)0xC014000AL)

//
// MessageId: STATUS_ACPI_INCORRECT_ARGUMENT_COUNT
//
// MessageText:
//
//  An incorrect number of arguments were specified
//
#define STATUS_ACPI_INCORRECT_ARGUMENT_COUNT ((LONG)0xC014000BL)

//
// MessageId: STATUS_ACPI_ADDRESS_NOT_MAPPED
//
// MessageText:
//
//  An address failed to translate
//
#define STATUS_ACPI_ADDRESS_NOT_MAPPED   ((LONG)0xC014000CL)

//
// MessageId: STATUS_ACPI_INVALID_EVENTTYPE
//
// MessageText:
//
//  An incorrect event type was specified
//
#define STATUS_ACPI_INVALID_EVENTTYPE    ((LONG)0xC014000DL)

//
// MessageId: STATUS_ACPI_HANDLER_COLLISION
//
// MessageText:
//
//  A handler for the target already exists
//
#define STATUS_ACPI_HANDLER_COLLISION    ((LONG)0xC014000EL)

//
// MessageId: STATUS_ACPI_INVALID_DATA
//
// MessageText:
//
//  Invalid data for the target was specified
//
#define STATUS_ACPI_INVALID_DATA         ((LONG)0xC014000FL)

//
// MessageId: STATUS_ACPI_INVALID_REGION
//
// MessageText:
//
//  An invalid region for the target was specified
//
#define STATUS_ACPI_INVALID_REGION       ((LONG)0xC0140010L)

//
// MessageId: STATUS_ACPI_INVALID_ACCESS_SIZE
//
// MessageText:
//
//  An attempt was made to access a field outside of the defined range
//
#define STATUS_ACPI_INVALID_ACCESS_SIZE  ((LONG)0xC0140011L)

//
// MessageId: STATUS_ACPI_ACQUIRE_GLOBAL_LOCK
//
// MessageText:
//
//  The Global system lock could not be acquired
//
#define STATUS_ACPI_ACQUIRE_GLOBAL_LOCK  ((LONG)0xC0140012L)

//
// MessageId: STATUS_ACPI_ALREADY_INITIALIZED
//
// MessageText:
//
//  An attempt was made to reinitialize the ACPI subsystem
//
#define STATUS_ACPI_ALREADY_INITIALIZED  ((LONG)0xC0140013L)

//
// MessageId: STATUS_ACPI_NOT_INITIALIZED
//
// MessageText:
//
//  The ACPI subsystem has not been initialized
//
#define STATUS_ACPI_NOT_INITIALIZED      ((LONG)0xC0140014L)

//
// MessageId: STATUS_ACPI_INVALID_MUTEX_LEVEL
//
// MessageText:
//
//  An incorrect mutex was specified
//
#define STATUS_ACPI_INVALID_MUTEX_LEVEL  ((LONG)0xC0140015L)

//
// MessageId: STATUS_ACPI_MUTEX_NOT_OWNED
//
// MessageText:
//
//  The mutex is not currently owned
//
#define STATUS_ACPI_MUTEX_NOT_OWNED      ((LONG)0xC0140016L)

//
// MessageId: STATUS_ACPI_MUTEX_NOT_OWNER
//
// MessageText:
//
//  An attempt was made to access the mutex by a process that was not the owner
//
#define STATUS_ACPI_MUTEX_NOT_OWNER      ((LONG)0xC0140017L)

//
// MessageId: STATUS_ACPI_RS_ACCESS
//
// MessageText:
//
//  An error occurred during an access to Region Space
//
#define STATUS_ACPI_RS_ACCESS            ((LONG)0xC0140018L)

//
// MessageId: STATUS_ACPI_INVALID_TABLE
//
// MessageText:
//
//  An attempt was made to use an incorrect table
//
#define STATUS_ACPI_INVALID_TABLE        ((LONG)0xC0140019L)

//
// MessageId: STATUS_ACPI_REG_HANDLER_FAILED
//
// MessageText:
//
//  The registration of an ACPI event failed
//
#define STATUS_ACPI_REG_HANDLER_FAILED   ((LONG)0xC0140020L)

//
// MessageId: STATUS_ACPI_POWER_REQUEST_FAILED
//
// MessageText:
//
//  An ACPI Power Object failed to transition state
//
#define STATUS_ACPI_POWER_REQUEST_FAILED ((LONG)0xC0140021L)

//
// Terminal Server specific Errors
//
//
// MessageId: STATUS_CTX_WINSTATION_NAME_INVALID
//
// MessageText:
//
//  Session name %1 is invalid.
//
#define STATUS_CTX_WINSTATION_NAME_INVALID ((LONG)0xC00A0001L)

//
// MessageId: STATUS_CTX_INVALID_PD
//
// MessageText:
//
//  The protocol driver %1 is invalid.
//
#define STATUS_CTX_INVALID_PD            ((LONG)0xC00A0002L)

//
// MessageId: STATUS_CTX_PD_NOT_FOUND
//
// MessageText:
//
//  The protocol driver %1 was not found in the system path.
//
#define STATUS_CTX_PD_NOT_FOUND          ((LONG)0xC00A0003L)

//
// MessageId: STATUS_CTX_CDM_CONNECT
//
// MessageText:
//
//  The Client Drive Mapping Service Has Connected on Terminal Connection.
//
#define STATUS_CTX_CDM_CONNECT           ((LONG)0x400A0004L)

//
// MessageId: STATUS_CTX_CDM_DISCONNECT
//
// MessageText:
//
//  The Client Drive Mapping Service Has Disconnected on Terminal Connection.
//
#define STATUS_CTX_CDM_DISCONNECT        ((LONG)0x400A0005L)

//
// MessageId: STATUS_CTX_CLOSE_PENDING
//
// MessageText:
//
//  A close operation is pending on the Terminal Connection.
//
#define STATUS_CTX_CLOSE_PENDING         ((LONG)0xC00A0006L)

//
// MessageId: STATUS_CTX_NO_OUTBUF
//
// MessageText:
//
//  There are no free output buffers available.
//
#define STATUS_CTX_NO_OUTBUF             ((LONG)0xC00A0007L)

//
// MessageId: STATUS_CTX_MODEM_INF_NOT_FOUND
//
// MessageText:
//
//  The MODEM.INF file was not found.
//
#define STATUS_CTX_MODEM_INF_NOT_FOUND   ((LONG)0xC00A0008L)

//
// MessageId: STATUS_CTX_INVALID_MODEMNAME
//
// MessageText:
//
//  The modem (%1) was not found in MODEM.INF.
//
#define STATUS_CTX_INVALID_MODEMNAME     ((LONG)0xC00A0009L)

//
// MessageId: STATUS_CTX_RESPONSE_ERROR
//
// MessageText:
//
//  The modem did not accept the command sent to it.
//  Verify the configured modem name matches the attached modem.
//
#define STATUS_CTX_RESPONSE_ERROR        ((LONG)0xC00A000AL)

//
// MessageId: STATUS_CTX_MODEM_RESPONSE_TIMEOUT
//
// MessageText:
//
//  The modem did not respond to the command sent to it.
//  Verify the modem is properly cabled and powered on.
//
#define STATUS_CTX_MODEM_RESPONSE_TIMEOUT ((LONG)0xC00A000BL)

//
// MessageId: STATUS_CTX_MODEM_RESPONSE_NO_CARRIER
//
// MessageText:
//
//  Carrier detect has failed or carrier has been dropped due to disconnect.
//
#define STATUS_CTX_MODEM_RESPONSE_NO_CARRIER ((LONG)0xC00A000CL)

//
// MessageId: STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE
//
// MessageText:
//
//  Dial tone not detected within required time.
//  Verify phone cable is properly attached and functional.
//
#define STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE ((LONG)0xC00A000DL)

//
// MessageId: STATUS_CTX_MODEM_RESPONSE_BUSY
//
// MessageText:
//
//  Busy signal detected at remote site on callback.
//
#define STATUS_CTX_MODEM_RESPONSE_BUSY   ((LONG)0xC00A000EL)

//
// MessageId: STATUS_CTX_MODEM_RESPONSE_VOICE
//
// MessageText:
//
//  Voice detected at remote site on callback.
//
#define STATUS_CTX_MODEM_RESPONSE_VOICE  ((LONG)0xC00A000FL)

//
// MessageId: STATUS_CTX_TD_ERROR
//
// MessageText:
//
//  Transport driver error
//
#define STATUS_CTX_TD_ERROR              ((LONG)0xC00A0010L)

//
// MessageId: STATUS_CTX_LICENSE_CLIENT_INVALID
//
// MessageText:
//
//  The client you are using is not licensed to use this system. Your logon request is denied.
//
#define STATUS_CTX_LICENSE_CLIENT_INVALID ((LONG)0xC00A0012L)

//
// MessageId: STATUS_CTX_LICENSE_NOT_AVAILABLE
//
// MessageText:
//
//  The system has reached its licensed logon limit.
//  Please try again later.
//
#define STATUS_CTX_LICENSE_NOT_AVAILABLE ((LONG)0xC00A0013L)

//
// MessageId: STATUS_CTX_LICENSE_EXPIRED
//
// MessageText:
//
//  The system license has expired. Your logon request is denied.
//
#define STATUS_CTX_LICENSE_EXPIRED       ((LONG)0xC00A0014L)

//
// MessageId: STATUS_CTX_WINSTATION_NOT_FOUND
//
// MessageText:
//
//  The specified session cannot be found.
//
#define STATUS_CTX_WINSTATION_NOT_FOUND  ((LONG)0xC00A0015L)

//
// MessageId: STATUS_CTX_WINSTATION_NAME_COLLISION
//
// MessageText:
//
//  The specified session name is already in use.
//
#define STATUS_CTX_WINSTATION_NAME_COLLISION ((LONG)0xC00A0016L)

//
// MessageId: STATUS_CTX_WINSTATION_BUSY
//
// MessageText:
//
//  The requested operation cannot be completed because the Terminal Connection is currently busy processing a connect, disconnect, reset, or delete operation.
//
#define STATUS_CTX_WINSTATION_BUSY       ((LONG)0xC00A0017L)

//
// MessageId: STATUS_CTX_BAD_VIDEO_MODE
//
// MessageText:
//
//  An attempt has been made to connect to a session whose video mode is not supported by the current client.
//
#define STATUS_CTX_BAD_VIDEO_MODE        ((LONG)0xC00A0018L)

//
// MessageId: STATUS_CTX_GRAPHICS_INVALID
//
// MessageText:
//
//  The application attempted to enable DOS graphics mode.
//  DOS graphics mode is not supported.
//
#define STATUS_CTX_GRAPHICS_INVALID      ((LONG)0xC00A0022L)

//
// MessageId: STATUS_CTX_NOT_CONSOLE
//
// MessageText:
//
//  The requested operation can be performed only on the system console.
//  This is most often the result of a driver or system DLL requiring direct console access.
//
#define STATUS_CTX_NOT_CONSOLE           ((LONG)0xC00A0024L)

//
// MessageId: STATUS_CTX_CLIENT_QUERY_TIMEOUT
//
// MessageText:
//
//  The client failed to respond to the server connect message.
//
#define STATUS_CTX_CLIENT_QUERY_TIMEOUT  ((LONG)0xC00A0026L)

//
// MessageId: STATUS_CTX_CONSOLE_DISCONNECT
//
// MessageText:
//
//  Disconnecting the console session is not supported.
//
#define STATUS_CTX_CONSOLE_DISCONNECT    ((LONG)0xC00A0027L)

//
// MessageId: STATUS_CTX_CONSOLE_CONNECT
//
// MessageText:
//
//  Reconnecting a disconnected session to the console is not supported.
//
#define STATUS_CTX_CONSOLE_CONNECT       ((LONG)0xC00A0028L)

//
// MessageId: STATUS_CTX_SHADOW_DENIED
//
// MessageText:
//
//  The request to control another session remotely was denied.
//
#define STATUS_CTX_SHADOW_DENIED         ((LONG)0xC00A002AL)

//
// MessageId: STATUS_CTX_WINSTATION_ACCESS_DENIED
//
// MessageText:
//
//  A process has requested access to a session, but has not been granted those access rights.
//
#define STATUS_CTX_WINSTATION_ACCESS_DENIED ((LONG)0xC00A002BL)

//
// MessageId: STATUS_CTX_INVALID_WD
//
// MessageText:
//
//  The Terminal Connection driver %1 is invalid.
//
#define STATUS_CTX_INVALID_WD            ((LONG)0xC00A002EL)

//
// MessageId: STATUS_CTX_WD_NOT_FOUND
//
// MessageText:
//
//  The Terminal Connection driver %1 was not found in the system path.
//
#define STATUS_CTX_WD_NOT_FOUND          ((LONG)0xC00A002FL)

//
// MessageId: STATUS_CTX_SHADOW_INVALID
//
// MessageText:
//
//  The requested session cannot be controlled remotely.
//  You cannot control your own session, a session that is trying to control your session,
//  a session that has no user logged on, nor control other sessions from the console.
//
#define STATUS_CTX_SHADOW_INVALID        ((LONG)0xC00A0030L)

//
// MessageId: STATUS_CTX_SHADOW_DISABLED
//
// MessageText:
//
//  The requested session is not configured to allow remote control.
//
#define STATUS_CTX_SHADOW_DISABLED       ((LONG)0xC00A0031L)

//
// MessageId: STATUS_RDP_PROTOCOL_ERROR
//
// MessageText:
//
//  The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client.
//
#define STATUS_RDP_PROTOCOL_ERROR        ((LONG)0xC00A0032L)

//
// MessageId: STATUS_CTX_CLIENT_LICENSE_NOT_SET
//
// MessageText:
//
//  Your request to connect to this Terminal server has been rejected.
//  Your Terminal Server Client license number has not been entered for this copy of the Terminal Client.
//  Please call your system administrator for help in entering a valid, unique license number for this Terminal Server Client.
//  Click OK to continue.
//
#define STATUS_CTX_CLIENT_LICENSE_NOT_SET ((LONG)0xC00A0033L)

//
// MessageId: STATUS_CTX_CLIENT_LICENSE_IN_USE
//
// MessageText:
//
//  Your request to connect to this Terminal server has been rejected.
//  Your Terminal Server Client license number is currently being used by another user.
//  Please call your system administrator to obtain a new copy of the Terminal Server Client with a valid, unique license number.
//  Click OK to continue.
//
#define STATUS_CTX_CLIENT_LICENSE_IN_USE ((LONG)0xC00A0034L)

//
// MessageId: STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE
//
// MessageText:
//
//  The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.
//
#define STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE ((LONG)0xC00A0035L)

//
// MessageId: STATUS_CTX_SHADOW_NOT_RUNNING
//
// MessageText:
//
//  Remote control could not be terminated because the specified session is not currently being remotely controlled.
//
#define STATUS_CTX_SHADOW_NOT_RUNNING    ((LONG)0xC00A0036L)

//
// MessageId: STATUS_PNP_BAD_MPS_TABLE
//
// MessageText:
//
//  A device is missing in the system BIOS MPS table. This device will not be used.
//  Please contact your system vendor for system BIOS update.
//
#define STATUS_PNP_BAD_MPS_TABLE         ((LONG)0xC0040035L)

//
// MessageId: STATUS_PNP_TRANSLATION_FAILED
//
// MessageText:
//
//  A translator failed to translate resources.
//
#define STATUS_PNP_TRANSLATION_FAILED    ((LONG)0xC0040036L)

//
// MessageId: STATUS_PNP_IRQ_TRANSLATION_FAILED
//
// MessageText:
//
//  A IRQ translator failed to translate resources.
//
#define STATUS_PNP_IRQ_TRANSLATION_FAILED ((LONG)0xC0040037L)

//
// MessageId: STATUS_PNP_INVALID_ID
//
// MessageText:
//
//  Driver %2 returned invalid ID for a child device (%3).
//
#define STATUS_PNP_INVALID_ID            ((LONG)0xC0040038L)

//
// MessageId: STATUS_SXS_SECTION_NOT_FOUND
//
// MessageText:
//
//  The requested section is not present in the activation context.
//
#define STATUS_SXS_SECTION_NOT_FOUND     ((LONG)0xC0150001L)

//
// MessageId: STATUS_SXS_CANT_GEN_ACTCTX
//
// MessageText:
//
//  Windows was not able to process the application binding information.
//  Please refer to your System Event Log for further information.
//
#define STATUS_SXS_CANT_GEN_ACTCTX       ((LONG)0xC0150002L)

//
// MessageId: STATUS_SXS_INVALID_ACTCTXDATA_FORMAT
//
// MessageText:
//
//  The application binding data format is invalid.
//
#define STATUS_SXS_INVALID_ACTCTXDATA_FORMAT ((LONG)0xC0150003L)

//
// MessageId: STATUS_SXS_ASSEMBLY_NOT_FOUND
//
// MessageText:
//
//  The referenced assembly is not installed on your system.
//
#define STATUS_SXS_ASSEMBLY_NOT_FOUND    ((LONG)0xC0150004L)

//
// MessageId: STATUS_SXS_MANIFEST_FORMAT_ERROR
//
// MessageText:
//
//  The manifest file does not begin with the required tag and format information.
//
#define STATUS_SXS_MANIFEST_FORMAT_ERROR ((LONG)0xC0150005L)

//
// MessageId: STATUS_SXS_MANIFEST_PARSE_ERROR
//
// MessageText:
//
//  The manifest file contains one or more syntax errors.
//
#define STATUS_SXS_MANIFEST_PARSE_ERROR  ((LONG)0xC0150006L)

//
// MessageId: STATUS_SXS_ACTIVATION_CONTEXT_DISABLED
//
// MessageText:
//
//  The application attempted to activate a disabled activation context.
//
#define STATUS_SXS_ACTIVATION_CONTEXT_DISABLED ((LONG)0xC0150007L)

//
// MessageId: STATUS_SXS_KEY_NOT_FOUND
//
// MessageText:
//
//  The requested lookup key was not found in any active activation context.
//
#define STATUS_SXS_KEY_NOT_FOUND         ((LONG)0xC0150008L)

//
// MessageId: STATUS_SXS_VERSION_CONFLICT
//
// MessageText:
//
//  A component version required by the application conflicts with another component version already active.
//
#define STATUS_SXS_VERSION_CONFLICT      ((LONG)0xC0150009L)

//
// MessageId: STATUS_SXS_WRONG_SECTION_TYPE
//
// MessageText:
//
//  The type requested activation context section does not match the query API used.
//
#define STATUS_SXS_WRONG_SECTION_TYPE    ((LONG)0xC015000AL)

//
// MessageId: STATUS_SXS_THREAD_QUERIES_DISABLED
//
// MessageText:
//
//  Lack of system resources has required isolated activation to be disabled for the current thread of execution.
//
#define STATUS_SXS_THREAD_QUERIES_DISABLED ((LONG)0xC015000BL)

//
// MessageId: STATUS_SXS_ASSEMBLY_MISSING
//
// MessageText:
//
//  The referenced assembly could not be found.
//
#define STATUS_SXS_ASSEMBLY_MISSING      ((LONG)0xC015000CL)

//
// MessageId: STATUS_SXS_RELEASE_ACTIVATION_CONTEXT
//
// MessageText:
//
//  A kernel mode component is releasing a reference on an activation context.
//
#define STATUS_SXS_RELEASE_ACTIVATION_CONTEXT ((LONG)0x4015000DL)

//
// MessageId: STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET
//
// MessageText:
//
//  An attempt to set the process default activation context failed because the process default activation context was already set.
//
#define STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET ((LONG)0xC015000EL)

//
// MessageId: STATUS_SXS_MULTIPLE_DEACTIVATION
//
// MessageText:
//
//  The activation context being deactivated has already been deactivated.
//
#define STATUS_SXS_MULTIPLE_DEACTIVATION ((LONG)0xC0150011L)

//
// MessageId: STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY
//
// MessageText:
//
//  The activation context of system default assembly could not be generated.
//
#define STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY ((LONG)0xC0150012L)

//
// MessageId: STATUS_SXS_PROCESS_TERMINATION_REQUESTED
//
// MessageText:
//
//  A component used by the isolation facility has requested to terminate the process.
//
#define STATUS_SXS_PROCESS_TERMINATION_REQUESTED ((LONG)0xC0150013L)

//
// MessageId: STATUS_SXS_CORRUPT_ACTIVATION_STACK
//
// MessageText:
//
//  The activation context activation stack for the running thread of execution is corrupt.
//
#define STATUS_SXS_CORRUPT_ACTIVATION_STACK ((LONG)0xC0150014L)

//
// MessageId: STATUS_SXS_CORRUPTION
//
// MessageText:
//
//  The application isolation metadata for this process or thread has become corrupt.
//
#define STATUS_SXS_CORRUPTION            ((LONG)0xC0150015L)

//
// MessageId: STATUS_CLUSTER_INVALID_NODE
//
// MessageText:
//
//  The cluster node is not valid.
//
#define STATUS_CLUSTER_INVALID_NODE      ((LONG)0xC0130001L)

//
// MessageId: STATUS_CLUSTER_NODE_EXISTS
//
// MessageText:
//
//  The cluster node already exists.
//
#define STATUS_CLUSTER_NODE_EXISTS       ((LONG)0xC0130002L)

//
// MessageId: STATUS_CLUSTER_JOIN_IN_PROGRESS
//
// MessageText:
//
//  A node is in the process of joining the cluster.
//
#define STATUS_CLUSTER_JOIN_IN_PROGRESS  ((LONG)0xC0130003L)

//
// MessageId: STATUS_CLUSTER_NODE_NOT_FOUND
//
// MessageText:
//
//  The cluster node was not found.
//
#define STATUS_CLUSTER_NODE_NOT_FOUND    ((LONG)0xC0130004L)

//
// MessageId: STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND
//
// MessageText:
//
//  The cluster local node information was not found.
//
#define STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND ((LONG)0xC0130005L)

//
// MessageId: STATUS_CLUSTER_NETWORK_EXISTS
//
// MessageText:
//
//  The cluster network already exists.
//
#define STATUS_CLUSTER_NETWORK_EXISTS    ((LONG)0xC0130006L)

//
// MessageId: STATUS_CLUSTER_NETWORK_NOT_FOUND
//
// MessageText:
//
//  The cluster network was not found.
//
#define STATUS_CLUSTER_NETWORK_NOT_FOUND ((LONG)0xC0130007L)

//
// MessageId: STATUS_CLUSTER_NETINTERFACE_EXISTS
//
// MessageText:
//
//  The cluster network interface already exists.
//
#define STATUS_CLUSTER_NETINTERFACE_EXISTS ((LONG)0xC0130008L)

//
// MessageId: STATUS_CLUSTER_NETINTERFACE_NOT_FOUND
//
// MessageText:
//
//  The cluster network interface was not found.
//
#define STATUS_CLUSTER_NETINTERFACE_NOT_FOUND ((LONG)0xC0130009L)

//
// MessageId: STATUS_CLUSTER_INVALID_REQUEST
//
// MessageText:
//
//  The cluster request is not valid for this object.
//
#define STATUS_CLUSTER_INVALID_REQUEST   ((LONG)0xC013000AL)

//
// MessageId: STATUS_CLUSTER_INVALID_NETWORK_PROVIDER
//
// MessageText:
//
//  The cluster network provider is not valid.
//
#define STATUS_CLUSTER_INVALID_NETWORK_PROVIDER ((LONG)0xC013000BL)

//
// MessageId: STATUS_CLUSTER_NODE_DOWN
//
// MessageText:
//
//  The cluster node is down.
//
#define STATUS_CLUSTER_NODE_DOWN         ((LONG)0xC013000CL)

//
// MessageId: STATUS_CLUSTER_NODE_UNREACHABLE
//
// MessageText:
//
//  The cluster node is not reachable.
//
#define STATUS_CLUSTER_NODE_UNREACHABLE  ((LONG)0xC013000DL)

//
// MessageId: STATUS_CLUSTER_NODE_NOT_MEMBER
//
// MessageText:
//
//  The cluster node is not a member of the cluster.
//
#define STATUS_CLUSTER_NODE_NOT_MEMBER   ((LONG)0xC013000EL)

//
// MessageId: STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS
//
// MessageText:
//
//  A cluster join operation is not in progress.
//
#define STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS ((LONG)0xC013000FL)

//
// MessageId: STATUS_CLUSTER_INVALID_NETWORK
//
// MessageText:
//
//  The cluster network is not valid.
//
#define STATUS_CLUSTER_INVALID_NETWORK   ((LONG)0xC0130010L)

//
// MessageId: STATUS_CLUSTER_NO_NET_ADAPTERS
//
// MessageText:
//
//  No network adapters are available.
//
#define STATUS_CLUSTER_NO_NET_ADAPTERS   ((LONG)0xC0130011L)

//
// MessageId: STATUS_CLUSTER_NODE_UP
//
// MessageText:
//
//  The cluster node is up.
//
#define STATUS_CLUSTER_NODE_UP           ((LONG)0xC0130012L)

//
// MessageId: STATUS_CLUSTER_NODE_PAUSED
//
// MessageText:
//
//  The cluster node is paused.
//
#define STATUS_CLUSTER_NODE_PAUSED       ((LONG)0xC0130013L)

//
// MessageId: STATUS_CLUSTER_NODE_NOT_PAUSED
//
// MessageText:
//
//  The cluster node is not paused.
//
#define STATUS_CLUSTER_NODE_NOT_PAUSED   ((LONG)0xC0130014L)

//
// MessageId: STATUS_CLUSTER_NO_SECURITY_CONTEXT
//
// MessageText:
//
//  No cluster security context is available.
//
#define STATUS_CLUSTER_NO_SECURITY_CONTEXT ((LONG)0xC0130015L)

//
// MessageId: STATUS_CLUSTER_NETWORK_NOT_INTERNAL
//
// MessageText:
//
//  The cluster network is not configured for internal cluster communication.
//
#define STATUS_CLUSTER_NETWORK_NOT_INTERNAL ((LONG)0xC0130016L)

//
// MessageId: STATUS_CLUSTER_POISONED
//
// MessageText:
//
//  The cluster node has been poisoned.
//
#define STATUS_CLUSTER_POISONED          ((LONG)0xC0130017L)


//
// MessageId: STATUS_LOG_SECTOR_INVALID
//
// MessageText:
//
//  Log service found an invalid log sector.
//
#define STATUS_LOG_SECTOR_INVALID        ((LONG)0xC01A0001L)

//
// MessageId: STATUS_LOG_SECTOR_PARITY_INVALID
//
// MessageText:
//
//  Log service encountered a log sector with invalid block parity.
//
#define STATUS_LOG_SECTOR_PARITY_INVALID ((LONG)0xC01A0002L)

//
// MessageId: STATUS_LOG_SECTOR_REMAPPED
//
// MessageText:
//
//  Log service encountered a remapped log sector.
//
#define STATUS_LOG_SECTOR_REMAPPED       ((LONG)0xC01A0003L)

//
// MessageId: STATUS_LOG_BLOCK_INCOMPLETE
//
// MessageText:
//
//  Log service encountered a partial or incomplete log block.
//
#define STATUS_LOG_BLOCK_INCOMPLETE      ((LONG)0xC01A0004L)

//
// MessageId: STATUS_LOG_INVALID_RANGE
//
// MessageText:
//
//  Log service encountered an attempt access data outside the active log range.
//
#define STATUS_LOG_INVALID_RANGE         ((LONG)0xC01A0005L)

//
// MessageId: STATUS_LOG_BLOCKS_EXHAUSTED
//
// MessageText:
//
//  Log service user log marshalling buffers are exhausted.
//
#define STATUS_LOG_BLOCKS_EXHAUSTED      ((LONG)0xC01A0006L)

//
// MessageId: STATUS_LOG_READ_CONTEXT_INVALID
//
// MessageText:
//
//  Log service encountered an attempt read from a marshalling area with an invalid read context.
//
#define STATUS_LOG_READ_CONTEXT_INVALID  ((LONG)0xC01A0007L)

//
// MessageId: STATUS_LOG_RESTART_INVALID
//
// MessageText:
//
//  Log service encountered an invalid log restart area.
//
#define STATUS_LOG_RESTART_INVALID       ((LONG)0xC01A0008L)

//
// MessageId: STATUS_LOG_BLOCK_VERSION
//
// MessageText:
//
//  Log service encountered an invalid log block version.
//
#define STATUS_LOG_BLOCK_VERSION         ((LONG)0xC01A0009L)

//
// MessageId: STATUS_LOG_BLOCK_INVALID
//
// MessageText:
//
//  Log service encountered an invalid log block.
//
#define STATUS_LOG_BLOCK_INVALID         ((LONG)0xC01A000AL)

//
// MessageId: STATUS_LOG_READ_MODE_INVALID
//
// MessageText:
//
//  Log service encountered an attempt to read the log with an invalid read mode.
//
#define STATUS_LOG_READ_MODE_INVALID     ((LONG)0xC01A000BL)

//
// MessageId: STATUS_LOG_NO_RESTART
//
// MessageText:
//
//  Log service encountered a log stream with no restart area.
//
#define STATUS_LOG_NO_RESTART            ((LONG)0x401A000CL)

//
// MessageId: STATUS_LOG_METADATA_CORRUPT
//
// MessageText:
//
//  Log service encountered a corrupted metadata file.
//
#define STATUS_LOG_METADATA_CORRUPT      ((LONG)0xC01A000DL)

//
// MessageId: STATUS_LOG_METADATA_INVALID
//
// MessageText:
//
//  Log service encountered a metadata file that could not be created by the log file system.
//
#define STATUS_LOG_METADATA_INVALID      ((LONG)0xC01A000EL)

//
// MessageId: STATUS_LOG_METADATA_INCONSISTENT
//
// MessageText:
//
//  Log service encountered a metadata file with inconsistent data.
//
#define STATUS_LOG_METADATA_INCONSISTENT ((LONG)0xC01A000FL)

//
// MessageId: STATUS_LOG_RESERVATION_INVALID
//
// MessageText:
//
//  Log service encountered an attempt to erroneously allocate or dispose reservation space.
//
#define STATUS_LOG_RESERVATION_INVALID   ((LONG)0xC01A0010L)

//
// MessageId: STATUS_LOG_CANT_DELETE
//
// MessageText:
//
//  Log service cannot delete log file or file system container.
//
#define STATUS_LOG_CANT_DELETE           ((LONG)0xC01A0011L)

//
// MessageId: STATUS_LOG_CONTAINER_LIMIT_EXCEEDED
//
// MessageText:
//
//  Log service has reached the maximum allowable containers allocated to a log file.
//
#define STATUS_LOG_CONTAINER_LIMIT_EXCEEDED ((LONG)0xC01A0012L)

//
// MessageId: STATUS_LOG_START_OF_LOG
//
// MessageText:
//
//  Log service has attempted to read or write backwards past the start of the log.
//
#define STATUS_LOG_START_OF_LOG          ((LONG)0xC01A0013L)

//
// MessageId: STATUS_LOG_POLICY_ALREADY_INSTALLED
//
// MessageText:
//
//  Log policy could not be installed because a policy of the same type is already present.
//
#define STATUS_LOG_POLICY_ALREADY_INSTALLED ((LONG)0xC01A0014L)

//
// MessageId: STATUS_LOG_POLICY_NOT_INSTALLED
//
// MessageText:
//
//  Log policy in question was not installed at the time of the request.
//
#define STATUS_LOG_POLICY_NOT_INSTALLED  ((LONG)0xC01A0015L)

//
// MessageId: STATUS_LOG_POLICY_INVALID
//
// MessageText:
//
//  The installed set of policies on the log is invalid.
//
#define STATUS_LOG_POLICY_INVALID        ((LONG)0xC01A0016L)

//
// MessageId: STATUS_LOG_POLICY_CONFLICT
//
// MessageText:
//
//  A policy on the log in question prevented the operation from completing.
//
#define STATUS_LOG_POLICY_CONFLICT       ((LONG)0xC01A0017L)

//
// MessageId: STATUS_LOG_PINNED_ARCHIVE_TAIL
//
// MessageText:
//
//  Log space cannot be reclaimed because the log is pinned by the archive tail.
//
#define STATUS_LOG_PINNED_ARCHIVE_TAIL   ((LONG)0xC01A0018L)

//
// MessageId: STATUS_LOG_RECORD_NONEXISTENT
//
// MessageText:
//
//  Log record is not a record in the log file.
//
#define STATUS_LOG_RECORD_NONEXISTENT    ((LONG)0xC01A0019L)

//
// MessageId: STATUS_LOG_RECORDS_RESERVED_INVALID
//
// MessageText:
//
//  Number of reserved log records or the adjustment of the number of reserved log records is invalid.
//
#define STATUS_LOG_RECORDS_RESERVED_INVALID ((LONG)0xC01A001AL)

//
// MessageId: STATUS_LOG_SPACE_RESERVED_INVALID
//
// MessageText:
//
//  Reserved log space or the adjustment of the log space is invalid.
//
#define STATUS_LOG_SPACE_RESERVED_INVALID ((LONG)0xC01A001BL)

//
// MessageId: STATUS_LOG_TAIL_INVALID
//
// MessageText:
//
//  A new or existing archive tail or base of the active log is invalid.
//
#define STATUS_LOG_TAIL_INVALID          ((LONG)0xC01A001CL)

//
// MessageId: STATUS_LOG_FULL
//
// MessageText:
//
//  Log space is exhausted.
//
#define STATUS_LOG_FULL                  ((LONG)0xC01A001DL)

//
// MessageId: STATUS_LOG_MULTIPLEXED
//
// MessageText:
//
//  Log is multiplexed, no direct writes to the physical log is allowed.
//
#define STATUS_LOG_MULTIPLEXED           ((LONG)0xC01A001EL)

//
// MessageId: STATUS_LOG_DEDICATED
//
// MessageText:
//
//  The operation failed because the log is a dedicated log.
//
#define STATUS_LOG_DEDICATED             ((LONG)0xC01A001FL)

//
// MessageId: STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS
//
// MessageText:
//
//  The operation requires an archive context.
//
#define STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS ((LONG)0xC01A0020L)

//
// MessageId: STATUS_LOG_ARCHIVE_IN_PROGRESS
//
// MessageText:
//
//  Log archival is in progress.
//
#define STATUS_LOG_ARCHIVE_IN_PROGRESS   ((LONG)0xC01A0021L)

//
// MessageId: STATUS_LOG_EPHEMERAL
//
// MessageText:
//
//  The operation requires a non-ephemeral log, but the log is ephemeral.
//
#define STATUS_LOG_EPHEMERAL             ((LONG)0xC01A0022L)

//
// MessageId: STATUS_LOG_NOT_ENOUGH_CONTAINERS
//
// MessageText:
//
//  The log must have at least two containers before it can be read from or written to.
//
#define STATUS_LOG_NOT_ENOUGH_CONTAINERS ((LONG)0xC01A0023L)

//
// MessageId: STATUS_LOG_CLIENT_ALREADY_REGISTERED
//
// MessageText:
//
//  A log client has already registered on the stream.
//
#define STATUS_LOG_CLIENT_ALREADY_REGISTERED ((LONG)0xC01A0024L)

//
// MessageId: STATUS_LOG_CLIENT_NOT_REGISTERED
//
// MessageText:
//
//  A log client has not been registered on the stream.
//
#define STATUS_LOG_CLIENT_NOT_REGISTERED ((LONG)0xC01A0025L)

//
// MessageId: STATUS_LOG_FULL_HANDLER_IN_PROGRESS
//
// MessageText:
//
//  A request has already been made to handle the log full condition.
//
#define STATUS_LOG_FULL_HANDLER_IN_PROGRESS ((LONG)0xC01A0026L)

//
// MessageId: STATUS_LOG_CONTAINER_READ_FAILED
//
// MessageText:
//
//  Log service enountered an error when attempting to read from a log container.
//
#define STATUS_LOG_CONTAINER_READ_FAILED ((LONG)0xC01A0027L)

//
// MessageId: STATUS_LOG_CONTAINER_WRITE_FAILED
//
// MessageText:
//
//  Log service enountered an error when attempting to write to a log container.
//
#define STATUS_LOG_CONTAINER_WRITE_FAILED ((LONG)0xC01A0028L)

//
// MessageId: STATUS_LOG_CONTAINER_OPEN_FAILED
//
// MessageText:
//
//  Log service enountered an error when attempting open a log container.
//
#define STATUS_LOG_CONTAINER_OPEN_FAILED ((LONG)0xC01A0029L)

//
// MessageId: STATUS_LOG_CONTAINER_STATE_INVALID
//
// MessageText:
//
//  Log service enountered an invalid container state when attempting a requested action.
//
#define STATUS_LOG_CONTAINER_STATE_INVALID ((LONG)0xC01A002AL)

//
// MessageId: STATUS_LOG_STATE_INVALID
//
// MessageText:
//
//  Log service is not in the correct state to perform a requested action.
//
#define STATUS_LOG_STATE_INVALID         ((LONG)0xC01A002BL)

//
// MessageId: STATUS_LOG_PINNED
//
// MessageText:
//
//  Log space cannot be reclaimed because the log is pinned.
//
#define STATUS_LOG_PINNED                ((LONG)0xC01A002CL)

//
// MessageId: STATUS_LOG_METADATA_FLUSH_FAILED
//
// MessageText:
//
//  Log metadata flush failed.
//
#define STATUS_LOG_METADATA_FLUSH_FAILED ((LONG)0xC01A002DL)

//
// MessageId: STATUS_LOG_INCONSISTENT_SECURITY
//
// MessageText:
//
//  Security on the log and its containers is inconsistent.
//
#define STATUS_LOG_INCONSISTENT_SECURITY ((LONG)0xC01A002EL)

//
// MessageId: STATUS_COULD_NOT_RESIZE_LOG
//
// MessageText:
//
//  The log could not be set to the requested size.
//
#define STATUS_COULD_NOT_RESIZE_LOG      ((LONG)0x80190009L)


// end_ntsecapi


#endif
#endif