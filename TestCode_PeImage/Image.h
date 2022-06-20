#include <Windows.h>
#include "Native/ntdll.h"

class Image
{
public:
	Image();
	~Image();
	bool Load(const wchar_t* lpFileName, bool ErasePE);
	bool Load(const void* Buff,bool ErasePE);
	NTSTATUS UnImage();
	bool Export(const char* lpProcName, PVOID* Function);

private:
	NTSTATUS Status;
	PVOID FileData;
	bool Initialize;
	bool HidePE;
	uint32_t Errorline;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER Section;
	LARGE_INTEGER SectionSize;
	HANDLE SectionHandle;
	PVOID BaseAddress;
	SIZE_T ViewSize;
	PLDR_DATA_TABLE_ENTRY LdrpNtdllBase;
	PVOID RtlFindLdrpInvertedFunctionTable;
	PDLL_STARTUP_ROUTINE StartupRoutine;
	PIMAGE_EXPORT_DIRECTORY ExportDir;
	uint32_t ExportSize;
	uint32_t ExportOffset;
	LPDWORD ExportprtAddress;
	LPWORD  ExportOrdinals;
	LPDWORD ExportNames;
	bool IsExport;

private:
	bool Open(const wchar_t* lpFileName, void** FileBuff);
	bool NtLoadDllMmEx();
	bool VerifyImage();
	bool MmLoadLibrary();
	NTSTATUS LoadIATModule(const char* ImportName, const char* lpProcName, PVOID* Function);
	NTSTATUS RtlInsertInvertedFunctionTable();
	PVOID FindLdrpInvertedFunctionTable32();
	bool RtlIsWindowsVersionInScope(DWORD MinMajorVersion, DWORD MinMinorVersion, DWORD MinBuildNumber, DWORD MaxMajorVersion, DWORD MaxMinorVersion, DWORD MaxBuildNumber);
	bool RtlIsWindowsVersionOrGreater(DWORD MajorVersion, DWORD MinorVersion, DWORD BuildNumber);
	bool RtlVerifyVersion(DWORD MajorVersion, DWORD MinorVersion, DWORD BuildNumber, BYTE Flags);
	bool RtlIsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry);
	int RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount);
	NTSTATUS RtlFindMemoryBlockFromModuleSection(HMODULE hModule, LPCSTR lpSectionName, PSEARCH_CONTEXT SearchContext);
	PLDR_DATA_TABLE_ENTRY RtlFindLdrTableEntryByBaseName(PCWSTR BaseName);
	NTSTATUS RtlProtectMrdata(SIZE_T Protect);
	VOID RtlpInsertInvertedFunctionTable(PRTL_INVERTED_FUNCTION_TABLE InvertedTable);
	bool LdrpExecuteTLS();
	bool LdrpCallInitializers(DWORD dwReason);
	
};