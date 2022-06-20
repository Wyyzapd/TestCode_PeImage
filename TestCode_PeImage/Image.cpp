#include "Image.h"
#include <stdio.h>



Image::Image()
{
	this->Status = 0;
	this->FileData = 0;
	this->Initialize = false;
	this->HidePE = false;
	this->Errorline = 0;
	this->NtHeader = 0;
	this->Section = 0;
	this->SectionSize = { 0 };
	this->SectionHandle = 0;
	this->BaseAddress = 0;
	this->ViewSize = 0;
	this->LdrpNtdllBase = this->RtlFindLdrTableEntryByBaseName(L"ntdll.dll");
	this->RtlFindLdrpInvertedFunctionTable = this->FindLdrpInvertedFunctionTable32();
	this->StartupRoutine = 0;
	this->ExportDir = 0;
	this->ExportSize = 0;
	this->ExportOffset = 0;
	this->ExportprtAddress = 0;
	this->ExportOrdinals = 0;
	this->ExportNames = 0;
	this->IsExport = false;
}

Image::~Image()
{
	this->UnImage();
}

bool Image::Load(const wchar_t* lpFileName, bool ErasePE)
{

	if (!this->Initialize)
	{
		if (this->Open(lpFileName,&this->FileData))
		{
			this->HidePE = ErasePE;
			if (this->NtLoadDllMmEx())
			{
				Native::NtUnmapViewOfSection(NtCurrentProcess(), this->FileData);
				return this->Initialize;
			}
			Native::NtUnmapViewOfSection(NtCurrentProcess(), this->FileData);
		}
	}
	return this->Initialize;
}

bool Image::Load(const void* Buff, bool ErasePE)
{
	if (!this->Initialize)
	{
		this->HidePE = ErasePE;
		this->FileData = (void*)Buff;
		return this->NtLoadDllMmEx();
	}
	return this->Initialize;
}

bool Image::Open(const wchar_t* lpFileName, void** FileBuff)
{

	wchar_t NtFileName[265] = L"\\??\\";
	UNICODE_STRING FullDllName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE mFileHandle = 0;
	HANDLE mSectionHandle = 0;
	IO_STATUS_BLOCK IoStatus = { 0 };
	SIZE_T BytesLength = 0;


	wcscat_s(NtFileName, 265, lpFileName);
	this->Status = Native::RtlInitUnicodeStringEx(&FullDllName, NtFileName);
	if (!NT_SUCCESS(this->Status))
		return false;

	InitializeObjectAttributes(&ObjectAttributes, &FullDllName, OBJ_CASE_INSENSITIVE, 0, 0);

	this->Status = Native::NtOpenFile(
		&mFileHandle,
		FILE_READ_ATTRIBUTES | FILE_READ_DATA,
		&ObjectAttributes,
		&IoStatus,
		FILE_SHARE_READ,
		0);

	if (!NT_SUCCESS(this->Status) || !NT_SUCCESS(IoStatus.Status))
	{
		this->Errorline = 85;
		goto Exit;
	}
		

	this->Status = Native::NtCreateSection(
		&mSectionHandle,
		SECTION_ALL_ACCESS,
		0,
		0,
		PAGE_READONLY,
		SEC_COMMIT,
		mFileHandle);

	if (!NT_SUCCESS(this->Status))
	{
		this->Errorline = 100;
		goto Exit;
	}

	this->Status = Native::NtMapViewOfSection(
		mSectionHandle,
		NtCurrentProcess(),
		FileBuff,
		0,
		0,
		0,
		&BytesLength,
		_SECTION_INHERIT::ViewShare,
		0,
		PAGE_READONLY);

	if (NT_SUCCESS(this->Status))
	{
		
		Native::NtClose(mFileHandle);
		Native::NtClose(mSectionHandle);
		return true;
	}
	else
	{
		this->Errorline = 115;
	}
Exit:
	if (mFileHandle)
		Native::NtClose(mFileHandle);

	if (mSectionHandle)
		Native::NtClose(mSectionHandle);

	return false;
}

bool Image::NtLoadDllMmEx()
{

	if (!this->VerifyImage())
		return false;

	if(!this->MmLoadLibrary())
		return false;

	
	if (!NT_SUCCESS(this->RtlInsertInvertedFunctionTable()))
	{
		Native::NtUnmapViewOfSection(NtCurrentProcess(), this->BaseAddress);
		return false;
	}

	if (this->LdrpExecuteTLS())
	{
		this->Initialize = LdrpCallInitializers(DLL_PROCESS_ATTACH);
		if(!this->Initialize)
			Native::NtUnmapViewOfSection(NtCurrentProcess(), this->BaseAddress);
	}

	
	return this->Initialize;
}

bool Image::VerifyImage()
{
	this->NtHeader = Native::RtlImageNtHeader(this->FileData);
	if (this->NtHeader)
	{
		if (PIMAGE_DOS_HEADER(this->FileData)->e_magic == IMAGE_DOS_SIGNATURE &&
			this->NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
			return true;
		else
			this->Errorline = 180;
	}
	this->Errorline = 178;
	return false;
}

bool Image::MmLoadLibrary()
{

	PVOID NewAddress = 0;
	PVOID OldAddress = 0;
	DWORD Delta = 0;
	PIMAGE_BASE_RELOCATION RelocationDir = 0;
	PIMAGE_DATA_DIRECTORY ImportDir = nullptr;
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = nullptr;
	PIMAGE_IMPORT_DESCRIPTOR ImportIAT = nullptr;
	uint32_t Count = 0;

	/*Create Section*/
	this->SectionSize.QuadPart = this->NtHeader->OptionalHeader.SizeOfImage;

	this->Status = Native::NtCreateSection(
		&this->SectionHandle, 
		SECTION_ALL_ACCESS,
		0, 
		&this->SectionSize, 
		0x40,
		SEC_COMMIT, 
		nullptr);

	if (!NT_SUCCESS(this->Status))
	{
		this->Errorline = 205;
		return false;
	}
		

	/*Map Page*/
	this->Status = Native::NtMapViewOfSection(
		this->SectionHandle, 
		NtCurrentProcess(), 
		&this->BaseAddress, 
		0,
		0, 
		nullptr, 
		&this->ViewSize,
		_SECTION_INHERIT::ViewUnmap, 
		0, 
		0x40);

	if (!NT_SUCCESS(this->Status))
	{
		this->Errorline = 222;
		Native::NtClose(this->SectionHandle);
		return false;
	}
	
	/*Copy Image*/

	RtlCopyMemory(this->BaseAddress,this->FileData, this->NtHeader->OptionalHeader.SizeOfHeaders);

	/*Get Section Table*/
	this->Section = IMAGE_FIRST_SECTION(this->NtHeader);

	/*Copy Image Section*/
	for (uint32_t i = 0; i < this->NtHeader->FileHeader.NumberOfSections; ++i)
	{
		if (!this->Section[i].VirtualAddress || !this->Section[i].SizeOfRawData)
			continue;

		NewAddress = OffsetPointer(this->BaseAddress,this->Section[i].VirtualAddress);
		OldAddress = OffsetPointer(this->FileData, this->Section[i].PointerToRawData);
		RtlCopyMemory(NewAddress, OldAddress, this->Section[i].SizeOfRawData);
	}
	/*Get NtHeader*/
	this->NtHeader = Native::RtlImageNtHeader(this->BaseAddress);
	/*Get Section Table*/
	this->Section = IMAGE_FIRST_SECTION(this->NtHeader);

	Native::NtClose(this->SectionHandle);

	/*fix relocation*/
	RelocationDir = 
		PIMAGE_BASE_RELOCATION(this->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + DWORD(BaseAddress));
	Delta = DWORD(DWORD(BaseAddress) - NtHeader->OptionalHeader.ImageBase);
	while ((RelocationDir->VirtualAddress + RelocationDir->SizeOfBlock) != 0)
	{
		PWORD Address = PWORD(DWORD(RelocationDir) + sizeof(IMAGE_BASE_RELOCATION));
		DWORD Count = ((RelocationDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2);
		for (size_t i = 0; i < Count; i++)
		{

			if (DWORD(Address[i] & 0xF000) == 0x3000)
			{
				PDWORD ShortPtr = PDWORD(DWORD(BaseAddress) + RelocationDir->VirtualAddress + (Address[i] & 0xFFF));
				*ShortPtr += Delta;
			}
		}
		RelocationDir = PIMAGE_BASE_RELOCATION(DWORD(RelocationDir) + RelocationDir->SizeOfBlock);
	}

	this->NtHeader->OptionalHeader.ImageBase = (uint32_t)this->BaseAddress;

	/* Fix import table */
	__try {
		ImportDir = GET_HEADER_DICTIONARY(this->NtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

		this->Status = STATUS_SUCCESS;

		if (ImportDir && ImportDir->Size) {
			ImportIAT = ImportDesc = PIMAGE_IMPORT_DESCRIPTOR((uint32_t)this->BaseAddress + ImportDir->VirtualAddress);
		}

		if (ImportIAT) {
			while (ImportIAT->Name) {
				++Count;
				++ImportIAT;
			}
		}

		if (ImportDesc && Count) {

			for (DWORD i = 0; i < Count; ++i, ++ImportDesc) {
				uintptr_t* Thunk;
				FARPROC* FirstThunk;
				Thunk = (uintptr_t*)((uint32_t)this->BaseAddress + (ImportDesc->OriginalFirstThunk ? ImportDesc->OriginalFirstThunk : ImportDesc->FirstThunk));
				FirstThunk = (FARPROC*)((uint32_t)this->BaseAddress + ImportDesc->FirstThunk);
				while (*Thunk) {

					this->Status = LoadIATModule(
						(LPCSTR)((uint32_t)this->BaseAddress + ImportDesc->Name),
						IMAGE_SNAP_BY_ORDINAL(*Thunk) ? (LPCSTR)IMAGE_ORDINAL(*Thunk) : (LPCSTR)PIMAGE_IMPORT_BY_NAME((uint32_t)this->BaseAddress + (*Thunk))->Name,
						(PVOID*)FirstThunk);
					if (!NT_SUCCESS(this->Status) || !*FirstThunk)
					{
						this->Errorline = 313;
						break;
					}	
					++Thunk;
					++FirstThunk;
				}

				if (!NT_SUCCESS(this->Status))
					break;
			}

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		this->Status = GetExceptionCode();
	}
	if (!NT_SUCCESS(this->Status))
	{
		Native::NtUnmapViewOfSection(NtCurrentProcess(), this->BaseAddress);
		return false;
	}

	if(this->NtHeader->OptionalHeader.AddressOfEntryPoint)
		this->StartupRoutine = (PDLL_STARTUP_ROUTINE)OffsetPointer(this->BaseAddress, this->NtHeader->OptionalHeader.AddressOfEntryPoint);
	
	if (this->HidePE)
	{
		RtlZeroMemory(this->BaseAddress, sizeof IMAGE_DOS_HEADER);
		this->NtHeader->Signature = 0;
		for (uint32_t i = 0; i < this->NtHeader->FileHeader.NumberOfSections; ++i)
		{
			this->Section[i].Characteristics = 0;
			RtlZeroMemory(this->Section[i].Name,8);
		}
	}

	/*Get Export Table*/
	if (this->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		this->IsExport = true;
		this->ExportDir =
			PIMAGE_EXPORT_DIRECTORY(this->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + this->NtHeader->OptionalHeader.ImageBase);
		this->ExportSize = this->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		this->ExportOffset = this->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		LPDWORD(ExportDir->AddressOfFunctions + this->NtHeader->OptionalHeader.ImageBase);
		this->ExportOrdinals =
			LPWORD(ExportDir->AddressOfNameOrdinals + this->NtHeader->OptionalHeader.ImageBase);
		this->ExportNames =
			LPDWORD(ExportDir->AddressOfNames + this->NtHeader->OptionalHeader.ImageBase);
		this->ExportprtAddress =
			LPDWORD(this->ExportDir->AddressOfFunctions + this->NtHeader->OptionalHeader.ImageBase);
	}
	

	/* STATUS_SUCCESS */
	return true;
}

NTSTATUS Image::LoadIATModule(const char* ImportName, const char* lpProcName, PVOID* Function)
{
	STRING AnsiDestinationString = { 0 };
	UNICODE_STRING DestinationString = { 0 };
	HMODULE DllHandle = 0;
	STRING ProcedureName = { 0 };

	this->Status = STATUS_SUCCESS;

	this->Status = Native::RtlInitAnsiStringEx(&AnsiDestinationString, ImportName);
	if (NT_SUCCESS(this->Status))
	{
		this->Status = Native::RtlAnsiStringToUnicodeString(&DestinationString, &AnsiDestinationString, 1);
		if (NT_SUCCESS(this->Status))
		{
			if (!NT_SUCCESS(Native::LdrGetDllHandle(0, 0, &DestinationString, &DllHandle)))
				if (!NT_SUCCESS(Native::LdrLoadDll(0, 0, &DestinationString, &DllHandle)))
				{
					this->Errorline = 393;
					return (this->Status = STATUS_DLL_NOT_FOUND);
				}
					
			if ((DWORD)lpProcName & 0xffff0000)
			{
				this->Status = Native::RtlInitAnsiStringEx(&ProcedureName, lpProcName);
				if (NT_SUCCESS(this->Status))
				{
					//printf_s("LoadIATModule:   %s:%s\n", ImportName, lpProcName);
					this->Status = Native::LdrGetProcedureAddress(DllHandle, &ProcedureName, 0, Function);
				}
				else
					this->Errorline = 401;
			}
			else
			{
				this->Status = Native::LdrGetProcedureAddress(DllHandle, 0, (ULONG)lpProcName, Function);
			}
			return this->Status;
		}
		else
			this->Errorline = 389;
	}
	else
		this->Errorline = 386;

	return this->Status;
}

NTSTATUS Image::RtlInsertInvertedFunctionTable()
{
	PRTL_INVERTED_FUNCTION_TABLE table = PRTL_INVERTED_FUNCTION_TABLE(RtlFindLdrpInvertedFunctionTable);
	if (!table)
		return STATUS_NOT_SUPPORTED;
	bool need_virtual_protect = RtlIsWindowsVersionOrGreater(6, 3, 0);
	if (need_virtual_protect) {
		this->Status = RtlProtectMrdata(PAGE_READWRITE);
		if (!NT_SUCCESS(this->Status))
		{
			this->Errorline = 432;
			return this->Status;
		}
	}
	RtlpInsertInvertedFunctionTable(table);
	if (need_virtual_protect) {
		this->Status = RtlProtectMrdata(PAGE_READONLY);
		if (!NT_SUCCESS(this->Status))
		{
			this->Errorline = 441;
			return this->Status;
		}
	}
	return (RtlIsWindowsVersionOrGreater(6, 2, 0) ? PRTL_INVERTED_FUNCTION_TABLE_64(table)->Overflow : PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(table)->Overflow) ?
		STATUS_NO_MEMORY : STATUS_SUCCESS;
}

PVOID Image::FindLdrpInvertedFunctionTable32() 
{

	HMODULE hModule = nullptr;
	PIMAGE_NT_HEADERS NtdllHeaders = nullptr; 
	PIMAGE_NT_HEADERS ModuleHeaders = nullptr;
	_RTL_INVERTED_FUNCTION_TABLE_ENTRY_WIN7_32 entry{};
	LPCSTR lpSectionName = ".data";
	SEARCH_CONTEXT SearchContext { SearchContext.MemoryBuffer = &entry,SearchContext.BufferLength = sizeof(entry) };
	PLIST_ENTRY ListHead = 0; 
	PLIST_ENTRY ListEntry = 0;
	PLDR_DATA_TABLE_ENTRY CurEntry = nullptr;
	DWORD SEHTable, SEHCount;
	BYTE Offset = 0x20;
	PRTL_INVERTED_FUNCTION_TABLE_WIN7_32 Table = 0;


	NtdllHeaders = Native::RtlImageNtHeader(this->LdrpNtdllBase->DllBase);
	ListHead = &NtCurrentTeb()->Peb->Ldr->InMemoryOrderModuleList;
	ListEntry = ListHead->Flink;


	if (this->RtlIsWindowsVersionOrGreater(6, 3, 0))
		lpSectionName = ".mrdata";
	else if (!this->RtlIsWindowsVersionOrGreater(6, 2, 0))
		Offset = 0xC;

	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ListEntry = ListEntry->Flink;
		if (this->RtlIsModuleUnloaded(CurEntry))
			continue;					//skip unloaded module
		if (this->BaseAddress == CurEntry->DllBase)
			continue;  //skip our memory module.
		if (CurEntry->DllBase == this->LdrpNtdllBase->DllBase && Offset == 0x20)
			continue;	//Win10 skip first entry, if the base of ntdll is smallest.
		hModule = (HMODULE)(hModule ? min(hModule, CurEntry->DllBase) : CurEntry->DllBase);
	}
	ModuleHeaders = Native::RtlImageNtHeader(hModule);
	if (!hModule || !ModuleHeaders  || !NtdllHeaders)
		return nullptr;

	this->RtlCaptureImageExceptionValues(hModule, &SEHTable, &SEHCount);
	entry = { Native::RtlEncodeSystemPointer((PVOID)SEHTable),(DWORD)hModule,ModuleHeaders->OptionalHeader.SizeOfImage,(PVOID)SEHCount };

	while (NT_SUCCESS(this->RtlFindMemoryBlockFromModuleSection((HMODULE)this->LdrpNtdllBase->DllBase, lpSectionName, &SearchContext)))
	{
		Table = PRTL_INVERTED_FUNCTION_TABLE_WIN7_32(SearchContext.OutBufferPtr - Offset);

		//Note: Same memory layout for RTL_INVERTED_FUNCTION_TABLE_ENTRY in Windows 10 x86 and x64.
		if (this->RtlIsWindowsVersionOrGreater(6, 2, 0) && 
			Table->MaxCount == 0x200 && !Table->NextEntrySEHandlerTableEncoded)
			return Table;
		else if (Table->MaxCount == 0x200 && !Table->Overflow)
			return Table;
	}

	return nullptr;
}

bool Image::RtlVerifyVersion(DWORD MajorVersion,DWORD MinorVersion, DWORD BuildNumber,BYTE Flags)
{
	DWORD Versions[3];
	Native::RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);
	if (Versions[0] == MajorVersion &&
		((Flags & 1) ? Versions[1] == MinorVersion : true) && ((Flags & 2) ? Versions[2] == BuildNumber : true))
		return true;
	this->Errorline = 515;
	return false;
}

bool Image::RtlIsWindowsVersionOrGreater(DWORD MajorVersion,DWORD MinorVersion,DWORD BuildNumber)
{
	static DWORD Versions[3]{};
	if (!Versions[0])
		Native::RtlGetNtVersionNumbers(Versions, Versions + 1, Versions + 2);

	if (Versions[0] == MajorVersion) {
		if (Versions[1] == MinorVersion) 
			return Versions[2] >= BuildNumber;
		else 
			return (Versions[1] > MinorVersion);
	}
	else 
		return Versions[0] > MajorVersion;
}

bool Image::RtlIsWindowsVersionInScope(DWORD MinMajorVersion,DWORD MinMinorVersion, DWORD MinBuildNumber,DWORD MaxMajorVersion,DWORD MaxMinorVersion,DWORD MaxBuildNumber)
{
	return this->RtlIsWindowsVersionOrGreater(MinMajorVersion, MinMinorVersion, MinBuildNumber) &&
		!this->RtlIsWindowsVersionOrGreater(MaxMajorVersion, MaxMinorVersion, MaxBuildNumber);
}

bool Image::RtlIsModuleUnloaded(PLDR_DATA_TABLE_ENTRY entry)
{
	if (this->RtlIsWindowsVersionOrGreater(6, 2, 0)) {
		return PLDR_DATA_TABLE_ENTRY_WIN8(entry)->DdagNode->State == LdrModulesUnloaded;
	}
	else {
		return entry->DllBase == nullptr;
	}
}

int Image::RtlCaptureImageExceptionValues(PVOID BaseAddress, PDWORD SEHandlerTable, PDWORD SEHandlerCount)
{
	PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfigDirectory;
	PIMAGE_COR20_HEADER pCor20;
	ULONG Size;

	//check if no seh
	if (Native::RtlImageNtHeader(BaseAddress)->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
		*SEHandlerTable = *SEHandlerCount = -1;
		this->Errorline = 562;
		return 0;
	}

	//get seh table and count
	pLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)Native::RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size);
	if (pLoadConfigDirectory) {
		if (Size == 0x40 && pLoadConfigDirectory->Size >= 0x48u) {
			if (pLoadConfigDirectory->SEHandlerTable && pLoadConfigDirectory->SEHandlerCount) {
				*SEHandlerTable = pLoadConfigDirectory->SEHandlerTable;
				return *SEHandlerCount = pLoadConfigDirectory->SEHandlerCount;
			}
		}
	}

	//is .net core ?
	pCor20 = (PIMAGE_COR20_HEADER)Native::RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &Size);
	*SEHandlerTable = *SEHandlerCount = ((pCor20 && pCor20->Flags & 1) ? -1 : 0);
	return 0;
}

NTSTATUS Image::RtlFindMemoryBlockFromModuleSection(HMODULE hModule,LPCSTR lpSectionName	,PSEARCH_CONTEXT SearchContext)
{
	size_t begin = 0, buffer = 0;
	DWORD Length = 0, bufferLength = 0;

	__try {
		begin = SearchContext->OutBufferPtr;
		Length = SearchContext->RemainingLength;
		buffer = SearchContext->InBufferPtr;
		bufferLength = SearchContext->BufferLength;
		if (!buffer || !bufferLength) {
			SearchContext->OutBufferPtr = 0;
			SearchContext->RemainingLength = 0;
			return STATUS_INVALID_PARAMETER;
		}
		if (!begin) {
			PIMAGE_NT_HEADERS headers = Native::RtlImageNtHeader(hModule);
			PIMAGE_SECTION_HEADER section = nullptr;
			if (!headers)
				return STATUS_INVALID_PARAMETER_1;
			section = IMAGE_FIRST_SECTION(headers);
			for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
				if (!_stricmp(lpSectionName, (LPCSTR)section->Name)) {
					begin = SearchContext->OutBufferPtr = (size_t)hModule + section->VirtualAddress;
					Length = SearchContext->RemainingLength = section->Misc.VirtualSize;
					break;
				}
				++section;
			}
			if (!begin || !Length || Length < bufferLength) {
				SearchContext->OutBufferPtr = 0;
				SearchContext->RemainingLength = 0;
				return STATUS_NOT_FOUND;
			}
		}
		else {
			begin++;
			Length--;
		}
		this->Status = STATUS_NOT_FOUND;
		for (DWORD i = 0; i < Length - bufferLength; ++begin, ++i) {
			if (RtlCompareMemory((PVOID)begin, (PVOID)buffer, bufferLength) == bufferLength) {
				SearchContext->OutBufferPtr = begin;
				--SearchContext->RemainingLength;
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		this->Status = GetExceptionCode();
	}

	SearchContext->OutBufferPtr = 0;
	SearchContext->RemainingLength = 0;
	return this->Status;
}

PLDR_DATA_TABLE_ENTRY Image::RtlFindLdrTableEntryByBaseName(PCWSTR BaseName)
{
	PLIST_ENTRY ListHead = &NtCurrentTeb()->Peb->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
	PLDR_DATA_TABLE_ENTRY CurEntry;
	while (ListEntry != ListHead) {
		CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ListEntry = ListEntry->Flink;
		if (!wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, (CurEntry->BaseDllName.Length / sizeof(wchar_t)) - 4) ||
			!wcsnicmp(BaseName, CurEntry->BaseDllName.Buffer, CurEntry->BaseDllName.Length / sizeof(wchar_t))) {
			return CurEntry;
		}
	}
	return nullptr;
}

NTSTATUS Image::RtlProtectMrdata(SIZE_T Protect) {
	static PVOID MrdataBase = nullptr;
	static SIZE_T size = 0;
	PVOID tmp;
	SIZE_T tmp_len;
	ULONG old;
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };

	if (!MrdataBase) {
		
		this->Status = Native::NtQueryVirtualMemory(
			NtCurrentProcess(), 
			this->RtlFindLdrpInvertedFunctionTable,
			MemoryBasicInformation,
			&MemoryBasic,
			sizeof(MemoryBasic),
			nullptr);
		if (!NT_SUCCESS(this->Status))
			return this->Status;
		MrdataBase = MemoryBasic.BaseAddress;
		size = MemoryBasic.RegionSize;
	}

	tmp = MrdataBase;
	tmp_len = size;
	return Native::NtProtectVirtualMemory(NtCurrentProcess(), &tmp, &tmp_len, Protect, &old);
}

VOID Image::RtlpInsertInvertedFunctionTable(PRTL_INVERTED_FUNCTION_TABLE InvertedTable)
{

	DWORD ptr, count;
	bool IsWin8OrGreater = RtlIsWindowsVersionOrGreater(6, 2, 0);
	ULONG Index = IsWin8OrGreater ? 1 : 0;

	if (InvertedTable->Count == InvertedTable->MaxCount) {
		if (IsWin8OrGreater)InvertedTable->NextEntrySEHandlerTableEncoded = TRUE;
		else InvertedTable->Overflow = TRUE;
		return;
	}
	while (Index < InvertedTable->Count) {
		if (this->BaseAddress < (IsWin8OrGreater ?
			((PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64)&InvertedTable->Entries[Index])->ImageBase :
			InvertedTable->Entries[Index].ImageBase))
			break;
		Index++;
	}
	if (Index != InvertedTable->Count) {
		if (IsWin8OrGreater) {
			RtlMoveMemory(&InvertedTable->Entries[Index + 1], &InvertedTable->Entries[Index],
				(InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
		else {
			RtlMoveMemory(&InvertedTable->Entries[Index].NextEntrySEHandlerTableEncoded,
				Index ? &InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded : (PVOID)&InvertedTable->NextEntrySEHandlerTableEncoded,
				(InvertedTable->Count - Index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY));
		}
	}

	RtlCaptureImageExceptionValues(this->BaseAddress, &ptr, &count);
	if (IsWin8OrGreater) {
		//memory layout is same as x64
		PRTL_INVERTED_FUNCTION_TABLE_ENTRY_64 entry = (decltype(entry))&InvertedTable->Entries[Index];
		entry->ExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)Native::RtlEncodeSystemPointer((PVOID)ptr);
		entry->ExceptionDirectorySize = count;
		entry->ImageBase = this->BaseAddress;
		entry->ImageSize = this->NtHeader->OptionalHeader.SizeOfImage;
	}
	else {
		if (Index) InvertedTable->Entries[Index - 1].NextEntrySEHandlerTableEncoded = Native::RtlEncodeSystemPointer((PVOID)ptr);
		else InvertedTable->NextEntrySEHandlerTableEncoded = (DWORD)Native::RtlEncodeSystemPointer((PVOID)ptr);
		InvertedTable->Entries[Index].ImageBase = this->BaseAddress;
		InvertedTable->Entries[Index].ImageSize = this->NtHeader->OptionalHeader.SizeOfImage;
		InvertedTable->Entries[Index].SEHandlerCount = count;
	}

	++InvertedTable->Count;

	return;
}

bool Image::LdrpExecuteTLS()
{

	PIMAGE_TLS_DIRECTORY Tls;
	PIMAGE_TLS_CALLBACK* Callback;
	PIMAGE_DATA_DIRECTORY TlsDir = &this->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	
	if (TlsDir->VirtualAddress == 0)
		return true;
	Tls = (PIMAGE_TLS_DIRECTORY)OffsetPointer(this->NtHeader->OptionalHeader.ImageBase, TlsDir->VirtualAddress);
	Callback = (PIMAGE_TLS_CALLBACK*)Tls->AddressOfCallBacks;
	if (Callback) {
		while (*Callback) {
			(*Callback)(this->BaseAddress, DLL_PROCESS_ATTACH, nullptr);
			Callback++;
		}
	}

	return true;
}

bool Image::LdrpCallInitializers(DWORD dwReason)
{
	if (this->StartupRoutine)
	{
		__try {
			// notify library about attaching to process
			if (this->StartupRoutine(this->BaseAddress, dwReason, 0)) {
				return true;
			}
			SetLastError(ERROR_DLL_INIT_FAILED);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			SetLastError(Native::RtlNtStatusToDosError(GetExceptionCode()));
		}

		return false;
	}

	return true;
}

NTSTATUS Image::UnImage()
{
	if (this->Initialize)
	{
		this->LdrpCallInitializers(DLL_PROCESS_DETACH);
		return Native::NtUnmapViewOfSection(NtCurrentProcess(), this->BaseAddress);
	}
	return 0x1;
}

bool Image::Export(const char* lpProcName, PVOID* Function)
{
	int Ordinal = 0;
	int Found = 0;
	DWORD ExportOffset_V = 0;

	if (this->Initialize)
	{
		if (this->IsExport)
		{
			Ordinal = -1;
			if (!(DWORD(lpProcName) & 0xFFFF0000))
			{
				Ordinal = IMAGE_ORDINAL(DWORD(lpProcName)) - this->ExportDir->Base;
			}
			else
			{
				Found = -1;
				for (size_t i = 0; i < this->ExportDir->NumberOfNames; i++)
				{
					PCHAR ExportName = PCHAR(this->ExportNames[i] + this->NtHeader->OptionalHeader.ImageBase);
					if (!strcmp(ExportName, lpProcName))
					{
						Found = i;
						break;
					}
				}
				if (Found >= 0)
				{
					Ordinal = INT(this->ExportOrdinals[Found]);
				}
			}

			if (Ordinal < 0 || DWORD(Ordinal) >= this->ExportDir->NumberOfFunctions)
			{
				return 0;
			}
			else
			{
				ExportOffset_V = this->ExportprtAddress[Ordinal];
				if (ExportOffset_V > this->ExportOffset && ExportOffset_V < (this->ExportOffset + this->ExportSize))
				{
					return false;
				}
				else
				{
					if (Function)
					{
						*Function = PVOID(ExportOffset_V + this->NtHeader->OptionalHeader.ImageBase);
						return true;
					}
					else
						return false;
				}
			}
		}
	}
	return false;
}

