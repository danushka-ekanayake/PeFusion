#pragma once
#ifndef __PE_HANDLER__
#define __PE_HANDLER__
#include <Windows.h>
#include <vector>


class PeHandler
{
public:
	typedef struct _BASE_RELOC_ENTRY {
		uint16_t Offset : 12;
		uint16_t Type : 4;
	} BASE_RELOC_ENTRY, *PBASE_RELOC_ENTRY;

	static PeHandler* InitPe(const wchar_t*, DWORD*, DWORD*);

	int PeReserveMemory();
	void LoadMemorySections();
	int InitRelocations();
	int ResolveImports();
	void RunFromMemory();
	void RegisterExceptionHandlers();

	HANDLE peFileHandle;
	LARGE_INTEGER peFileSize;
	LPVOID peDataBuffer;
	LPVOID peMemoryBuffer;

	IMAGE_DOS_HEADER imgDosHead;
	IMAGE_NT_HEADERS imgNtHead;

	IMAGE_DATA_DIRECTORY imgDataDir_Export;
	IMAGE_DATA_DIRECTORY imgDataDir_Import;
	IMAGE_DATA_DIRECTORY imgDataDir_Reloc;
	IMAGE_DATA_DIRECTORY imgDataDir_Exception;

	DWORD Win32_LastError;
	DWORD Int_LastError;

	std::vector<IMAGE_SECTION_HEADER> imgSectionHeads;

	PeHandler();
	~PeHandler();

private:
	static DWORD _processPeFile(PeHandler*);
	static DWORD64 _addOffset(void* addr, DWORD64 offset);

};

inline PeHandler* PeHandler::InitPe(const wchar_t* peFn, DWORD* krnlStatus, DWORD* intStatus)
{
	PeHandler* peHndlInst = new PeHandler();
	*krnlStatus = 0x00;
	*intStatus = 0x00;
	peHndlInst->peFileHandle = CreateFile(peFn, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (peHndlInst->peFileHandle == INVALID_HANDLE_VALUE) {
		*krnlStatus = GetLastError();
		return nullptr;
	}

	if (!GetFileSizeEx(peHndlInst->peFileHandle, &peHndlInst->peFileSize)) {
		*krnlStatus = GetLastError();
		return nullptr;
	}

	peHndlInst->peDataBuffer = VirtualAlloc(0, peHndlInst->peFileSize.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!peHndlInst->peDataBuffer) {
		*krnlStatus = GetLastError();
		return nullptr;
	}

	DWORD readByteCount = 0;
	if (!ReadFile(peHndlInst->peFileHandle, peHndlInst->peDataBuffer, peHndlInst->peFileSize.QuadPart, &readByteCount, 0)) {
		*krnlStatus = GetLastError();
		return nullptr;
	}

	*intStatus = PeHandler::_processPeFile(peHndlInst);
	if (*intStatus > 0x00)
		return nullptr;

	return peHndlInst;
}

inline void PeHandler::LoadMemorySections()
{
	for (const IMAGE_SECTION_HEADER& sect : this->imgSectionHeads) {
		memcpy((reinterpret_cast<BYTE*>(this->peMemoryBuffer) + sect.VirtualAddress), reinterpret_cast<BYTE*>(this->peDataBuffer) + sect.PointerToRawData, sect.SizeOfRawData);
	}
}

inline int PeHandler::InitRelocations()
{
	IMAGE_BASE_RELOCATION* imgBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD64>(this->peMemoryBuffer) + this->imgDataDir_Reloc.VirtualAddress);
	DWORD64 relocOffsetDiff = reinterpret_cast<DWORD64>(this->peMemoryBuffer) - this->imgNtHead.OptionalHeader.ImageBase;
	DWORD64 relocPos = NULL;
	PeHandler::BASE_RELOC_ENTRY* baseRelocPtr = reinterpret_cast<PeHandler::BASE_RELOC_ENTRY*>(reinterpret_cast<DWORD64>(imgBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));
	while (imgBaseReloc->VirtualAddress != NULL) {
		DWORD relocEntryCount = (imgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(PeHandler::BASE_RELOC_ENTRY);
		for (size_t i = 0; i < relocEntryCount; i++)
		{
			relocPos = (PeHandler::_addOffset(this->peMemoryBuffer, (imgBaseReloc->VirtualAddress + baseRelocPtr[i].Offset)));
			switch (baseRelocPtr[i].Type)
			{
			case IMAGE_REL_BASED_HIGH:
				*reinterpret_cast<WORD*>(relocPos) += HIWORD(relocOffsetDiff);
				break;
			case IMAGE_REL_BASED_LOW:
				*reinterpret_cast<WORD*>(relocPos) += LOWORD(relocOffsetDiff);
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*reinterpret_cast<DWORD*>(relocPos) += DWORD(relocOffsetDiff);
				break;
			case IMAGE_REL_BASED_DIR64:
				*reinterpret_cast<DWORD64*>(relocPos) += relocOffsetDiff;
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
			default:
				break;
			}
		}
		imgBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(PeHandler::_addOffset(imgBaseReloc, imgBaseReloc->SizeOfBlock));
	}
	return 0;
}

inline int PeHandler::ResolveImports()
{
	IMAGE_IMPORT_DESCRIPTOR* imgImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(PeHandler::_addOffset(this->peMemoryBuffer, this->imgDataDir_Import.VirtualAddress));
	char* modName;
	IMAGE_THUNK_DATA* orgFirst;
	IMAGE_THUNK_DATA* first;
	BOOL isOrdinal = FALSE;
	HMODULE hMod = 0;
	LPVOID funcAddr = 0;
	PIMAGE_IMPORT_BY_NAME imgImportByName = { 0 };

	while (imgImportDesc->FirstThunk != 0 && imgImportDesc->OriginalFirstThunk != 0) {
		modName = reinterpret_cast<char*>(PeHandler::_addOffset(this->peMemoryBuffer, imgImportDesc->Name));
		hMod = GetModuleHandleA(modName);

		if (hMod == INVALID_HANDLE_VALUE || hMod == NULL) {
			hMod = LoadLibraryA(modName);
		}

		if (hMod == INVALID_HANDLE_VALUE || hMod == 0) {
			return 1;
		}
		orgFirst = reinterpret_cast<PIMAGE_THUNK_DATA>(PeHandler::_addOffset(this->peMemoryBuffer, imgImportDesc->OriginalFirstThunk));
		first = reinterpret_cast<PIMAGE_THUNK_DATA>(PeHandler::_addOffset(this->peMemoryBuffer, imgImportDesc->FirstThunk));

		while (orgFirst->u1.Function != 0 && first->u1.Function != 0) {
			isOrdinal = ((orgFirst->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) ? FALSE : TRUE;

			if (isOrdinal) {
				funcAddr = GetProcAddress(hMod, MAKEINTRESOURCEA(orgFirst->u1.Ordinal));
			}
			else {
				imgImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(PeHandler::_addOffset(this->peMemoryBuffer, orgFirst->u1.AddressOfData));
				funcAddr = GetProcAddress(hMod, imgImportByName->Name);
			}

			if (funcAddr == 0)
				return 1;

			first->u1.Function = reinterpret_cast<ULONGLONG>(funcAddr);
			orgFirst++;
			first++;
		}
		
		imgImportDesc++;
	}
	return 0;
}

inline int PeHandler::PeReserveMemory()
{
	this->peMemoryBuffer = VirtualAlloc(0, this->imgNtHead.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!this->peMemoryBuffer) {
		this->Win32_LastError = GetLastError();
		return -1;
	}
	return 0;
}

inline void PeHandler::RunFromMemory()
{
	IMAGE_SECTION_HEADER sectHead = { 0 };
	DWORD newProtFlg = 0, oldProtFlg = 0;

	for (const IMAGE_SECTION_HEADER& i : this->imgSectionHeads)
	{
		sectHead = i;

		if (sectHead.VirtualAddress == 0) {
			continue;
		}

		/*if ((sectHead.Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sectHead.Characteristics & IMAGE_SCN_MEM_READ) && !(sectHead.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtFlg = PAGE_EXECUTE;
		}
		else if ((sectHead.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectHead.Characteristics & IMAGE_SCN_MEM_READ) && !(sectHead.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtFlg = PAGE_EXECUTE_READ;
		}
		else if ((sectHead.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectHead.Characteristics & IMAGE_SCN_MEM_READ) && (sectHead.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtFlg = PAGE_EXECUTE_READWRITE;
		}
		else if (!(sectHead.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectHead.Characteristics & IMAGE_SCN_MEM_READ) && !(sectHead.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtFlg = PAGE_READONLY;
		}
		else if (!(sectHead.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectHead.Characteristics & IMAGE_SCN_MEM_READ) && (sectHead.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtFlg = PAGE_READWRITE;
		}
		else {
			return;
		}*/
		newProtFlg = PAGE_EXECUTE_READWRITE;
		LPVOID x = reinterpret_cast<LPVOID>(PeHandler::_addOffset(this->peMemoryBuffer, sectHead.VirtualAddress));
		if (!VirtualProtect(reinterpret_cast<LPVOID>(PeHandler::_addOffset(this->peMemoryBuffer, sectHead.VirtualAddress)), sectHead.SizeOfRawData, newProtFlg, &oldProtFlg)) {
			int c = GetLastError();
			continue;
		}
	}

	typedef BOOL(*MAIN)(DWORD, char*);
	LPVOID entryPtr = reinterpret_cast<LPVOID>(PeHandler::_addOffset(this->peMemoryBuffer, this->imgNtHead.OptionalHeader.AddressOfEntryPoint));
	((MAIN)(entryPtr))(1, 0);
}

inline void PeHandler::RegisterExceptionHandlers()
{
	if (this->imgDataDir_Exception.VirtualAddress != 0) {
		RUNTIME_FUNCTION* runtimeFuncTbl = reinterpret_cast<RUNTIME_FUNCTION*>(PeHandler::_addOffset(this->peMemoryBuffer, this->imgDataDir_Exception.VirtualAddress));
		if (!RtlAddFunctionTable(runtimeFuncTbl, (this->imgDataDir_Exception.Size / sizeof(RUNTIME_FUNCTION)), reinterpret_cast<DWORD64>(this->peMemoryBuffer))) {
			return;
		}
	}
}

inline DWORD PeHandler::_processPeFile(PeHandler* handlerInst)
{
	handlerInst->imgDosHead = *reinterpret_cast<PIMAGE_DOS_HEADER>(handlerInst->peDataBuffer);
	if (handlerInst->imgDosHead.e_magic != IMAGE_DOS_SIGNATURE)
		return 0x01;

	handlerInst->imgNtHead = *reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(handlerInst->peDataBuffer) + (handlerInst->imgDosHead.e_lfanew));
	if (handlerInst->imgNtHead.Signature != IMAGE_NT_SIGNATURE)
		return 0x02;

	if (!(handlerInst->imgNtHead.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
		return 0x03;

	handlerInst->imgDataDir_Exception = *&handlerInst->imgNtHead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	handlerInst->imgDataDir_Export = *&handlerInst->imgNtHead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	handlerInst->imgDataDir_Import = *&handlerInst->imgNtHead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	handlerInst->imgDataDir_Reloc = *&handlerInst->imgNtHead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	PIMAGE_SECTION_HEADER imgSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<BYTE*>(handlerInst->peDataBuffer) +
		handlerInst->imgDosHead.e_lfanew + sizeof(IMAGE_NT_HEADERS));

	handlerInst->imgSectionHeads.assign(imgSection, (imgSection + handlerInst->imgNtHead.FileHeader.NumberOfSections));

	return 0x00;
}

inline DWORD64 PeHandler::_addOffset(void* addr, DWORD64 offset)
{
	return reinterpret_cast<DWORD64>(reinterpret_cast<BYTE*>(addr) + offset);
}

PeHandler::PeHandler()
{
}

PeHandler::~PeHandler()
{
}
#endif
