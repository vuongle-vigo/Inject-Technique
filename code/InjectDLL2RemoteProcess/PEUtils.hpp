#ifndef PE_UTILS_HPP
#define PE_UTILS_HPP

#include <Windows.h>
#include <iostream>

class PEUtils {
public:
	typedef struct _PE_STRUCT {
		PBYTE pPePointer;
		DWORD dwFilesize;

		PIMAGE_DOS_HEADER pImageDosHeader;
		PIMAGE_NT_HEADERS pImageNtHeader;
		PIMAGE_SECTION_HEADER pImageSectionHeader;

		PIMAGE_DATA_DIRECTORY pEntryImportDataDir;
		PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir;

	} PE_STRUCT, * PPE_STRUCT;



	BOOL ReadFileFromDisk(IN LPCSTR lpFileName, OUT PBYTE* ppbBuffer, OUT PDWORD pdwFilesize);
	BOOL InitializePEStruct(IN PBYTE pbBuffer, IN DWORD dwFilesize, OUT PPE_STRUCT pPeStruct);
	BOOL WritePE2Target(IN HANDLE hTargetProc = nullptr, IN PPE_STRUCT pPeStruct);
	BOOL FixReloc(IN HANDLE hTargetProc = nullptr, IN PPE_STRUCT pPeStruct, IN DWORD_PTR lpPeImagebase);
	BOOL FixIAT();

private:
	typedef struct BASE_RELOCATION_BLOCK {
		DWORD VirtualAddressBlock;
		DWORD SizeOfBlock;
	} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

	typedef struct BASE_RELOCATION_ENTRY {	//uint16_t 16bits = 1byte
		//Type is placed after because the bytes are arranged in little endian
		uint16_t  Offset : 12;
		uint16_t  Type : 4;
	} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
};

#endif
