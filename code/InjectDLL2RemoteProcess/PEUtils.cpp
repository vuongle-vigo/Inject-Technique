#include "PEUtils.hpp"

#define PRINT_WINAPI_ERR(lpAPIName) printf("[!] %s Failed With Error: %d\n", lpAPIName, GetLastError())

BOOL PEUtils::ReadFileFromDisk(IN LPCSTR lpFileName, OUT PBYTE* ppbBuffer, OUT PDWORD pdwFilesize) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE pbBuffer = nullptr;
	DWORD dwFilesize = 0;
	DWORD dwNumberOfBytesRead = 0;

	hFile = CreateFileA(lpFileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		PRINT_WINAPI_ERR("CreateFileA");
		return FALSE;
	}

	dwFilesize = GetFileSize(hFile, NULL);
	pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFilesize);
	if (!ReadFile(hFile, pbBuffer, dwFilesize, &dwNumberOfBytesRead, NULL) || dwFilesize != dwNumberOfBytesRead) {
		PRINT_WINAPI_ERR("ReadFile");
		return -1;
	}

	*ppbBuffer = pbBuffer;
	*pdwFilesize = dwFilesize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	
	if (!pbBuffer) {
		HeapFree(GetProcessHeap(), 0, pbBuffer);
	}

	return ((*ppbBuffer != NULL) && (*pdwFilesize != 0)) ? TRUE : FALSE;
}

BOOL PEUtils::InitializePEStruct(IN PBYTE pbBuffer, IN DWORD dwFilesize, OUT PPE_STRUCT pPeStruct) {
	if (!pbBuffer || !dwFilesize || !pPeStruct) {
		return FALSE;
	}

	pPeStruct->pPePointer = pbBuffer;
	pPeStruct->dwFilesize = dwFilesize;

	pPeStruct->pImageDosHeader = (PIMAGE_DOS_HEADER)pbBuffer;
	pPeStruct->pImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pbBuffer + pPeStruct->pImageDosHeader->e_lfanew);

	if (pPeStruct->pImageNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	pPeStruct->pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pbBuffer + pPeStruct->pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	pPeStruct->pEntryImportDataDir = &pPeStruct->pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeStruct->pEntryBaseRelocDataDir = &pPeStruct->pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return TRUE;
}

BOOL PEUtils::WritePE2Target(IN HANDLE hTargetProc = nullptr, IN PPE_STRUCT pPeStruct) {
	LPVOID lpPeImagebase = VirtualAllocEx(hTargetProc, nullptr, pPeStruct->pImageNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!lpPeImagebase) {
		PRINT_WINAPI_ERR("VirtualAllocEx");
		return FALSE;
	}

	//DWORD dwDeltaImagebase = (DWORD_PTR)lpNewDllImagebase - pPeStruct.pImageNtHeader->OptionalHeader.ImageBase;

	//Write PE Header
	if (hTargetProc != nullptr) {
		if (!WriteProcessMemory(hTargetProc, lpPeImagebase, pPeStruct->pPePointer, pPeStruct->pImageNtHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
			PRINT_WINAPI_ERR("WriteProcessMemory");
			return FALSE;
		}
	} 
	else {
		memcpy(lpPeImagebase, pPeStruct->pPePointer, pPeStruct->pImageNtHeader->OptionalHeader.SizeOfHeaders);
	}
	
	// Write PE Section
	PIMAGE_SECTION_HEADER pSectionPtr = pPeStruct->pImageSectionHeader;
	for (int i = 0; i < pPeStruct->pImageNtHeader->FileHeader.NumberOfSections; i++) {
		LPVOID lpRawSectionPtr = (LPVOID)((DWORD_PTR)pPeStruct->pPePointer + pSectionPtr->PointerToRawData);
		LPVOID lpMemSectionPtr = (LPVOID)((DWORD_PTR)lpPeImagebase + pSectionPtr->VirtualAddress);

		if (hTargetProc != nullptr) {
			if (!WriteProcessMemory(hTargetProc, lpMemSectionPtr, lpRawSectionPtr, pSectionPtr->SizeOfRawData, nullptr)) {
				PRINT_WINAPI_ERR("WriteProcessMemory");
				return FALSE;
			}
		}
		else {
			memcpy(lpMemSectionPtr, lpRawSectionPtr, pSectionPtr->SizeOfRawData);
		}
		
		pSectionPtr++;
	}
	
	return TRUE;
}

BOOL PEUtils::FixReloc(IN HANDLE hTargetProc = nullptr, IN PPE_STRUCT pPeStruct, IN DWORD_PTR lpPeImagebase) {
	DWORD dwDeltaImagebase = lpPeImagebase - pPeStruct->pImageNtHeader->OptionalHeader.ImageBase;
	//Rewrite location based on relocation table 
	if (dwDeltaImagebase != 0) {
		PBASE_RELOCATION_BLOCK pRelocBlock = (PBASE_RELOCATION_BLOCK)(lpPeImagebase + pPeStruct->pEntryBaseRelocDataDir->VirtualAddress);

		DWORD_PTR dwCountOffset = 0;
		while (dwCountOffset < pPeStruct->pEntryBaseRelocDataDir->Size) {
			uintptr_t countElementOfBlock = (pRelocBlock->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / 2;
			PBASE_RELOCATION_ENTRY sourceRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)pPeStruct->pPePointer + sizeof(BASE_RELOCATION_BLOCK));
			for (int i = 0; i < countElementOfBlock; i++) {
				if (sourceRelocationEntry->Type == 0) {
					continue;
				}

				DWORD_PTR relocationAddress = (DWORD_PTR)lpPeImagebase + pRelocBlock->VirtualAddressBlock + sourceRelocationEntry->Offset;
				SIZE_T byteRead;
				DWORD_PTR valueModify = 0;
				ReadProcessMemory(hTargetProc, (LPCVOID)relocationAddress, &valueModify, sizeof(DWORD_PTR), &byteRead);
				valueModify += dwDeltaImagebase;
				WriteProcessMemory(hTargetProc, (LPVOID)relocationAddress, &valueModify, sizeof(DWORD_PTR), NULL);
				sourceRelocationEntry++;
			}
			dwCountOffset += pRelocBlock->SizeOfBlock;
			pRelocBlock = (PBASE_RELOCATION_BLOCK)((DWORD_PTR)pRelocBlock + pRelocBlock->SizeOfBlock);
		}
	}
}