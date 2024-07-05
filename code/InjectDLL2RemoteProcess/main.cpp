#include "misc.hpp"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

typedef struct BASE_RELOCATION_BLOCK {
	DWORD VirtualAddressBlock;
	DWORD SizeOfBlock;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {	//uint16_t 16bits = 1byte
	//Type is placed after because the bytes are arranged in little endian
	uint16_t  Offset : 12;
	uint16_t  Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _PE_Struct {
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeader;
	PIMAGE_SECTION_HEADER pImageSectionHeader;

} PE_Struct, *PPE_Struct;


HANDLE getProcHandlebyName(LPWSTR procName, DWORD* PID) {
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);
	NTSTATUS status = NULL;
	HANDLE hProc = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot) {
		DEBUG("[x] Cannot retrieve the processes snapshot\n");
		return NULL;
	}
	if (Process32First(snapshot, &entry)) {
		do {
			if (wcscmp((entry.szExeFile), procName) == 0) {
				*PID = entry.th32ProcessID;
				DEBUG("[+] Injecting into : %d\n", *PID);
				hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
				if (!hProc) { continue; }
				return hProc;
			}
		} while (Process32Next(snapshot, &entry));
	}

	return NULL;

}


int main() {
	DWORD PID;
	PE_Struct pPeStruct = { 0 };
	HANDLE hProc = getProcHandlebyName((LPWSTR)L"cmd.exe", &PID);
	if (!hProc) {
		DEBUG("[-] Cannot find process to get handle");
		return -1;
	}

	HANDLE hDll = CreateFileA("C:\\Users\\Yasuo\\source\\repos\\Dll1\\x64\\Release\\Dll1.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD_PTR dwDllSize = GetFileSize(hDll, NULL);
	LPVOID lpDllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDllSize);
	if (!ReadFile(hDll, lpDllBuffer, dwDllSize, NULL, NULL)) {
		DEBUG("[-] Cannot read dll to buffer with error code : %d", GetLastError());
		return -1;
	}

	pPeStruct.pImageDosHeader = (PIMAGE_DOS_HEADER)lpDllBuffer;
	pPeStruct.pImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpDllBuffer + pPeStruct.pImageDosHeader->e_lfanew);
	pPeStruct.pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpDllBuffer + pPeStruct.pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	// (LPVOID)pPeStruct.pImageNtHeader->OptionalHeader.ImageBase don't work when try alloc in this memory address, replace with nullptr
	LPVOID lpNewDllImagebase = VirtualAllocEx(hProc, nullptr, pPeStruct.pImageNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpNewDllImagebase) {
		DEBUG("[-] Cannot alloc memory in remote process with error code: %d", GetLastError());
		return -1;
	}
	DWORD dwDeltaImagebase = (DWORD_PTR)lpNewDllImagebase - pPeStruct.pImageNtHeader->OptionalHeader.ImageBase;

	//Write PE Header to Remote process
	if (!WriteProcessMemory(hProc, lpNewDllImagebase, lpDllBuffer, pPeStruct.pImageNtHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
		DEBUG("[-] Write PE Header to Remote process failed with error code : %d", GetLastError());
		return -1;
	}

	//Write PE Section to Remote process 
	PIMAGE_SECTION_HEADER pSectionPtr = pPeStruct.pImageSectionHeader;
	for (int i = 0; i < pPeStruct.pImageNtHeader->FileHeader.NumberOfSections; i++) {
		LPVOID lpRawSectionPtr = (LPVOID)((DWORD_PTR)lpDllBuffer + pSectionPtr->PointerToRawData);
		LPVOID lpMemSectionPtr = (LPVOID)((DWORD_PTR)lpNewDllImagebase + pSectionPtr->VirtualAddress);
		if (!WriteProcessMemory(hProc, lpMemSectionPtr, lpRawSectionPtr, pSectionPtr->SizeOfRawData, nullptr)) {
			DEBUG("[-] Write PE Section to Remote process failed with error code : %d", GetLastError());
			return -1;
		}
		pSectionPtr++;
	}

	//Find .reloc section
	const char* relocName = ".reloc";
	PIMAGE_SECTION_HEADER pRelocSection = pPeStruct.pImageSectionHeader;
	for (int i = 0; i < pPeStruct.pImageNtHeader->FileHeader.NumberOfSections; i++) {
		if (!strcmp(relocName, (char*)pRelocSection->Name)) {
			break;
		}
		pRelocSection++;
	}

	//Rewrite location based on relocation table 
	/*if (dwDeltaImagebase != 0) {
		PBASE_RELOCATION_BLOCK pDllReloc = (PBASE_RELOCATION_BLOCK)((DWORD_PTR)lpDllBuffer + pRelocSection->PointerToRawData);
		DWORD_PTR dwCountOffset = 0;
		while (dwCountOffset < pPeStruct.pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			uintptr_t countElementOfBlock = (pDllReloc->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / 2;
			PBASE_RELOCATION_ENTRY sourceRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)lpDllBuffer + sizeof(BASE_RELOCATION_BLOCK));
			for (int i = 0; i < countElementOfBlock; i++) {
				if (sourceRelocationEntry->Type == 0) {
					continue;
				}
				DWORD_PTR relocationAddress = (DWORD_PTR)lpNewDllImagebase + pDllReloc->VirtualAddressBlock + sourceRelocationEntry->Offset;
				SIZE_T byteRead;
				DWORD_PTR valueModify = 0;
				ReadProcessMemory(hProc, (LPCVOID)relocationAddress, &valueModify, sizeof(DWORD_PTR), &byteRead);
				valueModify += dwDeltaImagebase;
				WriteProcessMemory(hProc, (LPVOID)relocationAddress, &valueModify, sizeof(DWORD_PTR), NULL);
				sourceRelocationEntry++;
			}
			dwCountOffset += pDllReloc->SizeOfBlock;
			pDllReloc = (PBASE_RELOCATION_BLOCK)((DWORD_PTR)pDllReloc + pDllReloc->SizeOfBlock);
		}
	}*/

	// Resolve import address table
	IMAGE_DATA_DIRECTORY importsDirectory = pPeStruct.pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	LPVOID lpImportDescriptorPtr = (LPVOID)((DWORD_PTR)lpNewDllImagebase + importsDirectory.VirtualAddress);
	LPVOID lpImportDescriptorBuffer = VirtualAlloc(nullptr, sizeof(IMAGE_IMPORT_DESCRIPTOR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ReadProcessMemory(hProc, lpImportDescriptorPtr, lpImportDescriptorBuffer, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr)) {
		DEBUG("[-] Cannot read import descriptor from remote process with error: %d", GetLastError());
		return -1;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpImportDescriptorBuffer);
	LPCSTR lpLibraryName = "";
	HMODULE hLibrary = NULL;

	while (importDescriptor->Name != 0)
	{	
		BYTE bLibName[20] = { 0 };
		int k = 0;
		LPVOID lpLibraryNamePtr = (LPVOID)((DWORD_PTR)lpNewDllImagebase + importDescriptor->Name);
		while (1) {
			BYTE byte = 0;
			if (!ReadProcessMemory(hProc, lpLibraryNamePtr, &byte, 1, nullptr)) {
				DEBUG("[-] Cannot read dll name import from remote process with error: %d", GetLastError());
				return -1;
			}
			bLibName[k] = byte;
			k++;
			lpLibraryNamePtr = (LPVOID) ((DWORD_PTR)lpLibraryNamePtr + 1);
			if (byte == '\0') { break; }
		}
		DEBUG("[+] Library Name: %s\n", bLibName);

		lpLibraryName = (DWORD_PTR)lpNewDllImagebase + (LPCSTR)importDescriptor->Name;

		hLibrary = LoadLibraryA((LPCSTR)bLibName);
		if (!hLibrary) {
			DEBUG("[-] Cannot LoadLibrary with error: %d", GetLastError());
			return -1;
		}
		if (hLibrary)
		{
			LPVOID lpImageThunkDataIATPtr = (LPVOID)((DWORD64)lpNewDllImagebase + importDescriptor->FirstThunk);
			LPVOID lpImageThunkDataIATBuffer = VirtualAlloc(nullptr, sizeof(IMAGE_THUNK_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!ReadProcessMemory(hProc, lpImageThunkDataIATPtr, lpImageThunkDataIATBuffer, sizeof(IMAGE_THUNK_DATA), nullptr)) {
				DEBUG("[-] Cannot read import descriptor from remote process with error: %d", GetLastError());
				return -1;
			}
			PIMAGE_THUNK_DATA dllImageThunkDataIAT = (PIMAGE_THUNK_DATA)(lpImageThunkDataIATBuffer);
			while (dllImageThunkDataIAT->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(dllImageThunkDataIAT->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(dllImageThunkDataIAT->u1.Ordinal);
					dllImageThunkDataIAT->u1.Function = (DWORD64)GetProcAddress(hLibrary, functionOrdinal);
				}
				else
				{
					LPVOID lpImageImportByNamePtr = (LPVOID)((DWORD64)lpNewDllImagebase + dllImageThunkDataIAT->u1.AddressOfData);
					LPVOID lpImageImportByNameBuffer = VirtualAlloc(nullptr, sizeof(IMAGE_IMPORT_BY_NAME), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (!ReadProcessMemory(hProc, lpImageImportByNamePtr, lpImageImportByNameBuffer, sizeof(IMAGE_IMPORT_BY_NAME), nullptr)) {
						DEBUG("[-] Cannot read function import by name from remote process with error: %d", GetLastError());
						return -1;
					}
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(lpImageImportByNameBuffer);
					lpImageImportByNamePtr = (LPVOID)((DWORD_PTR)lpImageImportByNamePtr + 2);
					BYTE bFunctionName[50] = { 0 };
					int j = 0;
					LPVOID lpLibraryNamePtr = (LPVOID)((DWORD_PTR)lpNewDllImagebase + importDescriptor->Name);
					while (1) {
						BYTE byte = 0;
						if (!ReadProcessMemory(hProc, lpImageImportByNamePtr, &byte, 1, nullptr)) {
							DEBUG("[-] Cannot read dll name import from remote process with error: %d", GetLastError());
							return -1;
						}
						bFunctionName[j] = byte;
						j++;
						lpImageImportByNamePtr = (LPVOID)((DWORD_PTR)lpImageImportByNamePtr + 1);
						if (byte == '\0') { break; }
					}
					DEBUG("[+] Import Function Name: %s\n", bFunctionName);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(hLibrary, (LPCSTR)(bFunctionName));

					if (!WriteProcessMemory(hProc, lpImageThunkDataIATPtr, &functionAddress, 8, nullptr)) {
						DEBUG("[-] Cannot write address of function to import descriptor from remote process with error: %d", GetLastError());
						return -1;
					}
				}
				lpImageThunkDataIATPtr = (LPVOID)((DWORD_PTR)lpImageThunkDataIATPtr + sizeof(IMAGE_THUNK_DATA));
				if (!ReadProcessMemory(hProc, lpImageThunkDataIATPtr, lpImageThunkDataIATBuffer, sizeof(IMAGE_THUNK_DATA), nullptr)) {
					DEBUG("[-] Cannot read import descriptor from remote process with error: %d", GetLastError());
					return -1;
				}
				dllImageThunkDataIAT = (PIMAGE_THUNK_DATA)(lpImageThunkDataIATBuffer);
			}
		}
		
		lpImportDescriptorPtr = (LPVOID)((DWORD_PTR)lpImportDescriptorPtr + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (!ReadProcessMemory(hProc, lpImportDescriptorPtr, lpImportDescriptorBuffer, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr)) {
			DEBUG("[-] Cannot read import descriptor from remote process with error: %d", GetLastError());
			return -1;
		}
		
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpImportDescriptorBuffer);
		
	}

	DWORD addr = 0;
	//Read export dll function
	/*IMAGE_DATA_DIRECTORY exportsDirectory = pPeStruct.pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	LPVOID lpExportDirectoryPtr = (LPVOID)((DWORD_PTR)lpNewDllImagebase + exportsDirectory.VirtualAddress);
	LPVOID lpExportDirectoryBuffer = VirtualAlloc(nullptr, sizeof(IMAGE_EXPORT_DIRECTORY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ReadProcessMemory(hProc, lpExportDirectoryPtr, lpExportDirectoryBuffer, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr)) {
		DEBUG("[-] Cannot read import descriptor from remote process with error: %d", GetLastError());
		return -1;
	}
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)lpExportDirectoryBuffer;
	DWORD_PTR addressOfNamesRVAPtr = (DWORD_PTR)lpNewDllImagebase + exportDirectory->AddressOfNames;
	DWORD_PTR addressOfFunctionsRVAPtr = (DWORD_PTR)lpNewDllImagebase + exportDirectory->AddressOfFunctions;
	DWORD_PTR addressOfNameOrdinalsRVAPtr = (DWORD_PTR)lpNewDllImagebase + exportDirectory->AddressOfNameOrdinals;

	for (int i = 0; i < exportDirectory->NumberOfNames; i++) {
		DWORD addressOfNamesRVA = 0;
		if (!ReadProcessMemory(hProc, (LPVOID)addressOfNamesRVAPtr, &addressOfNamesRVA, 4, nullptr)) {
			DEBUG("[-] Cannot read address of names RVA from remote process with error: %d", GetLastError());
			return -1;
		}

		addressOfNamesRVAPtr = addressOfNamesRVAPtr + 4;

		WORD addressOfNameOrdinalsRVA = 0;
		if (!ReadProcessMemory(hProc, (LPVOID)addressOfNameOrdinalsRVAPtr, &addressOfNameOrdinalsRVA, 2, nullptr)) {
			DEBUG("[-] Cannot read address of names RVA from remote process with error: %d", GetLastError());
			return -1;
		}

		addressOfNameOrdinalsRVAPtr = addressOfNameOrdinalsRVAPtr + 2;

		printf("[+] Ordinal: %d\n", addressOfNameOrdinalsRVA);

		addressOfFunctionsRVAPtr = addressOfFunctionsRVAPtr + addressOfNameOrdinalsRVA;
		DWORD addressOfFunctionsRVA = 0;
		if (!ReadProcessMemory(hProc, (LPVOID)addressOfFunctionsRVAPtr, &addressOfFunctionsRVA, 4, nullptr)) {
			DEBUG("[-] Cannot read address of names RVA from remote process with error: %d", GetLastError());
			return -1;
		}

		printf("[+] Address of function RVA: %d\n", addressOfFunctionsRVA);
		addr = addressOfFunctionsRVA;
		DWORD_PTR addressOfNameVA = (DWORD_PTR)lpNewDllImagebase + addressOfNamesRVA;
		BYTE bFunctionName[50] = { 0 };
		int j = 0;
		LPVOID lpLibraryNamePtr = (LPVOID)((DWORD_PTR)lpNewDllImagebase + importDescriptor->Name);
		while (1) {
			BYTE byte = 0;
			if (!ReadProcessMemory(hProc, (LPVOID)addressOfNameVA, &byte, 1, nullptr)) {
				DEBUG("[-] Cannot read dll name export from remote process with error: %d", GetLastError());
				return -1;
			}

			bFunctionName[j] = byte;
			j++;
			addressOfNameVA = addressOfNameVA + 1;
			if (byte == '\0') { break; }
		}
		DEBUG("[+] Export Function Name: %s\n", bFunctionName);
	}*/


	//DWORD_PTR entrypoint = addr + (DWORD_PTR)lpNewDllImagebase;
	DWORD_PTR entrypoint = 0x1000 + (DWORD_PTR)lpNewDllImagebase;
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)entrypoint, nullptr, 0, nullptr);
	if (!hThread) {
		DEBUG("[-] Cannot CreateRemoteThread to run dll with error code: %d", GetLastError());
		return -1;
	}

	
	CloseHandle(hDll);
	HeapFree(GetProcessHeap(), 0, lpDllBuffer);
	return 1;

}