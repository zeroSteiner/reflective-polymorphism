#include "ReflectiveUnloader.h"

// see: https://msdn.microsoft.com/en-us/library/f7f5138s.aspx
#ifdef _WIN64
#define IMAGE_BASE_DLL 0x180000000
#define IMAGE_BASE_EXE 0x140000000
#else
#define IMAGE_BASE_DLL 0x10000000
#define IMAGE_BASE_EXE 0x400000
#endif

typedef struct {
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

ULONG_PTR RawAddressFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress) {
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_DATA_DIRECTORY pImgDataDirectory = NULL;
	DWORD dwSecCursor;
	ULONG_PTR uiAddress;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgDataDirectory = &pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pImgDataDirectory->Size) {
		return 0;
	}

	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (dwSecCursor = 0; dwSecCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwSecCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwSecCursor];
		if (!pImgSecHeaderCursor->SizeOfRawData) {
			continue;
		}
		if (pVirtualAddress < pImgSecHeaderCursor->VirtualAddress) {
			continue;
		}
		if (pVirtualAddress >= pImgSecHeaderCursor->VirtualAddress + pImgSecHeaderCursor->SizeOfRawData) {
			continue;
		}
		uiAddress = (ULONG_PTR)pDosHeader;
		uiAddress += pVirtualAddress - pImgSecHeaderCursor->VirtualAddress;
		uiAddress += pImgSecHeaderCursor->PointerToRawData;
		return uiAddress;
	}
	return 0;
}

PIMAGE_SECTION_HEADER SectionHeaderFromName(PIMAGE_NT_HEADERS pImgNtHeaders, PVOID pName) {
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	DWORD dwCursor = 0;

	pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (dwCursor = 0; dwCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwCursor];
		if (!memcmp(pImgSecHeaderCursor->Name, pName, 8)) {
			return pImgSecHeaderCursor;
		}
	}
	return NULL;
}

DWORD ImageSizeFromHeaders(PIMAGE_NT_HEADERS pImgNtHeaders) {
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderLastRaw = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	DWORD dwCursor = 0;

	pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
	pImgSecHeaderLastRaw = pImgSecHeader;
	for (dwCursor = 0; dwCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwCursor];
		if (pImgSecHeaderLastRaw->PointerToRawData < pImgSecHeaderCursor->PointerToRawData) {
			pImgSecHeaderLastRaw = pImgSecHeaderCursor;
		}
	}
	return (pImgSecHeaderLastRaw->PointerToRawData + pImgSecHeaderLastRaw->SizeOfRawData);
}

BOOL ReflectiveUnloaderUnimport(PDOS_HEADER pDosHeader, ULONG_PTR pBaseAddress) {
	/*
	* PDOS_HEADER pDosHeader:   Pointer to the DOS header of the blob to patch
	* ULONG_PTR   pBaseAddress: Pointer to the original loaded PE blob
	*/
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pImgDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = NULL;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueD;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgDataDirectory = &pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!pImgDataDirectory->Size) {
		return FALSE;
	}

	pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pBaseAddress + pImgDataDirectory->VirtualAddress);
	while (pImgImpDesc->Name) {
		uiValueD = RawAddressFromRVA(pDosHeader, pImgImpDesc->OriginalFirstThunk);
		uiValueA = RawAddressFromRVA(pDosHeader, pImgImpDesc->FirstThunk);
		while (DEREF(uiValueA) && DEREF(uiValueD)) {
			DEREF(uiValueA) = DEREF(uiValueD);
			uiValueA += sizeof(ULONG_PTR);
			uiValueD += sizeof(ULONG_PTR);
		}
		pImgImpDesc += 1;
	}
	return TRUE;
}

BOOL ReflectiveUnloaderUnrelocate(PDOS_HEADER pDosHeader, ULONG_PTR pBaseAddress) {
	/*
	* PDOS_HEADER pDosHeader:   Pointer to the DOS header of the blob to patch
	* ULONG_PTR   pBaseAddress: Pointer to the original loaded PE blob
	*/
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pImgDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pImgBaseReloc = NULL;
	PIMAGE_RELOC pImgReloc = NULL;
	DWORD dwBlockEntries;
	ULONG_PTR uiRebaseBlock;
	ULONG_PTR uiRebaseDelta;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgDataDirectory = &pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pImgDataDirectory->Size) {
		return FALSE;
	}

	uiRebaseDelta = pBaseAddress - (ULONG_PTR)(pImgNtHeaders->OptionalHeader.ImageBase);
	/* pImgBaseReloc is now the first entry */
	pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pBaseAddress + pImgDataDirectory->VirtualAddress);
	while (pImgBaseReloc->SizeOfBlock) {
		uiRebaseBlock = RawAddressFromRVA(pDosHeader, pImgBaseReloc->VirtualAddress);
		if (uiRebaseBlock) {
			dwBlockEntries = (pImgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			pImgReloc = (PIMAGE_RELOC)((ULONG_PTR)pImgBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

			while (dwBlockEntries--) {
				if (pImgReloc->type == IMAGE_REL_BASED_DIR64) {
					*(ULONG_PTR *)(uiRebaseBlock + pImgReloc->offset) -= uiRebaseDelta;
				}
				else if (pImgReloc->type == IMAGE_REL_BASED_HIGHLOW) {
					*(DWORD *)(uiRebaseBlock + pImgReloc->offset) -= (DWORD)uiRebaseDelta;
				}
				else if (pImgReloc->type == IMAGE_REL_BASED_HIGH) {
					*(WORD *)(uiRebaseBlock + pImgReloc->offset) -= HIWORD(uiRebaseDelta);
				}
				else if (pImgReloc->type == IMAGE_REL_BASED_LOW) {
					*(WORD *)(uiRebaseBlock + pImgReloc->offset) -= LOWORD(uiRebaseDelta);
				}
				pImgReloc += 1;
			}
		}
		pImgBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pImgBaseReloc + pImgBaseReloc->SizeOfBlock);
	}
	return TRUE;
}

/* this step is optional */
BOOL ReflectiveUnloaderRestoreWritable(PDOS_HEADER pDosHeader, ULONG_PTR pBaseAddress) {
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCopy = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderDst = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderSrc = NULL;
	DWORD dwImageSize = 0;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgSecHeaderCopy = SectionHeaderFromName(pImgNtHeaders, ".restore");
	if (!pImgSecHeaderCopy) {
		return FALSE;
	}
	if (!pImgSecHeaderCopy->SizeOfRawData) {
		return FALSE;
	}

	dwImageSize = ImageSizeFromHeaders(pImgNtHeaders);
	pImgSecHeaderCursor = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pDosHeader + pImgSecHeaderCopy->PointerToRawData);
	while (memcmp(pImgSecHeaderCursor->Name, "\x00\x00\x00\x00\x00\x00\x00\x00", 8)) {
		pImgSecHeaderSrc = pImgSecHeaderCursor;
		pImgSecHeaderCursor += 1;

		if (!pImgSecHeaderSrc->SizeOfRawData) {
			continue;
		}
		pImgSecHeaderDst = SectionHeaderFromName(pImgNtHeaders, pImgSecHeaderSrc->Name);
		if (!pImgSecHeaderDst) {
			return FALSE;
		}
		if (pImgSecHeaderDst->SizeOfRawData != pImgSecHeaderSrc->SizeOfRawData) {
			return FALSE;
		}
		if (dwImageSize < (pImgSecHeaderCursor->PointerToRawData + pImgSecHeaderCursor->SizeOfRawData)) {
			return FALSE;
		}
		CopyMemory(
			(PVOID)((ULONG_PTR)pDosHeader + pImgSecHeaderDst->PointerToRawData),
			(PVOID)((ULONG_PTR)pDosHeader + pImgSecHeaderSrc->PointerToRawData),
			pImgSecHeaderDst->SizeOfRawData
		);
	}
	return TRUE;
}

VOID ReflectiveUnloaderFree(PVOID pAddress, SIZE_T dwSize) {
	/*
	 * PVOID  pAddress: Pointer to the blob returned by ReflectiveUnloader
	 * SIZE_T dwSize:   Size of the blob returned by ReflectiveUnloader
	 */
	SecureZeroMemory(pAddress, dwSize);
#ifdef DEBUG
	VirtualFree(pAddress, dwSize, MEM_DECOMMIT | MEM_RELEASE);
#else
	HeapFree(GetProcessHeap(), 0, pAddress);
#endif
	return;
}

PVOID ReflectiveUnloader(HINSTANCE hInstance, PSIZE_T pdwSize) {
	/*
	 * HINSTANCE hInstance: Handle to the module instance to unload from memory
	 * PSIZE_T   pdwSize:   Size of the returned blob
	 */
	PDOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	ULONG_PTR pBaseAddress = 0;
	SIZE_T dwImageSize = 0;
	DWORD dwCursor = 0;
	PVOID pCursor = NULL;

	if (pdwSize) {
		*pdwSize = 0;
	}
	pDosHeader = (PDOS_HEADER)hInstance;
	if (DEREF_32(pDosHeader) != 0x00905a4d) {
		return NULL;
	}
	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	if (pImgNtHeaders->Signature != 0x4550) {
		return NULL;
	}

	dwImageSize = ImageSizeFromHeaders(pImgNtHeaders);
#ifdef DEBUG
	pBaseAddress = (ULONG_PTR)VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
	pBaseAddress = (ULONG_PTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwImageSize);
#endif
	if (!pBaseAddress) {
		return NULL;
	}

	CopyMemory((PVOID)pBaseAddress, (PVOID)pDosHeader, dwImageSize);
	pCursor = pDosHeader;
	pDosHeader = (PDOS_HEADER)pBaseAddress;
	pBaseAddress = (ULONG_PTR)pCursor;
	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));

	/*
	* 0x400000 for EXEs and 0x10000000 for DLLs
	* see: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
	*/
	if (pImgNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		pImgNtHeaders->OptionalHeader.ImageBase = IMAGE_BASE_DLL;
	}
	else if (pImgNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		pImgNtHeaders->OptionalHeader.ImageBase = IMAGE_BASE_EXE;
	}

	for (dwCursor = 0; dwCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwCursor];
		if (!pImgSecHeaderCursor->SizeOfRawData) {
			continue;
		}
		pCursor = (PVOID)((ULONG_PTR)pDosHeader + pImgSecHeaderCursor->PointerToRawData);
		if (dwImageSize < (pImgSecHeaderCursor->PointerToRawData + pImgSecHeaderCursor->SizeOfRawData)) {
			ReflectiveUnloaderFree((PVOID)pDosHeader, dwImageSize);
			return NULL;
		}
		CopyMemory(pCursor, (PVOID)(pBaseAddress + pImgSecHeaderCursor->VirtualAddress), pImgSecHeaderCursor->SizeOfRawData);
	}

	ReflectiveUnloaderUnrelocate(pDosHeader, pBaseAddress);
	ReflectiveUnloaderUnimport(pDosHeader, pBaseAddress);
	ReflectiveUnloaderRestoreWritable(pDosHeader, pBaseAddress);

	if (pdwSize) {
		*pdwSize = dwImageSize;
	}
	return pDosHeader;
}
