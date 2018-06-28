#include "ReflectivePolymorphism.h"

typedef struct {
	WORD    offset : 12;
	WORD    type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

BOOL RebaseImage(PDOS_HEADER pDosHeader, ULONG_PTR uiBaseFrom, ULONG_PTR uiBaseTo) {
	// Rebase the specified PE image by processing the relocation data as
	// necessary.
	//
	// PDOS_HEADER pDosHeader: Pointer to the DOS header of the blob to patch.
	// ULONG_PTR uiBaseFrom:   The address to rebase the image from.
	// ULONG_PTR uiBaseTo:     The address to rebase the image to.
	// Returns: TRUE on success.
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

	uiRebaseDelta = uiBaseFrom - uiBaseTo;
	if (uiRebaseDelta == 0) {
		return TRUE;
	}
	// pImgBaseReloc is now the first entry
	pImgBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pDosHeader + PAFromRVA(pDosHeader, pImgDataDirectory->VirtualAddress));
	while (pImgBaseReloc->SizeOfBlock) {
		uiRebaseBlock = VAFromRVA(pDosHeader, pImgBaseReloc->VirtualAddress);
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

PIMAGE_SECTION_HEADER SectionHeaderFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress) {
	// Retrieve the section header for the specified Relative Virtual Address
	// (RVA).
	//
	// PDOS_HEADER pDosHeader:    A pointer to the associated DOS header.
	// ULONG_PTR pVirtualAddress: The RVA of the section header to retrieve.
	// Returns: A pointer to the section header or NULL if it could not be
	// found.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	DWORD dwCursor = 0;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (dwCursor = 0; dwCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwCursor];
		if (!pImgSecHeaderCursor->SizeOfRawData) {
			continue;
		}
		if (pVirtualAddress < pImgSecHeaderCursor->VirtualAddress) {
			continue;
		}
		if (pVirtualAddress >= pImgSecHeaderCursor->VirtualAddress + pImgSecHeaderCursor->SizeOfRawData) {
			continue;
		}
		return pImgSecHeaderCursor;
	}
	return NULL;
}

PIMAGE_SECTION_HEADER SectionHeaderFromName(PDOS_HEADER pDosHeader, PVOID pName) {
	// Retrieve the section header for the specified name.
	//
	// PDOS_HEADER pDosHeader: A pointer to the associated DOS header.
	// PVOID pName:            A pointer to the section header name to retrieve.
	// Returns: A pointer to the section header or NULL if it could not be
	// found.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	DWORD dwCursor = 0;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (dwCursor = 0; dwCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwCursor];
		if (memcmp(pImgSecHeaderCursor->Name, pName, 8)) {
			continue;
		}
		return pImgSecHeaderCursor;
	}
	return NULL;
}

ULONG_PTR PAFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress) {
	// Calculate the Physical Address (VA) from the specified Relative Virtual
	// Address (RVA). The Physical Address is the offset within the PE image in
	// relation to the DOS header.
	//
	// PDOS_HEADER pDosHeader:    A pointer to the associated DOS header.
	// ULONG_PTR pVirtualAddress: The RVA to convert to a VA.
	// Returns: The physical address of the specified relative virtual address or
	//          NULL on failure.
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;

	pImgSecHeader = SectionHeaderFromRVA(pDosHeader, pVirtualAddress);
	if (!pImgSecHeader) {
		return 0;
	}
	pVirtualAddress -= pImgSecHeader->VirtualAddress;
	pVirtualAddress += pImgSecHeader->PointerToRawData;
	return pVirtualAddress;
}

ULONG_PTR VAFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress) {
	// Calculate the Virtual Address (VA) from the specified Relative Virtual
	// Address (RVA).
	//
	// PDOS_HEADER pDosHeader:    A pointer to the associated DOS header.
	// ULONG_PTR pVirtualAddress: The RVA to convert to a VA.
	// Returns: The virtual address of the specified relative virtual address or
	//          NULL on failure.
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	ULONG_PTR uiAddress = 0;

	pImgSecHeader = SectionHeaderFromRVA(pDosHeader, pVirtualAddress);
	if (pImgSecHeader) {
		uiAddress = (ULONG_PTR)pDosHeader;
		uiAddress += pVirtualAddress - pImgSecHeader->VirtualAddress;
		uiAddress += pImgSecHeader->PointerToRawData;
	}
	return uiAddress;
}