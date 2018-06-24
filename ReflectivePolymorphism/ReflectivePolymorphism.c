#include "ReflectivePolymorphism.h"

PIMAGE_SECTION_HEADER SectionHeaderFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pAddress) {
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
		if (pAddress < pImgSecHeaderCursor->VirtualAddress) {
			continue;
		}
		if (pAddress >= pImgSecHeaderCursor->VirtualAddress + pImgSecHeaderCursor->SizeOfRawData) {
			continue;
		}
		return pImgSecHeaderCursor;
	}
	return NULL;
}

PIMAGE_SECTION_HEADER SectionHeaderFromName(PDOS_HEADER pDosHeader, PVOID pName) {
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