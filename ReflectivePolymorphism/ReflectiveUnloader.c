#include "ReflectiveUnloader.h"

static DWORD ImageSizeFromHeaders(PDOS_HEADER pDosHeader) {
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderLastRaw = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	DWORD dwCursor = 0;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
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

static BOOL ReflectiveUnloaderUnimport(PDOS_HEADER pDosHeader) {
	// PDOS_HEADER pDosHeader: Pointer to the DOS header of the blob to patch.
	// Returns: TRUE on success.
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

	pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pDosHeader + PAFromRVA(pDosHeader, pImgDataDirectory->VirtualAddress));
	while (pImgImpDesc->Name) {
		uiValueD = VAFromRVA(pDosHeader, pImgImpDesc->OriginalFirstThunk);
		uiValueA = VAFromRVA(pDosHeader, pImgImpDesc->FirstThunk);
		while (DEREF(uiValueA) && DEREF(uiValueD)) {
			DEREF(uiValueA) = DEREF(uiValueD);
			uiValueA += sizeof(ULONG_PTR);
			uiValueD += sizeof(ULONG_PTR);
		}
		pImgImpDesc += 1;
	}
	return TRUE;
}

static BOOL ReflectiveUnloaderUnrelocate(PDOS_HEADER pDosHeader, ULONG_PTR pBaseAddress) {
	// PDOS_HEADER pDosHeader: Pointer to the DOS header of the blob to patch.
	// ULONG_PTR pBaseAddress: Pointer to the original loaded PE blob.
	// Returns: TRUE on success.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pImgDataDirectory = NULL;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgDataDirectory = &pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pImgDataDirectory->Size) {
		return FALSE;
	}

	return RebaseImage(pDosHeader, pBaseAddress, (ULONG_PTR)(pImgNtHeaders->OptionalHeader.ImageBase));
}

static BOOL ReflectiveUnloaderRestoreWritable(PDOS_HEADER pDosHeader) {
	// Restore the sections that were backed up in the ".restore" section if it
	// is present. If the ".restore" section is not present, this function will
	// return FALSE and the resulting PE image will probably be corrupted due to
	// changes made to writeable sections persisting in the unloaded copy.
	//
	// PDOS_HEADER pDosHeader: Pointer to the DOS header of the blob to patch.
	// Returns: TRUE on success.
	PIMAGE_SECTION_HEADER pImgSecHeaderCopy = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderDst = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderSrc = NULL;
	DWORD dwImageSize = 0;

	pImgSecHeaderCopy = SectionHeaderFromName(pDosHeader, ".restore");
	if (!pImgSecHeaderCopy) {
		return FALSE;
	}
	if (!pImgSecHeaderCopy->SizeOfRawData) {
		return FALSE;
	}

	dwImageSize = ImageSizeFromHeaders(pDosHeader);
	pImgSecHeaderCursor = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pDosHeader + pImgSecHeaderCopy->PointerToRawData);
	while (memcmp(pImgSecHeaderCursor->Name, "\x00\x00\x00\x00\x00\x00\x00\x00", 8)) {
		pImgSecHeaderSrc = pImgSecHeaderCursor;
		pImgSecHeaderCursor += 1;

		if (!pImgSecHeaderSrc->SizeOfRawData) {
			continue;
		}
		pImgSecHeaderDst = SectionHeaderFromName(pDosHeader, pImgSecHeaderSrc->Name);
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
	// Free memory that was previously allocated by ReflectiveUnloader().
	//
	// PVOID pAddress: Pointer to the blob returned by ReflectiveUnloader.
	// SIZE_T dwSize:  Size of the blob returned by ReflectiveUnloader.
	SecureZeroMemory(pAddress, dwSize);
#ifdef DEBUG
	VirtualFree(pAddress, dwSize, MEM_DECOMMIT | MEM_RELEASE);
#else
	HeapFree(GetProcessHeap(), 0, pAddress);
#endif
	return;
}

PVOID ReflectiveUnloader(HINSTANCE hInstance, PSIZE_T pdwSize) {
	// Unload the module indicated by hInstance and return a pointer to it's
	// location in memory. If this function fails, NULL is returned.
	//
	// HINSTANCE hInstance: Handle to the module instance to unload from memory.
	// PSIZE_T pdwSize:     The size of the returned PE image.
	// Returns: A pointer to a blob of the unloaded PE image.
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

	dwImageSize = ImageSizeFromHeaders(pDosHeader);
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

	// 0x00400000 for EXEs and 0x10000000 for DLLs
	// see: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
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
	ReflectiveUnloaderUnimport(pDosHeader);
	// This step is optional
	ReflectiveUnloaderRestoreWritable(pDosHeader);

	if (pdwSize) {
		*pdwSize = dwImageSize;
	}
	return pDosHeader;
}
