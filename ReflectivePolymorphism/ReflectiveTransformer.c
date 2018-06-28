#include "ReflectiveTransformer.h"

static PIMAGE_NT_HEADERS ImageNTHeadersFromDOSHeader(PDOS_HEADER pDosHeader) {
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;

	if (DEREF_32(pDosHeader) != 0x00905a4d) {
		return NULL;
	}
	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	if (pImgNtHeaders->Signature != 0x4550) {
		return NULL;
	}
	return pImgNtHeaders;
}

BOOL DOSHeaderIsDLL(PDOS_HEADER pDosHeader) {
	// Check the FileHeader Characteristics field to determine whether the PE
	// image is marked as both executable (IMAGE_FILE_EXECUTABLE_IMAGE) and
	// a DLL (IMAGE_FILE_DLL).
	//
	// PDOS_HEADER pDosHeader: A pPointer to the DOS header to analyze
	// Returns: TRUE if pDosHeader is a DLL
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	WORD wCharacteristics = 0;

	pImgNtHeaders = ImageNTHeadersFromDOSHeader(pDosHeader);
	if (!pImgNtHeaders) {
		return FALSE;
	}

	wCharacteristics = pImgNtHeaders->FileHeader.Characteristics;
	wCharacteristics &= (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE);
	return wCharacteristics == (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE);
}

BOOL DOSHeaderIsEXE(PDOS_HEADER pDosHeader) {
	// Check the FileHeader Characteristics field to determine whether the PE
	// image is marked as both executable (IMAGE_FILE_EXECUTABLE_IMAGE) and
	// not a DLL (IMAGE_FILE_DLL).
	//
	// PDOS_HEADER pDosHeader: A pointer to the DOS header to analyze.
	// Returns: TRUE if pDosHeader is an EXE.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	WORD wCharacteristics = 0;

	pImgNtHeaders = ImageNTHeadersFromDOSHeader(pDosHeader);
	if (!pImgNtHeaders) {
		return FALSE;
	}

	wCharacteristics = pImgNtHeaders->FileHeader.Characteristics;
	wCharacteristics &= (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE);
	return wCharacteristics == IMAGE_FILE_EXECUTABLE_IMAGE;
}

BOOL ReflectiveTransformerToDLL(PDOS_HEADER pDosHeader, DWORD dwAddressOfEntryPoint) {
	// Transform the PE image pDosHeader into a DLL. This updates the FileHeader
	// Characteristics field as necessary, updates the OptionalHeader ImageBase
	// to the default value for DLL files and sets a new entry point.
	//
	// PDOS_HEADER pDosHeader:      A pointer to the DOS header transform.
	// DWORD dwAddressOfEntryPoint: The RVA of the new entry point for the PE
	//                              image.
	// Returns: TRUE on success.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;

	pImgNtHeaders = ImageNTHeadersFromDOSHeader(pDosHeader);
	if (!pImgNtHeaders) {
		return FALSE;
	}

	if (RebaseImage(pDosHeader, (ULONG_PTR)(pImgNtHeaders->OptionalHeader.ImageBase), IMAGE_BASE_DLL)) {
		ShadowSectionUpdate(pDosHeader);
	}

	pImgNtHeaders->FileHeader.Characteristics |= IMAGE_FILE_DLL;
	pImgNtHeaders->FileHeader.Characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
	pImgNtHeaders->OptionalHeader.ImageBase = IMAGE_BASE_DLL;
	pImgNtHeaders->OptionalHeader.AddressOfEntryPoint = dwAddressOfEntryPoint;
	return TRUE;
}

BOOL ReflectiveTransformerToEXE(PDOS_HEADER pDosHeader, DWORD dwAddressOfEntryPoint) {
	// Transform the PE image pDosHeader into an EXE. This updates the FileHeader
	// Characteristics field as necessary, updates the OptionalHeader ImageBase
	// to the default value for EXE files and sets a new entry point.
	//
	// PDOS_HEADER pDosHeader:      A pointer to the DOS header transform.
	// DWORD dwAddressOfEntryPoint: The RVA of the new entry point for the PE
	//                              image.
	// Returns: TRUE on success.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;

	pImgNtHeaders = ImageNTHeadersFromDOSHeader(pDosHeader);
	if (!pImgNtHeaders) {
		return FALSE;
	}
	
	if (RebaseImage(pDosHeader, (ULONG_PTR)(pImgNtHeaders->OptionalHeader.ImageBase), IMAGE_BASE_EXE)) {
		ShadowSectionUpdate(pDosHeader);
	}

	pImgNtHeaders->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
	pImgNtHeaders->FileHeader.Characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
	pImgNtHeaders->OptionalHeader.ImageBase = IMAGE_BASE_EXE;
	pImgNtHeaders->OptionalHeader.AddressOfEntryPoint = dwAddressOfEntryPoint;
	return TRUE;
}

DWORD RVAFromExportName(PDOS_HEADER pDosHeader, LPCSTR lpProcName) {
	// Get the relative virtual address (RVA) of an exported function by it's
	// name from an unloaded PE image. The return value can then be used as the
	// dwAddressOfEntryPoint argument to the ReflectiveTransformerTo* set of
	// functions.
	//
	// PDOS_HEADER pDosHeader: A pointer to the DOS header of the PE image to
	//                         resolve the export from.
	// LPCSTR lpProcName:      A pointer to the name of the exported function to
	//                         resolve the RVA for.
	// Returns: The function returns a non-zero value on success.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY pImgExDir = NULL;
	PIMAGE_DATA_DIRECTORY pImgDataDir = NULL;
	PDWORD pdwExAddress = NULL;
	PDWORD pdwExName = NULL;
	LPCSTR lpExportName;
	DWORD dwCursor;

	pImgNtHeaders = ImageNTHeadersFromDOSHeader(pDosHeader);
	if (!pImgNtHeaders) {
		return 0;
	}

	pImgDataDir = (PIMAGE_DATA_DIRECTORY)&pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!pImgDataDir->Size) {
		return 0;
	}

	pImgExDir = (PIMAGE_EXPORT_DIRECTORY)PAFromRVA(pDosHeader, (ULONG_PTR)pImgDataDir->VirtualAddress);
	if (!pImgExDir) {
		return 0;
	}
	(ULONG_PTR)pImgExDir += (ULONG_PTR)pDosHeader;

	(ULONG_PTR)pdwExAddress = PAFromRVA(pDosHeader, pImgExDir->AddressOfFunctions);
	(ULONG_PTR)pdwExAddress += (ULONG_PTR)pDosHeader;

	(ULONG_PTR)pdwExName = PAFromRVA(pDosHeader, pImgExDir->AddressOfNames);
	(ULONG_PTR)pdwExName += (ULONG_PTR)pDosHeader;

	for (dwCursor = 0; dwCursor < pImgExDir->NumberOfFunctions; dwCursor++) {
		lpExportName = (LPSTR)PAFromRVA(pDosHeader, (ULONG_PTR)pdwExName[dwCursor]);
		if (!lpExportName) {
			continue;
		}
		lpExportName += (ULONG_PTR)pDosHeader;
		if (memcmp(lpProcName, lpExportName, strlen(lpProcName))) {
			continue;
		}
		return pdwExAddress[dwCursor];
	}
	return 0;
}
