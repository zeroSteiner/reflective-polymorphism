#include "ReflectiveTransformer.h"
#include <stdio.h>
#include <tchar.h>

// https://support.microsoft.com/en-us/help/94248/how-to-use-the-c-run-time
BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

static BOOL DumpImage(LPCTSTR pFile, PVOID pBaseAddress, SIZE_T dwSize) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwNumberOfBytesWritten = 0;

	hFile = CreateFile(pFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	WriteFile(hFile, pBaseAddress, (DWORD)dwSize, &dwNumberOfBytesWritten, NULL);
	CloseHandle(hFile);
	return TRUE;
}

void Main(HMODULE hModule) {
	PDOS_HEADER pDosHeader = NULL;
	DWORD dwEntryRVA;
	BOOL bResult = FALSE;
	SIZE_T dwSize;
	TCHAR ctPath[MAX_PATH + 1];
	DWORD dwChars;

	pDosHeader = ReflectiveUnloader(hModule, &dwSize);
	if (!pDosHeader) {
		return;
	}
	if (DOSHeaderIsDLL(pDosHeader)) {
		dwEntryRVA = RVAFromExportName(pDosHeader, "ExeMain");
		if (!dwEntryRVA) {
			//_tprintf(_T("failed to find the rva of the ExeMain export\n"));
			return;
		}
		bResult = ReflectiveTransformerToEXE(pDosHeader, dwEntryRVA);
#ifdef _WIN64
		dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectiveTransformer.x64.exe"), ctPath, MAX_PATH + 1);
#else
#ifdef _WIN32
		dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectiveTransformer.x86.exe"), ctPath, MAX_PATH + 1);
#endif
#endif
	}
	else if (DOSHeaderIsEXE(pDosHeader)) {
		dwEntryRVA = RVAFromExportName(pDosHeader, "DllMain");
		if (!dwEntryRVA) {
			//_tprintf(_T("failed to find the rva of the DllMain export\n"));
			return;
		}
		bResult = ReflectiveTransformerToDLL(pDosHeader, dwEntryRVA);
#ifdef _WIN64
		dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectiveTransformer.x64.dll"), ctPath, MAX_PATH + 1);
#else
#ifdef _WIN32
		dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectiveTransformer.x86.dll"), ctPath, MAX_PATH + 1);
#endif
#endif
	}
	else {
		//_tprintf(_T("failed to identify pe image type as dll or exe\n"));
		return;
	}

	if ((dwChars == 0) || (dwChars > MAX_PATH + 1)) {
		//_tprintf(_T("could not get the file path for writing\n"));
		return;
	}

	if (bResult) {
		DumpImage(ctPath, pDosHeader, dwSize);
		ReflectiveUnloaderFree(pDosHeader, dwSize);
	}
}

// https://docs.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (!_CRT_INIT(hinstDLL, fdwReason, lpReserved)) {
		return(FALSE);
	}
	if (fdwReason == DLL_PROCESS_ATTACH) {
		Main(hinstDLL);
	}
	return TRUE;
}

__declspec(dllexport) int WINAPI ExeMain(int argc, char **argv) {
	Main(GetModuleHandle(NULL));
	return 0;
}
