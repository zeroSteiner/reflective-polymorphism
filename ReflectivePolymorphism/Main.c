#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

#include "ReflectiveDLLInjection.h"
#include "ReflectiveTransformer.h"
#include "ReflectiveUnloader.h"

// https://support.microsoft.com/en-us/help/94248/how-to-use-the-c-run-time
BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID);
HMODULE g_hModule = NULL;

static VOID DumpPEImage(LPTSTR pFile, PVOID pBaseAddress, SIZE_T dwSize) {
	HANDLE hFile;
	DWORD dwNumberOfBytesWritten;

	hFile = CreateFile(pFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// MessageBox(NULL, _T("Could not open the file for writing."), _T("Failed"), MB_OK);
		return;
	}
	WriteFile(hFile, pBaseAddress, (DWORD)dwSize, &dwNumberOfBytesWritten, NULL);
	CloseHandle(hFile);
}

static VOID DumpDLLImage(PDOS_HEADER pDosHeader, SIZE_T dwSize) {
	DWORD dwChars;
	DWORD dwEntryRVA;
	TCHAR ctDllPath[MAX_PATH + 1];
	
	ZeroMemory(ctDllPath, sizeof(ctDllPath));
	#ifdef _WIN64
		dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectivePolymorphism.x64.dll"), ctDllPath, MAX_PATH + 1);
	#else
	#ifdef _WIN32
		dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectivePolymorphism.x86.dll"), ctDllPath, MAX_PATH + 1);
	#endif
	#endif
	if ((dwChars == 0) || (dwChars > MAX_PATH + 1)) {
		MessageBox(NULL, _T("Could not get the file path for writing."), _T("Failed"), MB_OK);
		return;
	}

	dwEntryRVA = RVAFromExportName(pDosHeader, "DllMain");
	if (!dwEntryRVA) {
		MessageBox(NULL, _T("Failed to find the rva of the DllMain export."), _T("Failed"), MB_OK);
		return;
	}
	if (!ReflectiveTransformerToDLL(pDosHeader, dwEntryRVA)) {
		MessageBox(NULL, _T("Failed to transform the file."), _T("Failed"), MB_OK);
		return;
	}
	DumpPEImage(ctDllPath, pDosHeader, dwSize);
}

static VOID DumpEXEImage(PDOS_HEADER pDosHeader, SIZE_T dwSize) {
	DWORD dwChars;
	DWORD dwEntryRVA;
	TCHAR ctExePath[MAX_PATH + 1];

	ZeroMemory(ctExePath, sizeof(ctExePath));
#ifdef _WIN64
	dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectivePolymorphism.x64.exe"), ctExePath, MAX_PATH + 1);
#else
#ifdef _WIN32
	dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\ReflectivePolymorphism.x86.exe"), ctExePath, MAX_PATH + 1);
#endif
#endif
	if ((dwChars == 0) || (dwChars > MAX_PATH + 1)) {
		MessageBox(NULL, _T("Could not get the file path for writing."), _T("Failed"), MB_OK);
		return;
	}

	dwEntryRVA = RVAFromExportName(pDosHeader, "ExeMain");
	if (!dwEntryRVA) {
		MessageBox(NULL, _T("Failed to find the rva of the ExeMain export."), _T("Failed"), MB_OK);
		return;
	}
	if (!ReflectiveTransformerToEXE(pDosHeader, dwEntryRVA)) {
		MessageBox(NULL, _T("Failed to transform the file."), _T("Failed"), MB_OK);
		return;
	}
	DumpPEImage(ctExePath, pDosHeader, dwSize);
}

static VOID ProofOfConcept(HINSTANCE hInstance) {
	PDOS_HEADER pDosHeader = NULL;
	SIZE_T dwSize;
	
	MessageBox(NULL, _T("Select OK to proceed."), _T("Waiting"), MB_OK);

	pDosHeader = ReflectiveUnloader(hInstance, &dwSize);
	if (!pDosHeader) {
		MessageBox(NULL, _T("Unload failed."), _T("Failed"), MB_OK);
		return;
	}
	
	DumpDLLImage(pDosHeader, dwSize);
	DumpEXEImage(pDosHeader, dwSize);

	ReflectiveUnloaderFree(pDosHeader, dwSize);
}

__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_QUERY_HMODULE) {
		if (lpReserved) {
			*(HMODULE *)lpReserved = g_hModule;
		}
	}
	else {
		if (!_CRT_INIT(hInstDll, dwReason, lpReserved)) {
			return FALSE;
		}
		if ((dwReason == DLL_PROCESS_ATTACH) && (!g_hModule)) {
			g_hModule = hInstDll;
			// start a new thread so DllMain returns
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProofOfConcept, hInstDll, 0, 0);
		}
	}
	return TRUE;
}

__declspec(dllexport) int WINAPI ExeMain(int argc, char **argv) {
	ProofOfConcept(GetModuleHandle(NULL));
	return 0;
}
