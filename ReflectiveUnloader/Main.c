#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include "ReflectiveDLLInjection.h"
#include "ReflectiveUnloader.h"

HMODULE g_hModule = NULL;

VOID DumpImage(LPTSTR pFile, PVOID pBaseAddress, SIZE_T dwSize) {
	HANDLE hFile;
	DWORD dwNumberOfBytesWritten;

	hFile = CreateFile(pFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, _T("Could not open the file for writing."), _T("Failed"), MB_OK);
		return;
	}
	WriteFile(hFile, pBaseAddress, (DWORD)dwSize, &dwNumberOfBytesWritten, NULL);
	CloseHandle(hFile);
}

VOID ProofOfConcept(HINSTANCE hInstance) {
	PVOID pBaseAddress = NULL;
	SIZE_T dwSize;
	TCHAR ctPath[MAX_PATH + 1];
	DWORD dwChars;

	MessageBox(NULL, _T("Select OK to proceed."), _T("Waiting"), MB_OK);

	pBaseAddress = ReflectiveUnloader(hInstance, &dwSize);
	if (!pBaseAddress) {
		MessageBox(NULL, _T("Unload failed."), _T("Failed"), MB_OK);
		return;
	}

	dwChars = ExpandEnvironmentStrings(_T("%USERPROFILE%\\Desktop\\unloaded.dll"), ctPath, MAX_PATH + 1);
	if ((dwChars == 0) || (dwChars > MAX_PATH + 1)) {
		MessageBox(NULL, _T("Could not get the file path for writing."), _T("Failed"), MB_OK);
		return;
	}
	DumpImage(ctPath, pBaseAddress, dwSize);
	ReflectiveUnloaderFree(pBaseAddress, dwSize);
}

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_QUERY_HMODULE:
		if (lpReserved) {
			*(HMODULE *)lpReserved = g_hModule;
		}
		break;
	case DLL_PROCESS_ATTACH:
		if (!g_hModule) {
			g_hModule = hInstDll;
			/* start a new thread so DllMain returns */
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProofOfConcept, hInstDll, 0, 0);
		}
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	default:
		break;
	}
	return TRUE;
}