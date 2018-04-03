#include <stdio.h>
#include "ReflectiveUnloader.h"

VOID DumpImage(LPCSTR pFile, PVOID pBaseAddress, SIZE_T dwSize) {
	HANDLE hFile;
	DWORD dwNumberOfBytesWritten;

	hFile = CreateFile(pFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open the file for writting.\n");
		return;
	}
	WriteFile(hFile, pBaseAddress, (DWORD)dwSize, &dwNumberOfBytesWritten, NULL);
	CloseHandle(hFile);
}

VOID ProofOfConcept(HINSTANCE hInstance) {
	PVOID pBaseAddress = NULL;
	SIZE_T dwSize;

	pBaseAddress = ReflectiveUnloader(hInstance, &dwSize);
	if (!pBaseAddress) {
		printf("[-] Unload failed.\n");
		return;
	}
	printf("[+] Unload succedded.\n");
	DumpImage("unloaded.exe", pBaseAddress, dwSize);
	ReflectiveUnloaderFree(pBaseAddress, dwSize);
}

int main(int argc, char **argv) {
	ProofOfConcept(GetModuleHandle(NULL));
	return 0;
}
