#include <stdio.h>
#include "ReflectiveUnloader.h"

VOID DumpImage(LPCSTR pFile, PVOID pBaseAddress, SIZE_T dwSize) {
	HANDLE hFile;

	hFile = CreateFile(pFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, pBaseAddress, (DWORD)dwSize, NULL, NULL);
	CloseHandle(hFile);
}

VOID ProofOfConcept(HINSTANCE hInstance) {
	PVOID pBaseAddress = NULL;
	SIZE_T dwSize;

	pBaseAddress = ReflectiveUnloader(hInstance, &dwSize);
	if (pBaseAddress) {
		printf("Unload successful!\n");
	}
	else {
		printf("Unload failed!\n");
	}

	DumpImage("unloaded.exe", pBaseAddress, dwSize);
	ReflectiveUnloaderFree(pBaseAddress, dwSize);
}

int main(int argc, char **argv) {
	HINSTANCE hInstance;

	hInstance = GetModuleHandle(NULL);
	ProofOfConcept(hInstance);
	return 0;
}
