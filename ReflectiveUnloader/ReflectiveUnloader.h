#ifndef _REFLECTIVE_UNLOADER_H
#define _REFLECTIVE_UNLOADER_H

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef struct {
	// short is 2 bytes, long is 4 bytes
	WORD  signature;
	WORD  lastsize;
	WORD  nblocks;
	WORD  nreloc;
	WORD  hdrsize;
	WORD  minalloc;
	WORD  maxalloc;
	WORD  ss;
	WORD  sp;
	WORD  checksum;
	WORD  ip;
	WORD  cs;
	WORD  relocpos;
	WORD  noverlay;
	WORD  reserved1[4];
	WORD  oem_id;
	WORD  oem_info;
	WORD  reserved2[10];
	DWORD e_lfanew;
} DOS_HEADER, *PDOS_HEADER;

PVOID ReflectiveUnloader(HINSTANCE hInstance, PSIZE_T pdwSize);
VOID ReflectiveUnloaderFree(PVOID pAddress, SIZE_T dwSize);

#endif