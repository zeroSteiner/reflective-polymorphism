// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met :
// 
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of the project nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Author:  Spencer McIntyre (@zeroSteiner) 2018
// Version: 1.1
#ifndef _REFLECTIVE_UNLOADER_H
#define _REFLECTIVE_UNLOADER_H

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

// See: https://msdn.microsoft.com/en-us/library/f7f5138s.aspx
#ifdef _WIN64
#define IMAGE_BASE_DLL 0x180000000
#define IMAGE_BASE_EXE 0x140000000
#else
#define IMAGE_BASE_DLL 0x10000000
#define IMAGE_BASE_EXE 0x400000
#endif

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

// API functions
__declspec(dllexport) PVOID ReflectiveUnloader(HINSTANCE hInstance, PSIZE_T pdwSize);
__declspec(dllexport) VOID ReflectiveUnloaderFree(PVOID pAddress, SIZE_T dwSize);

__declspec(dllexport) PIMAGE_SECTION_HEADER SectionHeaderFromName(PDOS_HEADER pDosHeader, PVOID pName);
__declspec(dllexport) PIMAGE_SECTION_HEADER SectionHeaderFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pAddress);

#endif