#ifndef NTDLL_UNHOOK_H
#define NTDLL_UNHOOK_H

#include <windows.h>

BOOL ReadNtdllFromDisk(OUT PVOID* ppNtdllBuf);
PVOID FetchLocalNtdllBaseAddress();
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll);
void loadPE(PBYTE peBuffer, SIZE_T peSize);

#endif // NTDLL_UNHOOK_H
