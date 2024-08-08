#ifndef NTDLL_UNHOOK_H
#define NTDLL_UNHOOK_H

#include <windows.h>

BOOL ReadNtdllFromDisk(OUT PVOID* ppNtdllBuf);
PVOID FetchLocalNtdllBaseAddress();
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll);
void loadPE(LPCSTR pePath);

#endif // NTDLL_UNHOOK_H
