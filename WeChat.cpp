
#include "pch.h"
#include "WeChat.h"

ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");
NTQUERYOBJECT NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

int GetWeChatPath(WCHAR* Path)
{
    int ret = -1;

    if (Path == NULL)
        return ret;

    //HKEY_CURRENT_USER\Software\Tencent\WeChat InstallPath = xx
    HKEY hKey = NULL;
    if (ERROR_SUCCESS != RegOpenKey(HKEY_CURRENT_USER, L"Software\\Tencent\\WeChat", &hKey)) {
        ret = GetLastError();
        return ret;
    }

    DWORD Type = REG_SZ;
    // WCHAR Path[MAX_PATH] = { 0 };
    DWORD cbData = MAX_PATH * sizeof(WCHAR);
    if (ERROR_SUCCESS != RegQueryValueEx(hKey, L"InstallPath", 0, &Type, (LPBYTE)Path, &cbData)) {
        ret = GetLastError();
        if (hKey) {
            RegCloseKey(hKey);
        }

        return ret;
    }

    PathAppend(Path, L"WeChat.exe");

    return ERROR_SUCCESS;
}

int GetWeChatWinPath(WCHAR* Path)
{
    int ret = GetWeChatPath(Path);
    if (ret != ERROR_SUCCESS) {
        return ret;
    }

    PathRemoveFileSpecW(Path);
    PathAppendW(Path, L"WeChatWin.dll");

    return ret;
}

bool GetFileVersion(LPTSTR lpszFilePath, LPTSTR version)
{

    if (_tcslen(lpszFilePath) > 0 && PathFileExists(lpszFilePath))
    {
        VS_FIXEDFILEINFO* pVerInfo = NULL;
        DWORD dwTemp, dwSize;
        BYTE* pData = NULL;
        UINT uLen;

        dwSize = GetFileVersionInfoSize(lpszFilePath, &dwTemp);
        if (dwSize == 0)
        {
            return false;
        }

        pData = new BYTE[dwSize + 1];
        if (pData == NULL)
        {
            return false;
        }

        if (!GetFileVersionInfo(lpszFilePath, 0, dwSize, pData))
        {
            delete[] pData;
            return false;
        }

        if (!VerQueryValue(pData, TEXT("\\"), (void**)&pVerInfo, &uLen))
        {
            delete[] pData;
            return false;
        }

        DWORD verMS = pVerInfo->dwFileVersionMS;
        DWORD verLS = pVerInfo->dwFileVersionLS;
        DWORD major = HIWORD(verMS);
        DWORD minor = LOWORD(verMS);
        DWORD build = HIWORD(verLS);
        DWORD revision = LOWORD(verLS);
        delete[] pData;

        StringCbPrintf(version, 0x20, TEXT("%d.%d.%d.%d"), major, minor, build, revision);

        return true;
    }

    return false;
}

int GetWeChatVersion(WCHAR* version)
{
    WCHAR Path[MAX_PATH] = { 0 };

    int ret = GetWeChatWinPath(Path);
    if (ret != ERROR_SUCCESS) {
        return ret;
    }

    ret = GetFileVersion(Path, version);

    return ret;
}

//进程提权
BOOL ElevatePrivileges()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    tkp.PrivilegeCount = 1;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
        return FALSE;

    return TRUE;
}

int GetProcIds(LPCWSTR Name, DWORD* Pids)
{
    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    int num = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap) {
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(Name, pe32.szExeFile)) {
                    if (Pids) {
                        Pids[num++] = pe32.th32ProcessID;
                    }
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }

    return num;
}

BOOL IsTargetPid(DWORD Pid, DWORD* Pids, int num)
{
    for (int i = 0; i < num; i++) {
        if (Pid == Pids[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

HANDLE DuplicateHandleEx(DWORD pid, HANDLE h, DWORD flags)
{
    HANDLE hHandle = NULL;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc) {
        if (!DuplicateHandle(hProc, (HANDLE)h, GetCurrentProcess(), &hHandle, 0, FALSE, /*DUPLICATE_SAME_ACCESS*/ flags)) {
            hHandle = NULL;
        }

        CloseHandle(hProc);
    }

    return hHandle;
}

int PatchWeChat()
{
    DWORD dwSize = 0x1000;
    DWORD dwRequiredSize = 0;
    POBJECT_NAME_INFORMATION pNameInfo;
    POBJECT_NAME_INFORMATION pNameType;
    PVOID pbuffer = NULL;
    NTSTATUS Status;
    ULONG nIndex = 0;
    DWORD dwFlags = 0;
    char szType[128] = { 0 };
    char szName[512] = { 0 };
    PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
    DWORD Pids[100] = { 0 };
    int ret = -1;

    //ElevatePrivileges();

    DWORD Num = GetProcIds(L"WeChat.exe", Pids);
    if (Num == 0) {
        return ret;
    }

    if (!ZwQuerySystemInformation) {
        return ret;
    }

    // Allocate enough memory and get system handlers info
    do {
        pbuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
        if (!pbuffer) {
            printf("Alloc Memory for System Handler Info failed!\n");
            ret = GetLastError();
            return ret;
        }

        Status = ZwQuerySystemInformation(SystemHandleInformation, pbuffer, dwSize, &dwRequiredSize);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_INFO_LENGTH_MISMATCH) {
                if (pbuffer) {
                    VirtualFree(pbuffer, 0, MEM_RELEASE);
                    pbuffer = NULL;
                }
                dwSize += dwRequiredSize;
            } else {
                printf("Get System Hanlder Info failed : 0x%X\n", Status);
                
                if (pbuffer != NULL) {
                    VirtualFree(pbuffer, 0, MEM_RELEASE);
                }
                return ret;
            }
        }
    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pbuffer;
    for (nIndex = 0; nIndex < pHandleInfo->NumberOfHandles; nIndex++) {
        if (IsTargetPid(pHandleInfo->Handles[nIndex].UniqueProcessId, Pids, Num)) {
            HANDLE hHandle = DuplicateHandleEx(pHandleInfo->Handles[nIndex].UniqueProcessId, (HANDLE)pHandleInfo->Handles[nIndex].HandleValue, DUPLICATE_SAME_ACCESS);
            if (hHandle == NULL)
                continue;

            Status = NtQueryObject(hHandle, ObjectNameInformation, szName, 512, &dwFlags);
            if (!NT_SUCCESS(Status)) {
                CloseHandle(hHandle);
                continue;
            }

            Status = NtQueryObject(hHandle, ObjectTypeInformation, szType, 128, &dwFlags);
            if (!NT_SUCCESS(Status)) {
                CloseHandle(hHandle);
                continue;
            }

            pNameInfo = (POBJECT_NAME_INFORMATION)szName;
            pNameType = (POBJECT_NAME_INFORMATION)szType;

            WCHAR TypeName[1024] = { 0 };
            WCHAR Name[1024] = { 0 };

            wcsncpy_s(TypeName, (WCHAR*)pNameType->Name.Buffer, pNameType->Name.Length / 2);
            wcsncpy_s(Name, (WCHAR*)pNameInfo->Name.Buffer, pNameInfo->Name.Length / 2);

            // 匹配是否为需要关闭的句柄名称
            if (0 == wcscmp(TypeName, L"Mutant")) {
                if (wcsstr(Name, L"_WeChat_") && wcsstr(Name, L"_Instance_Identity_Mutex_Name")) {
                    CloseHandle(hHandle);

                    hHandle = DuplicateHandleEx(pHandleInfo->Handles[nIndex].UniqueProcessId, (HANDLE)pHandleInfo->Handles[nIndex].HandleValue, DUPLICATE_CLOSE_SOURCE);
                    if (hHandle) {
                        ret = ERROR_SUCCESS;
                        CloseHandle(hHandle);
                    } else {
                        ret = GetLastError();
                    }
                }
            } else {
                CloseHandle(hHandle);
            }
        }
    }

//__error:
//    if (NULL != pbuffer) {
//        VirtualFree(pbuffer, 0, MEM_RELEASE);
//    }

    return ret;
}

int OpenWeChat(DWORD* pid)
{
    int ret = -1;
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    ret = PatchWeChat();
    /*if (ret != ERROR_SUCCESS) {
        return ret;
    }*/

    WCHAR Path[MAX_PATH] = { 0 };
    ret = GetWeChatPath(Path);
    if (ERROR_SUCCESS != ret) {
        return ret;
    }

    //ShellExecute(NULL, L"Open", Path, NULL, NULL, SW_SHOW);

    if (!CreateProcess(NULL, Path, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        ret = GetLastError();
        return ret;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    *pid = pi.dwProcessId;

    ret = ERROR_SUCCESS;

    return ret;
}
