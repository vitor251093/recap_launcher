#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <detours.h>
#include <stdio.h>
#include <strsafe.h>

static const char* szDll = "RecapHooks.dll";
static const char* szExeDefault = "Darkspore.exe";

void PrintUsage()
{
    printf("Usage: RecapLauncher.exe [--help] [--exe <path_to_exe>]\n\n");
    printf("Options:\n");
    printf("--exe  Path to the Darkspore executable file (default: Darkspore.exe)\n");
}

int CDECL main(int argc, char** argv)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CHAR szFullExe[1024] = "\0";
    PCHAR pszFileExe = NULL;
    const char* szExe = szExeDefault;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    for (int i = 1; i < argc; ++i)
    {
        if ((_stricmp(argv[i], "--exe") == 0) && (++i < argc))
        {
            szExe = argv[i];
        }
        else if (_stricmp(argv[i], "--help") == 0)
        {
            PrintUsage();
            return 0;
        }
        else
        {
            PrintUsage();
            return -1;
        }
    }

    SetLastError(0);
    SearchPathA(NULL, szExe, NULL, ARRAYSIZE(szFullExe), szFullExe, &pszFileExe);
    if (szFullExe[0] == '\0')
    {
        printf("Darkspore.exe not found.");
        return -2;
    }

    DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;
    if (!DetourCreateProcessWithDllEx(szFullExe, NULL, NULL, NULL, TRUE, dwFlags, NULL, NULL, &si, &pi, szDll, NULL))
    {
        DWORD dwError = GetLastError();
        printf("DetourCreateProcessWithDllEx failed: %ld\n", dwError);
        ExitProcess(9009);
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD dwResult = 0;
    if (!GetExitCodeProcess(pi.hProcess, &dwResult))
    {
        printf("GetExitCodeProcess failed: %ld\n", GetLastError());
        return 9010;
    }

    return dwResult;
}
