#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <detours.h>
#include <stdio.h>
#include <strsafe.h>

static const char* szDll = "RecapHooks.dll";
static const char* szExeDefault = "Darkspore.exe";
static const char* szServerExeDefault = "Server/recap_server.exe";

void PrintUsage()
{
    printf("Usage: RecapLauncher.exe [--help] [--exe <path_to_exe>]\n\n");
    printf("Options:\n");
    printf("--exe  Path to the Darkspore executable file (default: Darkspore.exe)\n");
}

bool runExeInNewCmdWindow(const char* exePath) {
    std::string command = "cmd.exe /C start \"\" \"" + std::string(exePath) + "\"";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    BOOL success = CreateProcessA(
        NULL,
        (LPSTR)command.c_str(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    } else {
        std::cerr << "Failed to launch process. Error: " << GetLastError() << std::endl;
        return false;
    }
}

int CDECL main(int argc, char** argv)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CHAR szFullExe[1024] = "\0";
    PCHAR pszFileExe = NULL;
    const char* szExe = szExeDefault;
    const char* szServerExe = szServerExeDefault;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    for (int i = 1; i < argc; ++i)
    {
        if ((_stricmp(argv[i], "--exe") == 0) && (++i < argc))
        {
            szExe = argv[i];
        }
        else if ((_stricmp(argv[i], "--server") == 0) && (++i < argc))
        {
            szServerExe = argv[i];
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
        printf("Darkspore.exe not found.\n");
        return -2;
    }

    // Launch server, if possible
    runExeInNewCmdWindow(szServerExe);

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
