#include "Version.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <detours.h>
#include <stdio.h>
#include <strsafe.h>

#include <filesystem>
#include <string>
#include <vector>

static const char* szDll = "RecapHooks.dll";
static const char* szGameExeDefault = "Darkspore.exe";
static const char* szServerExeDefault = "Server/recap_server.exe";

void PrintUsage()
{
    printf("Usage: RecapLauncher.exe [--help] [--exe <path_to_exe>]\n\n");
    printf("Options:\n");
    printf("--game-exe    Path to the Darkspore executable file (default: Darkspore.exe)\n");
    printf("--server-exe  Path to the ReCap server executable file (default: recap_server.exe)\n");
    printf("--no-server   Disable launching the server before the game (default: ON)\n");
}

bool RunExeInNewCmdWindow(const char* exePath) {
    std::string exeName = std::filesystem::path(exePath).filename().string();
    std::string command = "cmd.exe /C start \"\" \"" + exeName + "\"";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    char cmdLine[1024];
    strncpy_s(cmdLine, command.c_str(), sizeof(cmdLine) - 1);

    std::string parentDir = std::filesystem::path(exePath).parent_path().string();

    BOOL success = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        parentDir.empty() ? NULL : parentDir.c_str(),
        &si,
        &pi
    );

    if (!success) {
        printf("Failed to launch process. Error: %d\n", GetLastError());
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

int CDECL main(int argc, char** argv)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CHAR szFullExe[1024] = "\0";
    PCHAR pszFileExe = NULL;
    const char* szGameExe = szGameExeDefault;
    const char* szServerExe = szServerExeDefault;
    bool runServer = true;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    for (int i = 1; i < argc; ++i)
    {
        if ((_stricmp(argv[i], "--game-exe") == 0) && (++i < argc))
        {
            szGameExe = argv[i];
        }
        else if ((_stricmp(argv[i], "--server-exe") == 0) && (++i < argc))
        {
            szServerExe = argv[i];
        }
        else if ((_stricmp(argv[i], "--no-server") == 0))
        {
            runServer = false;
        }
        else if ((_stricmp(argv[i], "--version") == 0))
        {
            printf(RECAP_VERSION_STRING);
            return 0;
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
    SearchPathA(NULL, szGameExe, NULL, ARRAYSIZE(szFullExe), szFullExe, &pszFileExe);
    if (szFullExe[0] == '\0')
    {
        printf("Darkspore.exe not found.\n");
        return -2;
    }

    if (runServer)
    {
        // Launch server, if possible
        RunExeInNewCmdWindow(szServerExe);
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
