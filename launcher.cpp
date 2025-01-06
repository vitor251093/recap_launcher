// DarksporeLauncher.cpp - C++ version of the DarksporeLauncher
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <memory>

bool OverwriteMemory(HANDLE hProcess, uintptr_t address, const std::vector<uint8_t>& buffer) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(address), buffer.size(), PAGE_READWRITE, &oldProtect)) {
        std::cerr << "OverwriteMemory ERROR: VirtualProtectEx failed with error " << GetLastError() << std::endl;
        return false;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), buffer.data(), buffer.size(), &bytesWritten) || bytesWritten != buffer.size()) {
        std::cerr << "OverwriteMemory ERROR: WriteProcessMemory failed with error " << GetLastError() << std::endl;
        return false;
    }

    if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(address), buffer.size(), oldProtect, &oldProtect)) {
        std::cerr << "OverwriteMemory ERROR: VirtualProtectEx restore failed with error " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

void OverwriteMemory(HANDLE hProcess, const std::string& ogValue, uintptr_t address, const std::vector<uint8_t>& buffer) {
    if (!OverwriteMemory(hProcess, address, buffer)) {
        std::cerr << "ERROR: Unable to overwrite " << ogValue << "!" << std::endl;
    }
}

std::vector<uint8_t> StringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string GetFileVersion(const std::string& filePath) {
    DWORD handle;
    DWORD size = GetFileVersionInfoSize(filePath.c_str(), &handle);
    if (size == 0) {
        std::cerr << "GetFileVersionInfoSize failed: " << GetLastError() << std::endl;
        return "";
    }

    std::vector<char> versionData(size);
    if (!GetFileVersionInfo(filePath.c_str(), handle, size, versionData.data())) {
        std::cerr << "GetFileVersionInfo failed: " << GetLastError() << std::endl;
        return "";
    }

    VS_FIXEDFILEINFO* fileInfo;
    UINT len;
    if (!VerQueryValue(versionData.data(), "\\", reinterpret_cast<LPVOID*>(&fileInfo), &len)) {
        std::cerr << "VerQueryValue failed: " << GetLastError() << std::endl;
        return "";
    }

    std::ostringstream versionStream;
    versionStream << HIWORD(fileInfo->dwFileVersionMS) << "."
                  << LOWORD(fileInfo->dwFileVersionMS) << "."
                  << HIWORD(fileInfo->dwFileVersionLS) << "."
                  << LOWORD(fileInfo->dwFileVersionLS);

    return versionStream.str();
}

void ShowHelp() {
    std::cout << "Usage: --domain=<domain> --exe=<path_to_exe>" << std::endl;
}

int main(int argc, char* argv[]) {
    std::string domain = "localhost";
    std::string exePath = "Darkspore.exe";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.find("--domain=") == 0) {
            domain = arg.substr(9);
        } else if (arg.find("--exe=") == 0) {
            exePath = arg.substr(6);
        } else if (arg == "--help") {
            ShowHelp();
            return 0;
        }
    }

    HANDLE eventHandle = CreateEvent(nullptr, FALSE, FALSE, "Global\\Darkspore L2G");
    if (!eventHandle) {
        std::cerr << "Failed to create event: " << GetLastError() << std::endl;
        return 1;
    }

    std::string version = GetFileVersion(exePath);
    if (version.empty()) {
        return 1;
    }

    std::cout << "Darkspore " << version << " has been detected!" << std::endl;

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    if (!CreateProcess(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to start process: " << GetLastError() << std::endl;
        return 1;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!processHandle) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return 1;
    }

    auto localhost = StringToBytes(domain + "\0");

    if (version == "5.3.0.103") {
        OverwriteMemory(processHandle, "http://config.darkspore.com/bootstrap/api?version=1", 0x401A00 + 0xBD6C5C, StringToBytes("http://" + domain + "/bootstrap/api?version=1&z=A"));
        OverwriteMemory(processHandle, "content.darkspore.com", 0x401A00 + 0xBD7C4C, localhost);
        OverwriteMemory(processHandle, "api.darkspore.com", 0x401A00 + 0xBD7C64, localhost);
        OverwriteMemory(processHandle, "gosredirector.ea.com", 0x401A00 + 0xCD173C, localhost);
        OverwriteMemory(processHandle, "gosredirector.scert.ea.com", 0x401A00 + 0xCD1754, localhost);
        OverwriteMemory(processHandle, "gosredirector.stest.ea.com", 0x401A00 + 0xCD1770, localhost);
        OverwriteMemory(processHandle, "gosredirector.online.ea.com", 0x401A00 + 0xCD178C, localhost);

        OverwriteMemory(processHandle, "redirector secure bool param", 0x400C00 + 0xA46B1D, { 0x01 });
    }

    if (version == "5.3.0.127") {
        OverwriteMemory(processHandle, "http://config.darkspore.com/bootstrap/api?version=1", 0x401200 + 0xBD9A9C, StringToBytes("http://" + domain + "/bootstrap/api?version=1&z=A"));
        OverwriteMemory(processHandle, "content.darkspore.com", 0x401200 + 0xBDA678, localhost);
        OverwriteMemory(processHandle, "api.darkspore.com", 0x401200 + 0xBDA690, localhost);
        OverwriteMemory(processHandle, "gosredirector.ea.com", 0x401200 + 0xCD887C, localhost);
        OverwriteMemory(processHandle, "gosredirector.scert.ea.com", 0x401200 + 0xCD8894, localhost);
        OverwriteMemory(processHandle, "gosredirector.stest.ea.com", 0x401200 + 0xCD88B0, localhost);
        OverwriteMemory(processHandle, "gosredirector.online.ea.com", 0x401200 + 0xCD88CC, localhost);

        OverwriteMemory(processHandle, "redirector secure bool param", 0x400C00 + 0xA4CF9D, { 0x01 });
    }

    CloseHandle(processHandle);
    CloseHandle(eventHandle);

    return 0;
}
