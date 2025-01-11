#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <Sig/Sig.hpp>
#include <detours.h>
#include <psapi.h>
#include <strsafe.h>
#define TOML_EXCEPTIONS 0
#include <toml++/toml.hpp>
#include <winsock2.h>

#define MAX_PRINT_BUFFER_SIZE 1024

// OpenSSL typedefs
#define X509_V_OK 0
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX* x509_ctx);

// ProtoSSL typedefs
struct X509CertificateT;

// WinSock2 typedefs
typedef hostent*(WSAAPI* gethostbyname_t)(const char* name);
typedef int(WSAAPI* connect_t)(SOCKET s, const sockaddr* name, int namelen);

// Targets
static gethostbyname_t orig_gethostbyname = gethostbyname;
static gethostbyname_t detoured_gethostbyname = NULL;
static connect_t orig_connect = connect;

// Signature-based targets
struct Target
{
    const char* signature;
    const void* original;
    void* detoured;
};

// Configuration
static const char* const configfile = "RecapHooks.toml";
static const char* const localhost = "localhost";
static const uint16_t http = 80;

static std::string hostname;
static uint16_t port;
static std::vector<std::string> inclist;
static std::vector<std::string> exclist;

template <typename... Args>
void dbgprintf(const char* data, Args... args)
{
#ifdef _DEBUG
    static char buff[MAX_PRINT_BUFFER_SIZE] = "\0";
    const HRESULT hr = StringCbPrintf(buff, ARRAYSIZE(buff), data, args...);
    if (SUCCEEDED(hr))
    {
        OutputDebugStringA(buff);
    }
#endif  // _DEBUG
}

void detoured_SSL_CTX_set_verify(SSL_CTX* ctx, int mode, SSL_verify_cb callback)
{
    dbgprintf("SSL_CTX_set_verify");
    return;
}

long detoured_SSL_get_verify_result(const SSL* ssl)
{
    dbgprintf("SSL_get_verify_result");
    return X509_V_OK;
}

int detoured__WildcardMatchNoCase(const char* pString1, const char* pString2)
{
    dbgprintf("_WildcardMatchNoCase");
    return 0;
}

int detoured__VerifyCertificate(X509CertificateT* pCert, int iSelfSigned)
{
    dbgprintf("_VerifyCertificate");
    return 0;
}

hostent* WSAAPI detoured_gethostbyname_impl(const char* name)
{
    static thread_local hostent host;
    static thread_local in_addr addr;
    static thread_local void* addr_list[2] = {};

    dbgprintf("gethostbyname: %s", name);

    if (addr_list[0] == NULL)
    {
        // Executed only first time
        hostent* resolved = orig_gethostbyname(hostname.c_str());
        if (resolved->h_addr_list[0] != NULL)
        {
            addr.s_addr = *(u_long*)resolved->h_addr_list[0];
            addr_list[0] = &addr;
        }
        host.h_name = NULL;
        host.h_aliases = NULL;
        host.h_addrtype = AF_INET;
        host.h_length = 4;
        host.h_addr_list = reinterpret_cast<char**>(&addr_list);
    }
    return &host;
}

hostent* WSAAPI detoured_gethostbyname_inclist(const char* name)
{
    dbgprintf("inclist: %s", name);

    if (std::find(inclist.begin(), inclist.end(), name) == inclist.end())
    {
        return orig_gethostbyname(name);
    }

    return detoured_gethostbyname_impl(name);
}

hostent* WSAAPI detoured_gethostbyname_exclist(const char* name)
{
    dbgprintf("exclist: %s", name);

    if (std::find(exclist.begin(), exclist.end(), name) != exclist.end())
    {
        return orig_gethostbyname(name);
    }

    return detoured_gethostbyname_impl(name);
}

int WSAAPI detoured_connect(SOCKET s, const sockaddr* name, int namelen)
{
    auto service = reinterpret_cast<sockaddr_in*>(const_cast<sockaddr*>(name));
    dbgprintf("connect: %hu", ntohs(service->sin_port));
    if (service->sin_port == htons(http))
    {
        service->sin_port = htons(port);
    }
    return orig_connect(s, name, namelen);
}

static Target targets[] = {
    {"8B 44 24 04 8B 4C 24 08 8B 54 24 0C 89 88", NULL, reinterpret_cast<void*>(detoured_SSL_CTX_set_verify)},
    {"8B 44 24 04 8B 80 E0 00 00 00 C3", NULL, reinterpret_cast<void*>(detoured_SSL_get_verify_result)},
    {"53 56 8B 74 24 10 57 8B 7C 24 10 EB 03", NULL, reinterpret_cast<void*>(detoured__WildcardMatchNoCase)},
    {"83 7C 24 04 00 56 57 8B F0", NULL, reinterpret_cast<void*>(detoured__VerifyCertificate)},
};

const void* FindSigInModule(HMODULE mod, const char* sig)
{
    MODULEINFO modinfo = {};
    GetModuleInformation(GetCurrentProcess(), mod, &modinfo, sizeof(MODULEINFO));
    const void* ptr = Sig::find(modinfo.lpBaseOfDll, modinfo.SizeOfImage, sig);
    if (ptr == nullptr)
    {
        dbgprintf("Signature not found: %s", sig);
    }
    return ptr;
}

void LoadHostRules(const toml::parse_result& config, const char* key, std::vector<std::string>& dest)
{
    auto hostnames = config["host"]["resolver"][key];
    if (const toml::array* arr = hostnames.as_array())
    {
        dest.resize(arr->size());
        for (const auto& host : *arr)
        {
            if (host.is_string())
            {
                dest.push_back(*host.value<std::string>());
            }
        }
    }
}

void LoadConfig()
{
    hostname = localhost;
    port = http;
    detoured_gethostbyname = detoured_gethostbyname_impl;

    auto config = toml::parse_file(configfile);
    if (!config)
    {
        dbgprintf("Config parsing failed: %s", config.error().description().data());
        return;
    }

    hostname = config["host"]["name"].value_or(localhost);
    port = config["host"]["port"].value_or(http);
    // Whitelist
    LoadHostRules(config, "include", inclist);
    if (!inclist.empty())
    {
        detoured_gethostbyname = detoured_gethostbyname_inclist;
        // Blacklist is ignored if whitelist is present
        return;
    }

    // Blacklist
    LoadHostRules(config, "exclude", exclist);
    if (!exclist.empty())
    {
        detoured_gethostbyname = detoured_gethostbyname_exclist;
    }
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hInst;
    (void)reserved;

    if (DetourIsHelperProcess())
    {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DetourRestoreAfterWith();
        dbgprintf("Begin detouring.");

        LoadConfig();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)orig_gethostbyname, detoured_gethostbyname);
        if (port != http)
        {
            DetourAttach(&(PVOID&)orig_connect, detoured_connect);
        }
        for (auto& target : targets)
        {
            target.original = FindSigInModule(GetModuleHandle(NULL), target.signature);
            DetourAttach(&(PVOID&)target.original, target.detoured);
        }
        error = DetourTransactionCommit();
        if (error == NO_ERROR)
        {
            dbgprintf("Detour successful.");
        }
        else
        {
            dbgprintf("Error detouring functions: %ld", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        dbgprintf("Begin removal of detours.");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)orig_gethostbyname, detoured_gethostbyname);
        if (port != http)
        {
            DetourDetach(&(PVOID&)orig_connect, detoured_connect);
        }
        for (auto& target : targets)
        {
            DetourDetach(&(PVOID&)target.original, target.detoured);
        }
        error = DetourTransactionCommit();
        dbgprintf("Removed detours (result=%ld).", error);
    }

    return TRUE;
}
