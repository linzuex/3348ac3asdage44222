#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winhttp.h>        // <-- added
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <cstring>
#include <map>
#include <thread>
#include <sstream>          // <-- added for parsing

#pragma comment(lib, "winhttp.lib")

// ------------------ Existing Function Declarations ------------------
extern "C" void dc_reject(const float* in, float* out, int* hp_mem, int len, int channels, int Fs);
extern "C" void hp_cutoff(const float* in, int cutoff_Hz, float* out, int* hp_mem, int len, int channels, int Fs, int arch);

// ------------------ Helpers ------------------
void ExternalWrite(HANDLE Process, void* Address, const char* source, uint32_t size)
{
    DWORD Old = 0;
    DWORD Junk = 0;
    // use size for VirtualProtectEx rather than hard-coded 0x1000
    VirtualProtectEx(Process, Address, size, PAGE_EXECUTE_READWRITE, &Old);
    if (!WriteProcessMemory(Process, Address, source, size, NULL))
    {
        std::cout << "Write failed! length: " << size << ", address: " << Address << ", code: " << GetLastError() << std::endl;
    }
    VirtualProtectEx(Process, Address, size, Old, &Junk);
}

void ExternalWrite(HANDLE Process, void* Address, uint8_t byte)
{
    DWORD Old = 0;
    DWORD Junk = 0;
    VirtualProtectEx(Process, Address, 1, PAGE_EXECUTE_READWRITE, &Old);
    if (!WriteProcessMemory(Process, Address, &byte, 1, NULL))
    {
        std::cout << "Write failed!" << std::endl;
    }
    VirtualProtectEx(Process, Address, 1, Old, &Junk);
}

// ------------------ Patch Addresses ------------------
uint32_t CreateAudioFrameStereoInstruction = 0xAD794;
uint32_t AudioEncoderOpusConfigSetChannelsInstruction = 0x302EA8;
uint32_t MonoDownmixerInstructions = 0x95B23;
uint32_t HighPassFilter_Process = 0x4A5022;
uint32_t EmulateStereoSuccess = 0x497504;
uint32_t EmulateBitrateModified = 0x497762;
uint32_t Emulate48Khz = 0x49761B;
uint32_t HighpassCutoffFilter = 0x8B4370;
uint32_t DcReject = 0x8B4550;
uint32_t downmix_func = 0x8B0BB0;
uint32_t AudioEncoderOpusConfig_IsOk = 0x30310C;
uint32_t AudioEncoderOpusImpl_EncodeImpl_Jump = 0x4998BA;
uint32_t AudioEncoderOpusImpl_EncodeImpl_Shellcode = 0x499A2F;

// ------------------ Registry HWID ------------------
std::string getHWID()
{
    HKEY hKey = NULL;
    LPCSTR subKey = "SOFTWARE\\Microsoft\\Cryptography";

    // Try standard view first, then explicitly try 64-bit view if needed
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) {
        res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (res != ERROR_SUCCESS) {
            return "";
        }
    }

    DWORD type = 0;
    DWORD bufSize = 0;

    // Query required buffer size
    res = RegQueryValueExA(hKey, "MachineGuid", nullptr, &type, nullptr, &bufSize);
    if (res != ERROR_SUCCESS || type != REG_SZ || bufSize == 0) {
        RegCloseKey(hKey);
        return "";
    }

    std::string result(bufSize, '\0');
    res = RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&result[0]), &bufSize);
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS)
        return "";

    // Trim null characters at the end
    size_t nullPos = result.find('\0');
    if (nullPos != std::string::npos)
        result.resize(nullPos);

    return result;
}

// ------------------ Simple WinHTTP fetch (raw text) ------------------
std::string FetchFromGitHubRaw(const std::wstring& host, const std::wstring& path)
{
    std::string result;
    HINTERNET hSession = WinHttpOpen(L"HWID Loader/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL))
    {
        DWORD dwSize = 0;
        do
        {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            // allocate writable buffer
            char* buffer = new char[dwSize];
            if (!buffer) break;

            if (!WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded))
            {
                delete[] buffer;
                break;
            }

            result.append(buffer, dwDownloaded);
            delete[] buffer;

        } while (dwSize > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

// ------------------ Load HWIDs from GitHub (simple TXT key=value) ------------------
std::map<std::string, std::string> LoadHWIDsFromGitHub()
{
    // Raw host and path - change path if your file location is different.
    const std::wstring GITHUB_HOST = L"raw.githubusercontent.com";
    // Example raw path: /<user>/<repo>/<branch>/hwid.txt
    const std::wstring GITHUB_PATH = L"/linzuex/3348ac3asdage44222/main/hwid.txt";

    std::string raw = FetchFromGitHubRaw(GITHUB_HOST, GITHUB_PATH);
    std::map<std::string, std::string> mapOut;
    if (raw.empty()) return mapOut;

    std::istringstream ss(raw);
    std::string line;
    while (std::getline(ss, line))
    {
        // Trim whitespace start/end
        if (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty() || line[0] == '#') continue; // support comments

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        // trim CR from val
        if (!val.empty() && val.back() == '\r') val.pop_back();

        // lower-case key for case-insensitive compare (optional)
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        mapOut[key] = val;
    }

    return mapOut;
}

// ------------------ Main ------------------
int main()
{
    // get HWID from registry
    std::string hwid = getHWID();
    if (hwid.empty()) {
        std::cerr << "Failed to retrieve HWID from registry.\n";
        return 1;
    }

    std::cout << "Retrieved HWID: " << hwid << "\n";

    // normalize hwid to lower-case for matching
    std::string hwid_lc = hwid;
    std::transform(hwid_lc.begin(), hwid_lc.end(), hwid_lc.begin(), ::tolower);

    // load HWIDs from GitHub
    auto HWID_MAP = LoadHWIDsFromGitHub();
    if (HWID_MAP.empty())
    {
        std::cerr << "Failed to load HWIDs from GitHub (or file empty). Falling back to local table.\n";

        // fallback to your hardcoded list if GitHub fetch fails
        HWID_MAP = {
            {"4f1e2b46-d12a-4552-9c9d-e85b90da929b", "wish"},
            {"83c22171-6293-435f-b585-a6a5fdf3ba8c", "pk"},
            {"419fd6a6-52ca-4a92-9d3a-cef7928e2c2e", "vek"},
            {"c0c08bbd-f8d9-4ce6-abed-f188e6ac7094", "jairo"},
            {"3348ac39-b0d7-41e8-b20b-6477180babd9", "codein/jayden"}
        };

        // ensure keys are lowercase to match our lookup
        std::map<std::string, std::string> temp;
        for (auto& p : HWID_MAP) {
            std::string k = p.first;
            std::transform(k.begin(), k.end(), k.begin(), ::tolower);
            temp[k] = p.second;
        }
        HWID_MAP.swap(temp);
    }

    // attempt match
    bool allowed = false;
    std::string userName;
    auto it = HWID_MAP.find(hwid_lc);
    if (it != HWID_MAP.end())
    {
        allowed = true;
        userName = it->second;
    }

    if (!allowed)
    {
        std::cerr << "HWID mismatch — access denied.\n";
        return 1;
    }

    std::cout << "Loading for " << userName << "...";
    std::cout.flush();
    for (int i = 0; i < 3; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        std::cout << ".";
        std::cout.flush();
    }
    std::cout << "\nHWID confirmed. Continuing program...\n";

    // ------------------ Find Discord Process & Module ------------------
    HMODULE VoiceEngine = {};
    HANDLE Discord = {};
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!Snapshot || Snapshot == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to create snapshot" << std::endl;
        return 0;
    }

    PROCESSENTRY32 ProcessEntry = {};
    ProcessEntry.dwSize = sizeof(ProcessEntry);
    while (Process32Next(Snapshot, &ProcessEntry))
    {
        if (!strcmp(ProcessEntry.szExeFile, "Discord.exe"))
        {
            HANDLE Process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                FALSE, ProcessEntry.th32ProcessID);
            if (!Process || Process == INVALID_HANDLE_VALUE)
            {
                std::cout << "Failed to obtain Discord.exe process access, run as admin" << std::endl;
                continue;
            }

            DWORD BytesUsed = 0;
            HMODULE Modules[1024] = {};
            if (!EnumProcessModules(Process, Modules, sizeof(Modules), &BytesUsed))
            {
                std::cout << "Failed to enumerate modules" << std::endl;
                CloseHandle(Process);
                continue;
            }

            for (uint32_t i = 0; i < BytesUsed / sizeof(Modules[0]); i++)
            {
                char ModuleName[MAX_PATH] = {};
                if (!GetModuleBaseNameA(Process, Modules[i], ModuleName, sizeof(ModuleName)))
                {
                    continue;
                }

                if (!strcmp(ModuleName, "discord_voice.node"))
                {
                    VoiceEngine = Modules[i];
                    Discord = Process;
                    break;
                }
            }

            if (Discord) break;
            CloseHandle(Process);
        }
    }

    CloseHandle(Snapshot);

    if (!Discord)
    {
        std::cout << "Could not find any running Discord process." << std::endl;
        system("pause");
        return 0;
    }

exit_from_loop:

    // ------------------ Apply Patches ------------------
    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + EmulateStereoSuccess),
        "\xBD\x01\x00\x00\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",
        sizeof("\xBD\x01\x00\x00\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90") - 1);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + CreateAudioFrameStereoInstruction),
        "\x4D\x89\xC5\x90", sizeof("\x4D\x89\xC5\x90") - 1);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + AudioEncoderOpusConfigSetChannelsInstruction),
        2);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + MonoDownmixerInstructions),
        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\xE9", 10);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + EmulateBitrateModified),
        "\x48\xC7\xC5\x00\xD0\x07\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",
        26);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + HighPassFilter_Process),
        "\x48\xB8\x10\x9E\xD8\xCF\x08\x02\x00\x00\xC3", 11);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + HighpassCutoffFilter),
        (const char*)hp_cutoff, 0x100);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + DcReject),
        (const char*)dc_reject, 0x1B6);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + downmix_func),
        "\xC3", 1);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + Emulate48Khz),
        "\x90\x90\x90", 3);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + AudioEncoderOpusConfig_IsOk),
        "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + AudioEncoderOpusImpl_EncodeImpl_Jump),
        "\x90\xE9", 2);

    ExternalWrite(Discord, (void*)((uintptr_t)VoiceEngine + AudioEncoderOpusImpl_EncodeImpl_Shellcode),
        "\x48\xC7\x47\x20\x00\xD0\x07\x00\xE9\x84\xFE\xFF\xFF", 13);


    std::cout << "heavenly restriction." << std::endl;

    system("pause");
    return 0;
}
