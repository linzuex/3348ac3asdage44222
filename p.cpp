#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <cstring>
#include <map>
#include <thread> 

// ------------------ Existing Function Declarations ------------------
extern "C" void dc_reject(const float* in, float* out, int* hp_mem, int len, int channels, int Fs);
extern "C" void hp_cutoff(const float* in, int cutoff_Hz, float* out, int* hp_mem, int len, int channels, int Fs, int arch);

void ExternalWrite(HANDLE Process, void* Address, const char* source, uint32_t size)
{
    DWORD Old = 0;
    DWORD Junk = 0;
    VirtualProtectEx(Process, Address, 0x1000, PAGE_EXECUTE_READWRITE, &Old);
    if (!WriteProcessMemory(Process, Address, source, size, NULL))
    {
        std::cout << "Write failed! length: " << size << ", address: " << Address << ", code: " << GetLastError() << std::endl;
    }
    VirtualProtectEx(Process, Address, 0x1000, Old, &Junk);
}

void ExternalWrite(HANDLE Process, void* Address, uint8_t byte)
{
    DWORD Old = 0;
    DWORD Junk = 0;
    VirtualProtectEx(Process, Address, 0x1000, PAGE_EXECUTE_READWRITE, &Old);
    if (!WriteProcessMemory(Process, Address, &byte, 1, NULL))
    {
        std::cout << "Write failed!" << std::endl;
    }
    VirtualProtectEx(Process, Address, 0x1000, Old, &Junk);
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

int main()
{
    std::map<std::string, std::string> HWID_MAP = {
        {"4f1e2b46-d12a-4552-9c9d-e85b90da929b", "wish"},
        {"83c22171-6293-435f-b585-a6a5fdf3ba8c", "pk"},
        {"419fd6a6-52ca-4a92-9d3a-cef7928e2c2e", "vek"},
        {"c0c08bbd-f8d9-4ce6-abed-f188e6ac7094", "jairo"},
        {"3348ac39-b0d7-41e8-b20b-6477180babd9", "codein/jayden"}.
    };

    std::string hwid = getHWID();
    if (hwid.empty()) {
        std::cerr << "Failed to retrieve HWID from registry.\n";
        return 1;
    }

    std::cout << "Retrieved HWID: " << hwid << "\n";

    std::string hwid_lc = hwid;
    std::transform(hwid_lc.begin(), hwid_lc.end(), hwid_lc.begin(), ::tolower);

    bool allowed = false;
    std::string userName;

    for (const auto& pair : HWID_MAP) {
        std::string allowed_lc = pair.first;
        std::transform(allowed_lc.begin(), allowed_lc.end(), allowed_lc.begin(), ::tolower);
        if (hwid_lc == allowed_lc) {
            allowed = true;
            userName = pair.second;
            break;
        }
    }

    if (!allowed) {
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
            HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessEntry.th32ProcessID);
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
                    goto exit_from_loop;
                }
            }
        }
    }

    std::cout << "Could not find any running Discord process." << std::endl;
    system("pause");
    return 0;









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


    std::cout << "jairo build." << std::endl;

    system("pause");
    return 0;
}
