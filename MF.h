#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>

#define SUCCESS true
#define FAILURE false

#define ADDRESS uintptr_t

class MFi
{
public:
    template <typename T>
    static T Read(uintptr_t address)
    {
        return *((T*)address);
    }

    template<typename T>
    static void Write(uintptr_t address, T value)
    {
        *((T*)address) = value;
    }

    template<typename T>
    static uintptr_t Protect(uintptr_t address, uintptr_t protect)
    {
        DWORD oldProt;
        VirtualProtect((LPVOID)address, sizeof(T), protect, &oldProt);
        return oldProt;
    }

    static void ReplaceByte(uintptr_t address, BYTE byteToReplaceWith)
    {
        uintptr_t oldProtect = Protect<BYTE>(address, PAGE_EXECUTE_READWRITE);
        Write<BYTE>(address, byteToReplaceWith);
        Protect<BYTE>(address, oldProtect);
    }

    static void ReplaceByte(uintptr_t address, BYTE byteToReplaceWith, int count)
    {
        for (int i = 0; i < count; i++)
        {
            uintptr_t oldProtect = Protect<BYTE>(address, PAGE_EXECUTE_READWRITE);
            Write<BYTE>(address + 0x1 * i, (BYTE)byteToReplaceWith);
            Protect<BYTE>(address, oldProtect);
        }
    }

    static void ReplaceByte(uintptr_t address, std::vector<BYTE> byteArray)
    {
        for (int i = 0; i < byteArray.size(); i++)
        {
            uintptr_t oldProtect = Protect<BYTE>(address, PAGE_EXECUTE_READWRITE);
            Write<BYTE>(address + 0x1 * i, (BYTE)byteArray[i]);
            Protect<BYTE>(address, oldProtect);
        }
    }

    static void PrintBytes(uintptr_t address, int count)
    {
        for (int i = 0; i < count; i++)
        {
            printf("%02hhX ", Read<BYTE>(address + 0x1 * i));
        }
    }

    static unsigned char* hookWithJump(uintptr_t hookAt, uintptr_t newFunc)
    {
        uintptr_t newOffset = newFunc - hookAt - 5;

        auto oldProtection = Protect<BYTE[5]>(hookAt, PAGE_EXECUTE_READWRITE);

        unsigned char* originals = new unsigned char[5];
        for (unsigned int i = 0; i < 5; i++)
            originals[i] = Read<unsigned char>(hookAt + i);

        Write<BYTE>(hookAt, 0xE9);
        Write<uintptr_t>(hookAt + 1, newOffset);

        Protect<BYTE[5]>(hookAt + 1, oldProtection);
        return originals;
    }

    static void unhookWithJump(uintptr_t hookAt, unsigned char* originals)
    {
        auto oldProtection = Protect<BYTE[5]>(hookAt, PAGE_EXECUTE_READWRITE);
        for (unsigned int i = 0; i < 5; i++)
            Write<BYTE>(hookAt + i, originals[i]);
        Protect<BYTE[5]>(hookAt + 1, oldProtection);

        delete[] originals;
    }

    static uintptr_t GetModuleAddress(const char* moduleName)
    {
        HMODULE hModule = GetModuleHandleA(moduleName);
        if (hModule == NULL)
            return NULL;
        return (uintptr_t)hModule;
    }

    static uintptr_t FindDMAAddy(uintptr_t baseAddress, std::vector<unsigned int> offsets)
    {
        for (int i = 0; i < offsets.size(); i++)
            baseAddress = *(uintptr_t*)baseAddress + offsets[i];
        return baseAddress;
    }

    static uintptr_t GetPointerAddress(uintptr_t baseAddress, std::vector<unsigned int> offsets)
    {
        uintptr_t addr = baseAddress;
        for (int i = 0; i < offsets.size(); i++)
        {
            addr = *(uintptr_t*)addr;
            addr += offsets[i];
        }
        return addr;
    }
};

class MFe
{
private:
    HANDLE ProcessHandle;
    DWORD ProcessID;

public:
    uintptr_t GetModule(const wchar_t* ModuleName)
    {
        uintptr_t modBaseAddr = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(ProcessHandle));
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 modEntry;
            modEntry.dwSize = sizeof(modEntry);

            if (Module32First(hSnap, &modEntry)) {
                do {
                    if (!_wcsicmp(modEntry.szModule, ModuleName)) {
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        break;
                    }
                } while (Module32Next(hSnap, &modEntry));
            }
        }
        CloseHandle(hSnap);
        return modBaseAddr;
    }

    HANDLE GetHandle(const wchar_t* ProcessName)
    {
        HANDLE hSnap = (CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnap)
            return nullptr;

        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do {
                if (!_wcsicmp(procEntry.szExeFile, ProcessName)) {
                    ProcessID = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }

        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

        return ProcessHandle;
    }

    template <typename T> T Read(uintptr_t Address)
    {
        T BytesRead;
        ReadProcessMemory(ProcessHandle, (LPVOID)Address, &BytesRead, sizeof(T), 0);
        return BytesRead;
    }

    template <typename T> T Write(uintptr_t Address, T Value)
    {
        WriteProcessMemory(ProcessHandle, (LPVOID)Address, &Value, sizeof(T), 0);
    }

    uintptr_t GetPointerAddress(uintptr_t Base, std::vector <unsigned int> Offsets)
    {
        uintptr_t Address = Base;
        for (unsigned int i = 0; i < Offsets.size(); i++)
        {
            ReadProcessMemory(ProcessHandle, (LPCVOID)Address, &Address, sizeof(uintptr_t), NULL);
            Address += Offsets[i];
        }
        return Address;
    }

    uintptr_t GetPointerAddress(uintptr_t ModuleAddress, uintptr_t Address, std::vector<unsigned int> offsets)
    {

        uintptr_t offset_null = NULL;
        ReadProcessMemory(ProcessHandle, (LPVOID*)(ModuleAddress + Address), &offset_null, sizeof(offset_null), 0);
        uintptr_t pointeraddress = offset_null;
        for (int i = 0; i < offsets.size() - 1; i++)
        {
            ReadProcessMemory(ProcessHandle, (LPVOID*)(pointeraddress + offsets.at(i)), &pointeraddress, sizeof(pointeraddress), 0);
        }
        return pointeraddress += offsets.at(offsets.size() - 1);
    }

    void Inject(LPCSTR DllPath)
    {
        LPVOID LoadLibAddy, RemoteString;

        LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
        RemoteString = (LPVOID)VirtualAllocEx(ProcessHandle, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

        WriteProcessMemory(ProcessHandle, RemoteString, (LPVOID)DllPath, strlen(DllPath) + 1, NULL);
        CreateRemoteThread(ProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, RemoteString, NULL, NULL);
    }

    bool Close()
    {
        bool _close = CloseHandle(ProcessHandle);
        if (_close == SUCCESS)
            return SUCCESS;
        return FAILURE;
    }
};