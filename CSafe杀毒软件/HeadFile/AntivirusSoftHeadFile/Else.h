/*
 * Else.h
 * 包含杀毒软件处理时的一些其他杂项(关机等)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <fstream>
#define SELFSTART_REGEDIT_PATH "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"//定义写入的注册表路径

bool IsUserAnAdmin() {
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;  //判断是否有管理员权限
	PSID AdministratorsGroup;
	BOOL b = AllocateAndInitializeSid(
	             &NtAuthority,
	             2,
	             SECURITY_BUILTIN_DOMAIN_RID,
	             DOMAIN_ALIAS_RID_ADMINS,
	             0, 0, 0, 0, 0, 0,
	             &AdministratorsGroup);
	if (b) {
		CheckTokenMembership(NULL, AdministratorsGroup, &b);
		FreeSid(AdministratorsGroup);
	}

	return (b == TRUE) ? true : false;
}

bool SetStart(bool bKey) {//设置启动项
	//获取程序完整路径
	char pName[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, pName, MAX_PATH);
	//在注册表中写入启动信息
	HKEY hKey = NULL;
	LONG lRet = 0;
	if ( bKey) {
		//打开注册表
		lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SELFSTART_REGEDIT_PATH, 0, KEY_ALL_ACCESS, &hKey);
		//判断是否成功
		if (lRet != ERROR_SUCCESS) {
			return false;
		} else {

			//写入注册表，名为Cdun.
			RegSetValueExA(hKey, "CSafe", 0, REG_SZ, (const unsigned char *)pName, strlen(pName) + sizeof(char));

			//关闭注册表
			RegCloseKey(hKey);
			return true;
		}
	} else {
		lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SELFSTART_REGEDIT_PATH, 0, KEY_ALL_ACCESS, &hKey);
		//判断是否成功
		if (lRet != ERROR_SUCCESS) {
			return false;
		} else {

			//删除名为Cdun的注册表信息
			RegDeleteValueA(hKey, "CSafe");

			//关闭注册表
			RegCloseKey(hKey);
			return true;
		}
	}
}

void DisableFastMake() {
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	GetConsoleMode(hStdin, &mode);
	mode &= ~ENABLE_QUICK_EDIT_MODE;  //移除快速编辑模式
	mode &= ~ENABLE_INSERT_MODE;      //移除插入模式
	mode &= ~ENABLE_MOUSE_INPUT;
	SetConsoleMode(hStdin, mode);
}

unsigned long getFileSize(const std::string &filePath) {
	std::ifstream file(filePath, std::ifstream::in | std::ifstream::binary);
	if (file.is_open()) {
		file.seekg(0, std::ios::end);
		return file.tellg(); // tellg 获取文件大小
	}
	return 0;
}

bool ShutdownSystem(void) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
	                     &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
	                      (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return false;

	if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
	                   SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
	                   SHTDN_REASON_FLAG_PLANNED))
		return false;

	return true;
}

bool RebootSystem(void) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
	                     &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
	                      (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return false;

	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
	                   SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
	                   SHTDN_REASON_FLAG_PLANNED))
		return false;

	return true;
}