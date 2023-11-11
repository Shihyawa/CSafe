#include <cmath>     //头文件
#include <ctime>
#include <time.h>
#include <cstdio>
#include <string>
#include <tchar.h>
#include <fstream>
#include <cstdlib>
#include <conio.h>
#include <iostream>
#include <windows.h>
#include <algorithm>
#include <tlhelp32.h>             //检查进程用的
using namespace std;
#define MAX_PATH 4096          //定义路径最大程度
#define SELFSTART_REGEDIT_PATH "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"//定义写入的注册表路径


/*
 *函数名称：SetStart(bKey)
 *函数参数：
 *	bKey：启动项设置
 *函数功能：开启或关闭当前程序开机自启动
 *函数返回值：bool类型
 *	为true：成功执行
 *	为false：执行失败（没有权限或者没有指定的注册表路径）
*/
BOOL SetStart(bool bKey) {
	//获取程序完整路径
	char pName[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, pName, MAX_PATH);
	//在注册表中写入启动信息
	HKEY hKey = NULL;
	LONG lRet = NULL;
	if ( bKey) {
		//打开注册表
		lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SELFSTART_REGEDIT_PATH, 0, KEY_ALL_ACCESS, &hKey);
		//判断是否成功
		if (lRet != ERROR_SUCCESS) {
			return FALSE;
		} else {

			//写入注册表，名为Cdun.
			RegSetValueExA(hKey, "Cdun", 0, REG_SZ, (const unsigned char *)pName, strlen(pName) + sizeof(char));

			//关闭注册表
			RegCloseKey(hKey);
			return TRUE;
		}
	} else {
		lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SELFSTART_REGEDIT_PATH, 0, KEY_ALL_ACCESS, &hKey);
		//判断是否成功
		if (lRet != ERROR_SUCCESS) {
			return FALSE;
		} else {

			//删除名为Cdun的注册表信息
			RegDeleteValueA(hKey, "Cdun");

			//关闭注册表
			RegCloseKey(hKey);
			return TRUE;
		}
	}
}

/*
 *函数名称：GetFileSize(file_name)
 *函数参数：
 *	file_name：目标文件
 *函数功能：获取文件大小
 *函数返回值：无
*/
size_t GetFileSize(const std::string &file_name) {
	FILE *fp = fopen(file_name.c_str(), "r");
	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fclose(fp);
	return size; //单位是：byte
}
/*
 *函数名称：LockFileToEasy(lpPath)
 *函数参数：
 *	FileName：目标文件
 *函数功能：锁定文件
 *函数返回值：无
*/
void LockFileToEasy(const char *FileName) {
	_OVERLAPPED Oapped;
	HANDLE hDir = CreateFile (FileName, GENERIC_READ | GENERIC_WRITE,
	                          FILE_SHARE_READ | FILE_SHARE_DELETE/* | FILE_SHARE_WRITE*/, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
	LockFileEx(hDir, LOCKFILE_EXCLUSIVE_LOCK, (DWORD)0, (DWORD)0,  (DWORD)1024, &Oapped);
	return;
}

/*
 *函数名称：ShutdownSystem()
 *函数参数：无
 *函数功能：关闭计算机
 *函数返回值：BOOL类型
 *	为TRUE：成功
 *	为FALSE：失败
*/
BOOL ShutdownSystem() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
	                     &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
	                      (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
	                   SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
	                   SHTDN_REASON_MINOR_UPGRADE |
	                   SHTDN_REASON_FLAG_PLANNED))
		return FALSE;

	return TRUE;
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