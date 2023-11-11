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
#include <winbase.h>
#include <psapi.h>
using namespace std;


/*
 *函数名称：GetProcess(name)
 *函数参数：
 *	name：目标进程名
 *函数功能：检测指定进程是否存在
 *函数返回值：bool类型
 *	为true：进程存在
 *	为false：进程不存在
*/
bool GetProcess(LPCTSTR name, PROCESSENTRY32 &ProcData) {
	PROCESSENTRY32 pe;
	int id = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe))
		return false;             //失败
	while (1) {
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32Next(hSnapshot, &pe) == FALSE)
			break;
		if (strcmp(pe.szExeFile, name) == 0) {
			id = pe.th32ProcessID;
			ProcData = pe;
			break;
		}
	}
	CloseHandle(hSnapshot);
	return id;
}

int NameToPID(const char *ProcessName) {
	HANDLE processAll = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	tagPROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(tagPROCESSENTRY32);
	DWORD dwPID = 0;
	do {
		if (strcmp(ProcessName, processEntry.szExeFile) == 0) {
			// 获取到PID
			dwPID = processEntry.th32ProcessID;
			break;
		}
	} while (Process32Next(processAll, &processEntry));
	CloseHandle(processAll);

	TCHAR        szImagePath[MAX_PATH];
	HANDLE        hProcess;
	return (int)dwPID;
}

/*
 *函数名称：KillProcess(ProcessName)
 *函数参数：
 *	ProcessName：目标进程名
 *函数功能：结束指定进程
 *函数返回值：bool类型
 *	为true：结束成功
 *	为false：结束失败
*/
bool KillProcess(char *ProcessName) {	                 //杀除病毒进程函数
	HANDLE processAll = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	tagPROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(tagPROCESSENTRY32);
	DWORD processId = 0;
	do {
		if (strcmp(ProcessName, processEntry.szExeFile) == 0) {
			// 获取到PID
			processId = processEntry.th32ProcessID;
			break;
		}
	} while (Process32Next(processAll, &processEntry));
	bool KillTrue = TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId), 0);
	CloseHandle(processAll);
	return KillTrue;
}

bool PauseProcess(DWORD dwProcessID, bool fSuspend) {     //挂起进程函数
	HANDLE hSnapshot = CreateToolhelp32Snapshot(
	                       TH32CS_SNAPTHREAD, dwProcessID);

	if (hSnapshot != INVALID_HANDLE_VALUE) {

		THREADENTRY32 te = {sizeof(te)};
		BOOL fOk = Thread32First(hSnapshot, &te);
		for (; fOk; fOk = Thread32Next(hSnapshot, &te)) {
			if (te.th32OwnerProcessID == dwProcessID) {
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME,
				                            FALSE, te.th32ThreadID);

				if (hThread != NULL) {
					if (fSuspend) {
						SuspendThread(hThread);
					} else {
						ResumeThread(hThread);
					}
				}
				CloseHandle(hThread);
			}
		}
		CloseHandle(hSnapshot);
		return true;
	}
	return false;
}

bool IsHidden(const char *pszFilePath) {
	DWORD dwAttr = GetFileAttributes(pszFilePath);

	if (dwAttr & FILE_ATTRIBUTE_HIDDEN) {
		//是目录
		return true;
	} else {
		//是文件
		return false;
	}
}

bool GetExecuteFiles(string path) {
	//文件句柄
	intptr_t hFile = 0;
	//文件信息
	struct _finddata_t fileinfo;
	string p;

	if ((hFile = _findfirst(p.assign(path).append("\\*.exe").c_str(), &fileinfo)) != -1) {
		do {
			if ((fileinfo.attrib ==  _A_NORMAL)) {
//				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
//					getFiles(p.assign(path).append("\\").append(fileinfo.name), files);
//				}
			} else {
				string FileBuf = p.assign(path).append("\\").append(fileinfo.name);       //定义缓存
				char *FileBufc = new char[strlen(FileBuf.c_str()) + 1];            //定义char*型缓存
				strcpy(FileBufc, FileBuf.c_str());                            //将string型缓存强转为char*型缓存

				if (IsHidden(FileBufc)) {                           //是否为隐藏文件
					delete FileBufc;                               //delete掉刚才new出来的对象
					return true;                                    //检测到隐藏文件，return true
				}

				delete FileBufc;
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}

	return false;            //没检测到就return false
}

bool IsProcessElevatedForHandle(HANDLE hProcess) {
	HANDLE hToken;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		return false;
	}

	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return (elevation.TokenIsElevated != 0);
}

bool IsProcessElevatedForName(char *ProcessName) {
	HANDLE processAll = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	tagPROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(tagPROCESSENTRY32);
	DWORD processId = 0;
	do {
		if (strcmp(ProcessName, processEntry.szExeFile) == 0) {
			// 获取到PID
			processId = processEntry.th32ProcessID;
			break;
		}
	} while (Process32Next(processAll, &processEntry));
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess)
		return false;

	HANDLE hToken = nullptr;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		CloseHandle(hProcess);
		return false;
	}

	TOKEN_ELEVATION elevation;
	DWORD cbSize = sizeof(TOKEN_ELEVATION);

	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
		CloseHandle(hToken);
		CloseHandle(hProcess);
		return false;
	}

	bool fIsElevated = elevation.TokenIsElevated;

	CloseHandle(hToken);
	CloseHandle(hProcess);

	return fIsElevated;
}

bool IsSystemProcessAsPathForPID(DWORD processId) {
	// 打开进程句柄
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (hProcess == NULL)
		return false;

	// 获取进程的映像文件名
	char processFileName[MAX_PATH];
	if (!GetProcessImageFileName(hProcess, processFileName, MAX_PATH)) {
		CloseHandle(hProcess);
		return false;
	}

	// 判断进程是否为系统进程
	bool isSystemProcess = (strstr(processFileName, "\\System32\\") != NULL)
	                       || (strstr(processFileName, "svchost") != NULL);

	// 关闭进程句柄
	CloseHandle(hProcess);

	// 返回结果
	return isSystemProcess;
}

bool IsSystemProcessAsSystemForPID(DWORD processId) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess != NULL) {
		BOOL isSystem = FALSE;
		if (IsProcessInJob(hProcess, NULL, &isSystem) && isSystem) {
			CloseHandle(hProcess);
			return true;
		}
		CloseHandle(hProcess);
	}
	return false;
}