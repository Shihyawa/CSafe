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
#include <psapi.h>
using namespace std;



BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath) {
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//检查参数
	if (!pszDosPath || !pszNtPath )
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr)) {
		for (i = 0; szDriveStr[i]; i += 4) {
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100)) //查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0) { //命中
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
/*
 *函数名称：GetProcessPath(ProcessName, pszFullPath[MAX_PATH])
 *函数参数：
 *	ProcessName：目标进程位置
 *	pszFullPath：位置信息储存位置
 *函数功能：检测程序路径并将位置信息储存进输入的pszFullPath变量
 *函数返回值：BOOL类型
 *	为TRUE：成功执行
 *	为FALSE：执行失败
*/
BOOL GetProcessPath(char *ProcessName, TCHAR pszFullPath[MAX_PATH]) {
	/*_______________________________________获取进程pid_________________________________________*/
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
	if (!pszFullPath)
		return FALSE;
	/*___________________________________________获取进程pid完成____________________________________________*/
	pszFullPath[0] = '\0';
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess)
		return FALSE;

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}
/*
 *函数名称：MoveFileTo(InFile[MAX_PATH], OutFile[MAX_PATH])
 *函数参数：
 *	InFile：将被移动的文件
 *	OutFile：移动后的目标文件
 *函数功能：将指定文件移动到另一个位置
 *函数返回值：bool类型
 *	为true：成功执行
 *	为false：执行失败
*/
bool MoveFileTo(TCHAR InFile[MAX_PATH] = {0}, TCHAR OutFile[MAX_PATH] = {0}) {      //移动文件函数，单独包成一个函数，到时候好用
	ifstream InFileSt(InFile, ios::binary);//将被移动的文件
	ofstream OutFileSt(OutFile, ios::binary);//将要输出的文件
	if (!InFileSt) {//打开错误
		return false;
	}
	if (!OutFileSt) {//打开错误
		return false;
	}
	OutFileSt << InFileSt.rdbuf();//创建输出文件并拷贝数据
	OutFileSt.close();//关闭文件
	InFileSt.close();//关闭文件
	remove(InFile);//删除源文件
	return true;
}

bool CopyMBR(void) {      //复制文件函数，单独包成一个函数，写MBR用的
	FILE *MBRFile;
	FILE *ToMBR;
	unsigned char MBRCode[512] = {0};//一个扇区512字节
	MBRFile = fopen("\\\\.\\PhysicalDrive0", "rb+");
	if (!MBRFile) {
		return false;
	} else if (!feof(MBRFile)) {
		fseek(MBRFile, 0, SEEK_SET);
		fread(MBRCode, 512, 1, MBRFile);
		ToMBR = fopen("Data\\MBRData.data", "wb+");
		if (!ToMBR) {
			return false;
		} else if (!feof(ToMBR)) {
			fwrite(MBRCode, 512, 1, ToMBR);
			fclose(ToMBR);
		}
		fclose(MBRFile);
	}
	return true;
}

bool ReMBR(void) {      //复制文件函数，单独包成一个函数，写MBR用的
	FILE *MBRFile;
	FILE *ToMBR;
	unsigned char MBRCode[512] = {0};//一个扇区512字节
	MBRFile = fopen("Data\\MBRData.data", "rb+");
	if (!MBRFile) {
		return false;
	} else if (!feof(MBRFile)) {
		fseek(MBRFile, 0, SEEK_SET);
		fread(MBRCode, 512, 1, MBRFile);
		ToMBR = fopen("\\\\.\\PhysicalDrive0", "wb+");
		if (!ToMBR) {
			return false;
		} else if (!feof(ToMBR)) {
			fwrite(MBRCode, 512, 1, ToMBR);
			fclose(ToMBR);
		}
		fclose(MBRFile);
	}
	return true;
}