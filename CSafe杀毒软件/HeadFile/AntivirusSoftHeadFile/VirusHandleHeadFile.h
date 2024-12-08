/*
 * MainAntivirus.h
 * 包含主杀毒模块的功能封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <iostream>
#include <ctime>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <vector>
#include <string>
#include <tchar.h>
#include "Log.h"
#include "SHA256.h"
#include "Else.h"
#include "../CSafeAntivirusEngine/CSafeAntivirusEngine.h"
using namespace std;

void LockFileToEasy(const char *FileName) {//锁定文件
	_OVERLAPPED Oapped;
	HANDLE hDir = CreateFile (FileName, GENERIC_READ | GENERIC_WRITE,
	                          FILE_SHARE_READ | FILE_SHARE_DELETE/* | FILE_SHARE_WRITE*/, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
	LockFileEx(hDir, LOCKFILE_EXCLUSIVE_LOCK, (DWORD)0, (DWORD)0,  (DWORD)1024, &Oapped);
	return;
}

bool DeleteLine(std::string file, std::string target) {//删除一个指定文件中的指定一行
	std::ifstream fileIn;
	std::ofstream fileOut;
	std::string line;
	std::vector<std::string> lines;

	fileIn.open(file);

	// 检查文件是否成功打开
	if (fileIn.fail()) {
		return false;
	}

	while (getline(fileIn, line)) {
		// 如果当前行不等于目标字符串，则将其添加到vector中
		if (line != target) {
			lines.push_back(line);
		}
	}

	fileIn.close();

	// 将vector中的所有行写回到同一文件中
	fileOut.open(file);
	for (const auto &line : lines) {
		fileOut << line << std::endl;
	}

	fileOut.close();
	return true;
}

std::string extractFileName(const std::string &fullPath) {//将程序全路径过滤为文件名
	// Find the position of the last directory separator
	std::size_t pos = fullPath.find_last_of("/\\");

	// If found, return the substring after it (i.e., the filename)
	if (pos != std::string::npos) {
		return fullPath.substr(pos + 1);
	}

	// If not found, return the original path
	return fullPath;
}

void ErgodicFolder(std::string path, std::vector<string> &files) {//遍历一个文件夹中的所有文件然后写入files动态数组
	long hFile = 0;
	struct _finddata_t fileinfo;
	std::string pathp;
	if ((hFile = _findfirst(pathp.assign(path).append("\\*").c_str(), &fileinfo)) != -1) {
		do {
			if ((fileinfo.attrib &  _A_SUBDIR)) {
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
					ErgodicFolder(pathp.assign(path).append("\\").append(fileinfo.name), files);
					std::string filestr = fileinfo.name;
					files.push_back(pathp.assign(path).append("\\").append(filestr));
				}
			} else {
				std::string filestr = fileinfo.name;
				files.push_back(pathp.assign(path).append("\\").append(filestr));
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}

std::string GetWindowsDirectoryPath() {
	char path[MAX_PATH];
	GetWindowsDirectory(path, MAX_PATH);
	std::string windowsDirectoryPath(path);
	return windowsDirectoryPath;
}

bool WhiteList(std::string targetPath) {
	char ExeName[MAX_PATH] = {0};//CSafe程序本体全路径
	char path[MAX_PATH] = {0};//CSafe根目录
	GetModuleFileName(NULL, ExeName, MAX_PATH);//获取本体全路径
	GetModuleFileName(NULL, path, MAX_PATH);//获取本体全路径
	(_tcsrchr(path, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串

	if (targetPath.find(std::string(path) + "\\IsolatedZone\\") != std::string::npos) {
		return true;//如果已经隔离了就不管它了
	} else if (targetPath.find(GetWindowsDirectoryPath() + "\\System32") != std::string::npos || targetPath.find(GetWindowsDirectoryPath() + "\\system32") != std::string::npos) {
		return true;//硬拉白C:\Windows\System32
	} else if (targetPath.find(GetWindowsDirectoryPath() + "\\WinSXS") != std::string::npos) {
		return true;//硬拉白C:\Windows\WinSXS
	} else if (targetPath.find(GetWindowsDirectoryPath() + "\\SysWOW64") != std::string::npos) {
		return true;//硬拉白C:\Windows\SysWOW64
	} else if (targetPath.find(GetWindowsDirectoryPath() + "\\explorer.exe") != std::string::npos) {
		return true;//硬拉白文件资源管理器
	} else if (targetPath.find(GetWindowsDirectoryPath() + "\\regedit.exe") != std::string::npos) {
		return true;//硬拉注册表编辑器
	}//别的cmd什么的东西在System32被处理过了，所以不拉白

	if (calculate_file_sha256(ExeName) == calculate_file_sha256(targetPath)) {
		return true;//如果目标文件的哈希码与当前CSafe本体的哈希码一致，那么直接屏蔽
		//P.S.因为文件的哈希码在编译的时候会变(因为文件头和属性不一样了)，所以这里要先计算一次当前文件的哈希码
	}

	string ListName;
	string VirusName = calculate_file_sha256(targetPath);
	fstream WhiteList("CSafeData\\WhiteList.csdata");

	while (getline(WhiteList, ListName)) {
		if (VirusName == ListName || targetPath.find(ListName) != std::string::npos) {//支持目录白名单、文件白名单与SHA-256白名单
			WhiteList.close();//关闭文件
			return true;//return
		}
	}

	WhiteList.close();//关闭文件
	return false;//return
}

bool WriteList(std::string filePath) {//写入白名单
	char currentPath[MAX_PATH];
	// 获取当前进程的可执行文件的完整路径
	GetModuleFileNameA(NULL, currentPath, MAX_PATH);
	(_tcsrchr(currentPath, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串
	ofstream WhiteListFile("CSafeData\\WhiteList.csdata", ios::app);//打开文件

	string VirusName = calculate_file_sha256(filePath);

	if (!WhiteListFile) {//失败
		return false;
	}

	if (!WhiteList(filePath))
		WhiteListFile << VirusName << endl;//写入
	WhiteListFile.close();
	return true;
}

bool forceRemove(std::string filePath, bool deleteImmediately = false) {//默认重启删除
	if (deleteImmediately) {//如果设置了立即删除
		if (!MoveFile(filePath.data(), NULL)) { //常规删除失败
			MoveFileEx(filePath.data(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);//如果无法常规删除则设置重启删除
			return false;//然后返回false
		}
	} else {
		MoveFileEx(filePath.data(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);//不经过常规删除，直接重启删除
	}
	return true;//返回true
}

bool IsolateFile(const std::string fullPath) {
	// 获取当前时间
	std::time_t now = std::time(nullptr);
	std::tm *localTime = std::localtime(&now);

	// 格式化时间字符串
	std::ostringstream oss;
	oss << (localTime->tm_year + 1900) << '.'
	    << (localTime->tm_mon + 1) << '.'
	    << localTime->tm_mday << '.'
	    << localTime->tm_hour << '.'
	    << localTime->tm_min << '.'
	    << localTime->tm_sec;
	std::string timeStr = oss.str();

	// 构建目标文件名
	std::string targetFileName = "IsolatedZone\\" + timeStr + "_" + extractFileName(fullPath) + ".isofile";

	// 移动文件
	if (!MoveFile(fullPath.c_str(), targetFileName.c_str())) {
		log_error("\nIsolated failed!\nDo you wanna remove it forcefully when you reboot the computer?");
		int infyn = MessageBoxA(NULL, (std::string("隔离失败！\n是否强制删除目标文件：") + fullPath + "\n如果设置强制删除，请点击\"是\"，否则请点击\"否\"。\n注意！强制删除后的文件不可恢复！").data(), NULL, MB_SETFOREGROUND | MB_ICONERROR | MB_YESNO);
		if (infyn == IDYES) {
			forceRemove(fullPath);
			log_warn("\nCSafe will delete malware forcefully when you reboot the computer.\nPlease back it up if you think that this is a false alarm, and please make sure you save all your work.\nFile path: ", fullPath);
			int inf = MessageBoxA(NULL, "设置完成，CSafe将在您重启计算机后强制删除目标文件。\n该操作无法撤销，如果该操作为误触，请在您关闭计算机前备份文件！\nCSafe将在您点击\"确定\"后重启计算机，\n如果您希望稍后手动重启，可以点击\"取消\"。", NULL, MB_SETFOREGROUND | MB_ICONWARNING | MB_OKCANCEL);
			if (inf == IDOK) {
				RebootSystem();
			}
		}
	}

	return true;
}

bool ReleaseFile(const std::string HashCode, const std::string TargetReFile) {
	std::vector<std::string> IsolatedFiles;
	ErgodicFolder("IsolatedZone", IsolatedFiles);
	for (int i = 0; i < IsolatedFiles.size(); i++) {
		if (HashCode == calculate_file_sha256(IsolatedFiles[i])) {
			if (MoveFile(IsolatedFiles[i].c_str(), TargetReFile.c_str())) {
				return true;
			}
		}
	}
	return false;
}

std::vector<std::pair<std::string, std::string>> ExportIsolatedFileList(void) {
	std::vector<std::pair<std::string, std::string>> pairRet;//返回结果
	std::vector<std::string> IsolatedFiles;//遍历到的文件名
	ErgodicFolder("IsolatedZone", IsolatedFiles);

	for (int i = 0; i < IsolatedFiles.size(); i++) {
		std::string time = IsolatedFiles[i].substr(IsolatedFiles[i].find("\\") + 1, IsolatedFiles[i].find("_") - (IsolatedFiles[i].find("\\") + 1));
		std::string path = IsolatedFiles[i].substr(IsolatedFiles[i].find("_") + 1, IsolatedFiles[i].find(".isofile") - (IsolatedFiles[i].find("_") + 1));
		pairRet.push_back(std::make_pair(time, path));
	}
	std::cout << "ret" << std::endl;
	return pairRet;
}

std::string GetProcessNameByPid(DWORD dwProcessId) {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return "Invalid_handle_value";
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return "Process32First_failed";
	}

	do {
		// Assuming the process name is the same as the executable name
		std::string processName(pe32.szExeFile);
		if (pe32.th32ProcessID == dwProcessId) {
			CloseHandle(hProcessSnap);
			return processName;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return "Process_not_found";
}

std::string GetCurrentPath() {
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);
	std::string::size_type pos = std::string(path).find_last_of("\\/");
	return std::string(path).substr(0, pos);
}

bool ForceTerminateProcess(DWORD dwPid) {
	struct {
		HMODULE toSafetyLoadLibrary(std::string dllName) {
			char systemDir[MAX_PATH];
			UINT result = GetSystemDirectoryA(systemDir, MAX_PATH);
			if (!(result != 0 && result < MAX_PATH)) {
				return NULL;
			}

			return LoadLibraryA((systemDir + dllName).data());
		}
	} inlineTool;
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwPid);//传统方法kill
	if (hProcess != NULL) {
		return TerminateProcess(hProcess, 0);
	}

	//WinStationTerminateProcess杀
	typedef BOOLEAN (*__WinStationTerminateProcess)(_In_opt_ HANDLE, _In_ ULONG, _In_ ULONG);//函数指针的声明

	static HMODULE killerDLL = inlineTool.toSafetyLoadLibrary("winsta.dll");//加载DLL
	if (killerDLL == NULL) {
		return false;
	}
	__WinStationTerminateProcess WinStationTerminateProcess = (killerDLL != NULL) ? (__WinStationTerminateProcess)GetProcAddress(killerDLL, "WinStationTerminateProcess") : NULL;//获取WinStationTerminateProcess地址
	if (WinStationTerminateProcess != NULL)
		return (bool)WinStationTerminateProcess(NULL, dwPid, 0);
	return false;
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