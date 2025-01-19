/*
 * TOProtect.h
 * CSafe杀毒引擎子引擎TOProtect的API封装及定义和一些风险行为的检测API封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <io.h>
#include <algorithm>
#include "EngineHeadFile/TOProtect.h"
#include "EngineHeadFile/SharedMap.h"
#define MAX_MAPSIZE 16384

//======================================//
//Windows API检测函数
//通过检测一些不需要注入等特殊技术就可以获取到的信息来生成风险等级
//======================================//

bool HideFileDetection(PROCESSENTRY32 TargetProcess) {//检查文件是否隐藏
	if (IsFileHidden(GetProcessFullPath(TargetProcess)))
		return true;
	return false;
}

bool HideExeDetection(PROCESSENTRY32 TargetProcess) {//检查文件根目录下有无隐藏exe
	std::string directoryPath = GetProcessFullPath(TargetProcess);

	for (int i = 0; i < directoryPath.size(); ++i) {
		if (directoryPath[i] == '/')
			directoryPath[i] = '\\';
	}

	for (int i = directoryPath.size() - 1; i >= 0; --i) {
		if (directoryPath[i] == '\\') {
			directoryPath.erase(i, directoryPath.size() - 1);
			break;
		}
	}

	directoryPath += "\\*.exe";

	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile(directoryPath.c_str(), &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		return false;
	}

	do {
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
			return true;

		// 确保跳过目录，只列出文件
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	FindClose(hFind); // 关闭搜索句柄
	return false;
}

bool HideDllDetection(PROCESSENTRY32 TargetProcess) {//检查文件根目录下有无隐藏dll
	std::string directoryPath = GetProcessFullPath(TargetProcess);

	for (int i = 0; i < directoryPath.size(); ++i) {
		if (directoryPath[i] == '/')
			directoryPath[i] = '\\';
	}

	for (int i = directoryPath.size() - 1; i >= 0; --i) {
		if (directoryPath[i] == '\\') {
			directoryPath.erase(i, directoryPath.size() - 1);
			break;
		}
	}

	directoryPath += "\\*.dll";

	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile(directoryPath.c_str(), &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		return false;
	}

	do {
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
			return true;

		// 确保跳过目录，只列出文件
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	FindClose(hFind); // 关闭搜索句柄
	return false;
}

bool StartItemDetection(PROCESSENTRY32 TargetProcess) {
	std::vector<std::string> StartItems = getStartupItems();

	for (int i = 0; i < StartItems.size(); ++i) {
		for (int j = 0; j < StartItems[i].size(); ++j) {
			if (StartItems[i][j] == '/')
				StartItems[i][j] = '\\';
		}
		FilterProgramName(StartItems[i]);
	}

	const std::string ProcessPath = GetProcessFullPath(TargetProcess);

	for (int i = 0; i < StartItems.size(); ++i) {
		if (StartItems[i] == ProcessPath)
			return true;
	}
	return false;
}

bool IEFODetection(PROCESSENTRY32 TargetProcess) {
	std::vector<std::string> IEFOItems = ScanIEFO();

	for (int i = 0; i < IEFOItems.size(); ++i) {
		for (int j = 0; j < IEFOItems[i].size(); ++j) {
			if (IEFOItems[i][j] == '/')
				IEFOItems[i][j] = '\\';
		}
		FilterProgramName(IEFOItems[i]);
	}

	const std::string ProcessPath = GetProcessFullPath(TargetProcess);

	for (int i = 0; i < IEFOItems.size(); ++i) {
		if (IEFOItems[i] == ProcessPath)
			return true;
	}
	return false;
}

bool AdminDetection(PROCESSENTRY32 TargetProcess) {
	return IsProcessElevatedForProcessID(TargetProcess.th32ProcessID);
}

//======================================//
//DLL注入部分检测函数
//通过DLL注入计算一个进程的风险
//======================================//

bool MBRDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_CreateFile", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	std::transform(strBuffer.begin(), strBuffer.end(), strBuffer.begin(),
	[](unsigned char c) {
		return std::tolower(c);
	});

	if (strBuffer.find("physicaldrive0") != std::string::npos) {
		return true;
	}
	return false;
}

bool PEDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_CreateFile", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	std::transform(strBuffer.begin(), strBuffer.end(), strBuffer.begin(),
	[](unsigned char c) {
		return std::tolower(c);
	});

	if (strBuffer.find("exe") != std::string::npos || strBuffer.find("dll") != std::string::npos) {
		return true;
	}
	return false;
}

bool AutoRunDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_CreateFile", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	std::transform(strBuffer.begin(), strBuffer.end(), strBuffer.begin(),
	[](unsigned char c) {
		return std::tolower(c);
	});

	if (strBuffer.find("autorun.inf") != std::string::npos) {
		return true;
	}
	return false;
}

bool SettingFilesDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_CreateFile", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	std::transform(strBuffer.begin(), strBuffer.end(), strBuffer.begin(),
	[](unsigned char c) {
		return std::tolower(c);
	});

	if ((strBuffer.find("inf") != std::string::npos && strBuffer.find("autorun.inf") == std::string::npos) || strBuffer.find("ini") != std::string::npos) {
		return true;
	}
	return false;
}

bool RiskFunctionsDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_GetProcAddress", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	//你猜为什么我不对加壳病毒的导入表漏杀做优化（
	//因为LSProtect有针对导入表隐藏的优化（
	//你可能会说等级全部调1级会不会误报
	//霉逝，谁家好程序开局就搞这么炸裂的东西
	std::vector<std::string> RiskFunctions = {//不带风险等级，有一个就杀
		"WinStationTerminateProcess",//结束进程
		"NtTerminateProcess",//结束进程
		"ZwTerminateProcess",//结束进程
		"PsTerminateProcess",//结束进程
		"PspTerminateProcess",//结束进程
		"PspTerminateThreadByPoint",//结束进程
		"PspExitThread",//结束进程
		"LoadLibraryA",//DLL注入
		"LoadLibraryW",//DLL注入
		"GetProcAddress",//DLL注入
		"ExitProcess",//注入结束进程的代码
		"ZwCreateThreadEx",
		"NtCreateProcess",
		"NtSetInformationProcess",
		"IoCreateDriver",
		"IoDeleteDriver",
		"pspTerminateProcess",
		"NtAllocateVirtualMemory",
		"NtFreeVirtualMemory",
		"NtQuerySystemInformation",
		"NtSetSystemInformation",
		"NtCreateKey",
		"NtDeleteKey",
		"NtCreateProcess",
		"KeStackAttachProcess"
	};

	short RiskLevel = 0;

	for (int i = 0; i < RiskFunctions.size(); ++i) {
		//在返回的函数中找到了可能有风险的函数
		if (strBuffer.find(RiskFunctions[i]) != std::string::npos) {
			++RiskLevel;
		}
	}

	if (RiskLevel >= 1) { //因为正常程序很少出现这种情况，因此这里只要有一条匹配就直接返回true
		return true;
	}
	return false;
}

bool OpenProcessDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	if (std::string(buffer).find("-1") != std::string::npos || std::string(buffer).find(std::to_string(GetCurrentProcessId())) != std::string::npos) { //检测到预设的危险进程或者当前杀软进程
		return true;
	}

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	// 初始化 PROCESSENTRY32 结构体
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	// 获取第一个进程的信息
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return false;
	}
	// 遍历所有进程
	do {
		if (std::string(pe32.szExeFile).find("explorer.exe") != std::string::npos ||
		        std::string(pe32.szExeFile).find("winlogon.exe") != std::string::npos ||
		        std::string(pe32.szExeFile).find("cmd.exe") != std::string::npos) {//拉exe风险单
			if (std::string(buffer).find(std::to_string(pe32.th32ProcessID)) != std::string::npos) { //如果这个进程尝试访问了这些拉单的进程
				CloseHandle(hProcessSnap);
				return true;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
	// 关闭句柄
	CloseHandle(hProcessSnap);

	return false;
}



//======================================//
//注入用API
//======================================//

//初始化TOProtect引擎，执行DLL注入，返回true说明注入成功，返回false说明注入失败(对于一些短命的进程来说无所谓)
//DLLPath可以省略，函数将返回false，其他函数在无DLL注入的情况下仍可继续运行
bool TOProtect_InitInject(PROCESSENTRY32 TargetProcess, std::string DLLPath = nullptr) {
	return InjectDLL(TargetProcess.th32ProcessID, DLLPath.c_str());
}
void TOProtect_EndInject(PROCESSENTRY32 TargetProcess) {//结束某一个进程的共享内存
	HANDLE Map = CreateMap("toMap_bFlag", MAX_MAPSIZE, TargetProcess.th32ProcessID);//创建共享内存
	const char *bFlagBuffer = std::to_string(TargetProcess.th32ProcessID).data();
	WriteMap(Map, bFlagBuffer, strlen(bFlagBuffer) + 1);//写入共享内存

	const char ClearBuffer[MAX_MAPSIZE] = {0};//这里清除一下共享内存的内容
	HANDLE toMap_CreateFile = CreateMap("toMap_CreateFile", MAX_MAPSIZE, TargetProcess.th32ProcessID);//删除共享内存
	WriteMap(toMap_CreateFile, ClearBuffer, strlen(ClearBuffer) + 1);//写入共享内存
	DeleteMap(toMap_CreateFile);
	HANDLE toMap_GetProcAddress = CreateMap("toMap_GetProcAddress", MAX_MAPSIZE, TargetProcess.th32ProcessID);//删除共享内存
	WriteMap(toMap_GetProcAddress, ClearBuffer, strlen(ClearBuffer) + 1);//写入共享内存
	DeleteMap(toMap_GetProcAddress);
	HANDLE toMap_OpenProcess = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, TargetProcess.th32ProcessID);//删除共享内存
	WriteMap(toMap_OpenProcess, ClearBuffer, strlen(ClearBuffer) + 1);//写入共享内存
	DeleteMap(toMap_OpenProcess);
}


//======================================//
//打包用内部API
//======================================//

//内部API，用来计算风险等级字符串，更改等级建议从这里修改
inline std::string strGenerateRiskLevel(short RiskLevel) {
	if (RiskLevel <= 0) { //RiskLevel <= 0，无风险
		return "Risk.NoRisk";
	} else if (RiskLevel >= 1 && RiskLevel <= 3) { //1 <= RiskLevel <= 3，低风险
		return "Risk.LowRisk";
	} else if (RiskLevel >= 4 && RiskLevel <= 6) { //4 <= RiskLevel <= 6，中等风险
		return "Risk.MidRisk";
	} else if (RiskLevel >= 7 && RiskLevel <= 8) { //7 <= RiskLevel <= 8，危险
		return "Risk.HighRisk";
	}

	//RiskLevel > 8(RiskLevel >= 9)，病毒
	return "Risk.Malware";
}

//这个其实算内部API的，用来在非注入模式下获取进程的风险等级，但是实际调用拿到的应该是风险字符串
inline short TOProtect_NoInject_LEVEL(PROCESSENTRY32 TargetProcess) {
	short RiskLevel = 0;

	//基于Windows API的动态检测
	(AdminDetection(TargetProcess)) ? RiskLevel += 2 : 0;//FirstRiskLevel在第一阶段检测之后会自动清空，由于这几条条目检测速度较快且在进程刚启动的时候就能检测到的概率不高，所以第二次循环会再检一遍
	(IEFODetection(TargetProcess)) ? RiskLevel += 8 : 0;
	(StartItemDetection(TargetProcess)) ? RiskLevel += 3 : 0;

	(HideFileDetection(TargetProcess) ||
	 HideExeDetection(TargetProcess) ||
	 HideDllDetection(TargetProcess)) ? RiskLevel += 7 : 0;//三个检测合到一起(因为类型相似、风险等级相同)，同时因为文件检测较慢所以只进行一次，因此用SecondRiskLevel，不清零，继承下去

	return RiskLevel;
}

//注入模式下获取进程风险等级
inline short TOProtect_Injected_LEVEL(PROCESSENTRY32 TargetProcess) {
	short RiskLevel = 0;

	//基于注入过的DLL的动态防护
	(MBRDetection(TargetProcess)) ? RiskLevel += 9 : 0;
	(PEDetection(TargetProcess)) ? RiskLevel += 8 : 0;
	(AutoRunDetection(TargetProcess)) ? RiskLevel += 6 : 0;
	(SettingFilesDetection(TargetProcess)) ? RiskLevel += 4 : 0;
	(RiskFunctionsDetection(TargetProcess)) ? RiskLevel += 8 : 0;
	(OpenProcessDetection(TargetProcess)) ? RiskLevel += 7 : 0;

	return RiskLevel;
}


//======================================//
//打包API
//======================================//

//快捷检测一个进程的风险等级，不需要注入
std::string TOProtect_NoInject(PROCESSENTRY32 TargetProcess) {
	return strGenerateRiskLevel(TOProtect_NoInject_LEVEL(TargetProcess));
}

std::string TOProtect_Injected(PROCESSENTRY32 TargetProcess) {
	return strGenerateRiskLevel(TOProtect_Injected_LEVEL(TargetProcess));
}

//开始注入
bool TOProtect_Begin(PROCESSENTRY32 TargetProcess, std::string DLLPath) {
	if (access(DLLPath.c_str(), F_OK) == -1) {
		return false;
	}
	return TOProtect_InitInject(TargetProcess, DLLPath);
}

//结束注入并返回风险等级
std::string TOProtect_End(PROCESSENTRY32 TargetProcess) {
	short RiskLevel = 0;

	//基于Windows API的动态检测
	RiskLevel += TOProtect_NoInject_LEVEL(TargetProcess);

	//基于注入过的DLL的动态防护
	RiskLevel += TOProtect_Injected_LEVEL(TargetProcess);

	TOProtect_EndInject(TargetProcess);//重置共享内存

	return strGenerateRiskLevel(RiskLevel);
}

//提示：
//注释中写的"越级"代表杀毒引擎因为条件判断的设置有误，或者等级划分不合理，给出了一个不符合程序危险行为的等级的情况，
//例如本来危险等级应该是6级，但是杀毒引擎却给出了9级甚至是以上的风险等级，并且这不是因为程序或者代码出问题了，
//而是杀毒软件本身对等级叠加的设置或者该行为的等级定义不合理，那么我们就称之为"越级"。

//当前版本风险等级与风险程度对照表：
//0级：无风险
//1-3级：低风险
//4-6级：高风险
//7-8级：危险
//9级及以上：病毒

//以下是不同风险程度建议给予的处理：
//无风险：不予处理
//低风险-高风险：挂起程序并记录
//危险-病毒：结束进程并隔离

//注意：除无风险以外，其他风险情况均应该告知用户，
//并且应该让用户决定后续的处理方式(如删除文件、隔离文件、不予处理并添加白名单等处理方式)！