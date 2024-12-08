/*
 * CSafeAntivirusEngine.h
 * CSafe杀毒引擎主头文件，封装了一些可以用于直接调用的操作API
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <vector>
#include <string>
#include <fstream>
#include "CSafeAntivirusEngineHeadFile.h"

//查杀引擎
#include "AntivirusEngine/TOProtect.h"//动态启发
#include "AntivirusEngine/LSProtect.h"//导入表静态启发
#include "AntivirusEngine/BITProtect.h"//PE文件可识别字符串静态启发

namespace CSafeAntivirusEngine {
	//常用变量
	static bool LSProtectEnableSensitiveMode = true;//默认启用高启发
	static float BITProtectBlackWeight = 1.0F;


	//工具函数
	std::string getProcessPath(DWORD dwProcessId) {//获取进程路径
		char cProcessPath[MAX_PATH];
		if (GetProcessPath(dwProcessId, cProcessPath)) {
			return cProcessPath;
		} else {
			return "Error";
		}
	}
	bool getNewProcess(PROCESSENTRY32 &targetProcess) {//获取新启动的进程，如果有新启动的进程则将进程信息赋给targetProcess并返回true，反之返回false
		return GetProcessListStart(targetProcess);
	}


	//进程查杀类API
	bool detectProcess_Begin(PROCESSENTRY32 targetProcess, std::string dllPath) {
		return TOProtect_Begin(targetProcess, dllPath);
	}
	std::string detectProcess_End(PROCESSENTRY32 targetProcess) {
		return TOProtect_End(targetProcess);
	}
	std::string detectProcess_NoInject(PROCESSENTRY32 targetProcess) {
		return TOProtect_NoInject(targetProcess);
	}
	std::string detectProcess_Injected(PROCESSENTRY32 targetProcess) {
		return TOProtect_Injected(targetProcess);
	}


	//文件查杀类API
	std::string detectFile(std::string targetFile) {
		std::string LSProtectResult = LSProtect(targetFile, LSProtectEnableSensitiveMode);
		if (LSProtectResult.find("Error") == std::string::npos && LSProtectResult.find("disVirus") == std::string::npos) { //未Error且是病毒
			return "CSafe.LSProtect." + LSProtectResult;
		}
		return "CSafe.BITProtect." + BITProtect(targetFile, BITProtectBlackWeight);
	}
	std::string detectFile_fast(std::string targetFile) {//快速检查文件
		return "CSafe.LSProtect." + LSProtect(targetFile, LSProtectEnableSensitiveMode);
	}
	void enableLSProtectSensitiveMode(void) {
		LSProtectEnableSensitiveMode = true;
	}
	void disableLSProtectSensitiveMode(void) {
		LSProtectEnableSensitiveMode = false;
	}
	void setBITProtectWeight(float BlackWeight) {
		BITProtectBlackWeight = BlackWeight;
	}
	void scanFolder(const std::string path, void (*HandleFunction)(std::string, std::string), const bool EnableFastMode = false) {//扫描文件夹
		long hFile = 0;
		struct _finddata_t fileinfo;
		std::string pathp;
		if ((hFile = _findfirst(pathp.assign(path).append("\\*").c_str(), &fileinfo)) != -1) {
			do {
				if ((fileinfo.attrib &  _A_SUBDIR)) {
					if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
						scanFolder(pathp.assign(path).append("\\").append(fileinfo.name), HandleFunction, EnableFastMode);
					}
				} else {
					std::string filestr = pathp.assign(path).append("\\").append(fileinfo.name);

					(EnableFastMode) ?
					HandleFunction(filestr, detectFile_fast(filestr))
					:
					HandleFunction(filestr, detectFile(filestr));
				}
			} while (_findnext(hFile, &fileinfo) == 0);
			_findclose(hFile);
		}
	}
};