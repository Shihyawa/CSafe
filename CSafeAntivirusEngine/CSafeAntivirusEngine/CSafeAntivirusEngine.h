/*
 * CSafeAntivirusEngine.h
 * CSafeɱ��������ͷ�ļ�����װ��һЩ��������ֱ�ӵ��õĲ���API
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <vector>
#include <string>
#include <fstream>
#include "CSafeAntivirusEngineHeadFile.h"

//��ɱ����
#include "AntivirusEngine/TOProtect.h"//��̬����
#include "AntivirusEngine/LSProtect.h"//�����̬����
#include "AntivirusEngine/BITProtect.h"//PE�ļ���ʶ���ַ�����̬����

namespace CSafeAntivirusEngine {
	//���ñ���
	static bool LSProtectEnableSensitiveMode = true;//Ĭ�����ø�����
	static float BITProtectBlackWeight = 1.0F;


	//���ߺ���
	std::string getProcessPath(DWORD dwProcessId) {//��ȡ����·��
		char cProcessPath[MAX_PATH];
		if (GetProcessPath(dwProcessId, cProcessPath)) {
			return cProcessPath;
		} else {
			return "Error";
		}
	}
	bool getNewProcess(PROCESSENTRY32 &targetProcess) {//��ȡ�������Ľ��̣�������������Ľ����򽫽�����Ϣ����targetProcess������true����֮����false
		return GetProcessListStart(targetProcess);
	}


	//���̲�ɱ��API
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


	//�ļ���ɱ��API
	std::string detectFile(std::string targetFile) {
		std::string LSProtectResult = LSProtect(targetFile, LSProtectEnableSensitiveMode);
		if (LSProtectResult.find("Error") == std::string::npos && LSProtectResult.find("disVirus") == std::string::npos) { //δError���ǲ���
			return "CSafe.LSProtect." + LSProtectResult;
		}
		return "CSafe.BITProtect." + BITProtect(targetFile, BITProtectBlackWeight);
	}
	std::string detectFile_fast(std::string targetFile) {//���ټ���ļ�
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
	void scanFolder(const std::string path, void (*HandleFunction)(std::string, std::string), const bool EnableFastMode = false) {//ɨ���ļ���
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