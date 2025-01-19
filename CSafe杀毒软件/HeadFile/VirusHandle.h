/*
 * MainAntivirus.h
 * 包含主杀毒模块的封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"
#include "AntivirusSoftHeadFile/VirusHandleHeadFile.h"
#include "AntivirusSoftHeadFile/Log.h"//万念俱灰啦，不干啦，这俩文件头的顺序谁要是换了我干死他
#include "AntivirusSoftHeadFile/MBR.h"

void VirusHandle(PROCESSENTRY32 processInfo, std::string riskLevel) {
	if (riskLevel.find("NoRisk") != std::string::npos || riskLevel.find("LowRisk") != std::string::npos) {
		return;
	}
	char CSafePath[MAX_PATH] = {0};//CSafe根目录
	GetModuleFileName(NULL, CSafePath, MAX_PATH);//获取本体全路径
	(_tcsrchr(CSafePath, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串

	if (calculate_file_sha256(std::string(CSafePath) + "\\CSafeData\\MBRData.data") != calculate_file_sha256("\\\\.\\PhysicalDrive0")) { // 这个时候就需要尝试修复MBR了
		log_warn("Found the MBR broken! Trying to fix it...");
		if (ReMBR()) {
			log_warn("Fixed successfully!");
		} else {
			log_error("Fixed failed!");
		}
	}

	std::string filePath = CSafeAntivirusEngine::getProcessPath(processInfo.th32ProcessID);
	std::string hash = calculate_file_sha256(filePath);
	if (WhiteList(filePath))
		return;
	std::string outStr;
	//因为静态查杀能力增强了，所以低风险进程就不管它了
	if (riskLevel.find("MidRisk") != std::string::npos) {
		if (!PauseProcess(processInfo.th32ProcessID, true)) {
			log_error("Failed to pause the process!");
		}
		log("Found a high risk program and paused the program!",
		    "\nPath: ", filePath,
		    "\nRiskLevel: ", riskLevel,
		    "\nPID: ", processInfo.th32ProcessID,
		    "\nHash Code: ", hash
		   );
		outStr += "发现高风险进程并暂停！\n风险等级：";
		outStr += riskLevel;
		outStr += "\n进程PID码：";
		outStr += std::to_string(processInfo.th32ProcessID);
		outStr += "\n进程全路径：";
		outStr += filePath;
		outStr += "\n是否处理？\n点击\"是\"，将会将程序隔离，点击\"否\"，将会释放程序并添加白名单例外，点击\"取消\"，将会释放程序并不予处理，\n您可以使用\"release\"命令释放已隔离文件，\n但是您必须保存您的进度并且尽快关闭该程序，以防未预料的风险等级提升！";
	} else if (riskLevel.find("HighRisk") != std::string::npos) {
		if (!ForceTerminateProcess(processInfo.th32ProcessID)) {
			log_error("Failed to terminate process!");
		}
		log("Found a dangerous program and kill the program!",
		    "\nPath: ", filePath,
		    "\nRiskLevel: ", riskLevel,
		    "\nPID: ", processInfo.th32ProcessID,
		    "\nHash Code: ", hash
		   );
		outStr += "发现危险进程并结束！\n风险等级：";
		outStr += riskLevel;
		outStr += "\n进程PID码：";
		outStr += std::to_string(processInfo.th32ProcessID);
		outStr += "\n进程全路径：";
		outStr += filePath;
		outStr += "\n是否处理？\n点击\"是\"，将会将程序隔离，点击\"否\"，将会为程序添加白名单例外，点击\"取消\"，将会不予处理，您可以使用\"release\"命令释放已隔离文件！";
	} else if (riskLevel.find("Malware") != std::string::npos) {
		if (!ForceTerminateProcess(processInfo.th32ProcessID)) {
			log_error("Failed to terminate process!");
		}
		Sleep(64);
		IsolateFile(filePath);
		log("Found a virus process and kill the program and isolated!",
		    "\nPath: ", filePath,
		    "\nRiskLevel: ", riskLevel,
		    "\nPID: ", processInfo.th32ProcessID,
		    "\nHash Code: ", hash
		   );
		outStr += "发现病毒程序并隔离！\n风险等级：";
		outStr += riskLevel;
		outStr += "\n进程PID码：";
		outStr += std::to_string(processInfo.th32ProcessID);
		outStr += "\n进程全路径：";
		outStr += filePath;
		outStr += "\n是否处理？\n点击\"是\"，将会将程序继续停留在隔离区，点击\"否\"，将会释放程序并添加白名单例外，点击\"取消\"，将会释放程序并不予处理，您可以使用\"release\"命令释放已隔离文件！";
	} else {
		return;
	}
	char *MsgOutData = new char[strlen(outStr.c_str()) + 1];
	strcpy(MsgOutData, outStr.c_str());
	int MsgRs = MessageBox(NULL, MsgOutData, "CSafe", MB_SETFOREGROUND | MB_ICONWARNING | MB_YESNOCANCEL);
	delete[] MsgOutData;

	if (MsgRs == IDNO) {//释放文件
		if (riskLevel.find("Malware") != std::string::npos) {
			if (!ReleaseFile(hash, filePath)) { //释放文件
				log_error("Failed to release file!");
			}
		} else if (riskLevel.find("MidRisk") != std::string::npos) {
			if (!PauseProcess(processInfo.th32ProcessID, false)) {
				log_error("Failed to continue the process!");
			}
		}
		Sleep(64);
		WriteList(filePath);
	} else if (MsgRs == IDYES) { //杀除文件
		if (riskLevel.find("MidRisk") != std::string::npos) {
			if (!ForceTerminateProcess(processInfo.th32ProcessID)) {
				log_error("Failed to terminate process!");
			}
			Sleep(64);
		}
		IsolateFile(filePath);
	} else if (MsgRs == IDCANCEL) { //不予处理
		if (riskLevel.find("Malware") != std::string::npos) {//确认病毒（行为检测）的程序
			if (!ReleaseFile(hash, filePath)) { //释放文件
				log_error("Failed to release file!");
			}
		} else if (riskLevel.find("MidRisk") != std::string::npos) { //暂停程序了如果
			if (!PauseProcess(processInfo.th32ProcessID, false)) {
				log_error("Failed to continue the process!");
			}
		}
		//别的情况（低风险、高风险）不予处理
	}
}