/*
 * MainAntivirus.h
 * ������ɱ��ģ��ķ�װ
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"
#include "AntivirusSoftHeadFile/VirusHandleHeadFile.h"
#include "AntivirusSoftHeadFile/Log.h"//�����������������������ļ�ͷ��˳��˭Ҫ�ǻ����Ҹ�����
#include "AntivirusSoftHeadFile/MBR.h"

void VirusHandle(PROCESSENTRY32 processInfo, std::string riskLevel) {
	if (riskLevel.find("NoRisk") != std::string::npos || riskLevel.find("LowRisk") != std::string::npos) {
		return;
	}
	char CSafePath[MAX_PATH] = {0};//CSafe��Ŀ¼
	GetModuleFileName(NULL, CSafePath, MAX_PATH);//��ȡ����ȫ·��
	(_tcsrchr(CSafePath, _T('\\')))[0] = 0;//ɾ���ļ�����ֻ���·�� �ִ�

	if (calculate_file_sha256(std::string(CSafePath) + "\\CSafeData\\MBRData.data") != calculate_file_sha256("\\\\.\\PhysicalDrive0")) { // ���ʱ�����Ҫ�����޸�MBR��
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
	//��Ϊ��̬��ɱ������ǿ�ˣ����Եͷ��ս��̾Ͳ�������
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
		outStr += "���ָ߷��ս��̲���ͣ��\n���յȼ���";
		outStr += riskLevel;
		outStr += "\n����PID�룺";
		outStr += std::to_string(processInfo.th32ProcessID);
		outStr += "\n����ȫ·����";
		outStr += filePath;
		outStr += "\n�Ƿ���\n���\"��\"�����Ὣ������룬���\"��\"�������ͷų�����Ӱ��������⣬���\"ȡ��\"�������ͷų��򲢲��账��\n������ʹ��\"release\"�����ͷ��Ѹ����ļ���\n���������뱣�����Ľ��Ȳ��Ҿ���رոó����Է�δԤ�ϵķ��յȼ�������";
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
		outStr += "����Σ�ս��̲�������\n���յȼ���";
		outStr += riskLevel;
		outStr += "\n����PID�룺";
		outStr += std::to_string(processInfo.th32ProcessID);
		outStr += "\n����ȫ·����";
		outStr += filePath;
		outStr += "\n�Ƿ���\n���\"��\"�����Ὣ������룬���\"��\"������Ϊ������Ӱ��������⣬���\"ȡ��\"�����᲻�账��������ʹ��\"release\"�����ͷ��Ѹ����ļ���";
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
		outStr += "���ֲ������򲢸��룡\n���յȼ���";
		outStr += riskLevel;
		outStr += "\n����PID�룺";
		outStr += std::to_string(processInfo.th32ProcessID);
		outStr += "\n����ȫ·����";
		outStr += filePath;
		outStr += "\n�Ƿ���\n���\"��\"�����Ὣ�������ͣ���ڸ����������\"��\"�������ͷų�����Ӱ��������⣬���\"ȡ��\"�������ͷų��򲢲��账��������ʹ��\"release\"�����ͷ��Ѹ����ļ���";
	} else {
		return;
	}
	char *MsgOutData = new char[strlen(outStr.c_str()) + 1];
	strcpy(MsgOutData, outStr.c_str());
	int MsgRs = MessageBox(NULL, MsgOutData, "CSafe", MB_SETFOREGROUND | MB_ICONWARNING | MB_YESNOCANCEL);
	delete[] MsgOutData;

	if (MsgRs == IDNO) {//�ͷ��ļ�
		if (riskLevel.find("Malware") != std::string::npos) {
			if (!ReleaseFile(hash, filePath)) { //�ͷ��ļ�
				log_error("Failed to release file!");
			}
		} else if (riskLevel.find("MidRisk") != std::string::npos) {
			if (!PauseProcess(processInfo.th32ProcessID, false)) {
				log_error("Failed to continue the process!");
			}
		}
		Sleep(64);
		WriteList(filePath);
	} else if (MsgRs == IDYES) { //ɱ���ļ�
		if (riskLevel.find("MidRisk") != std::string::npos) {
			if (!ForceTerminateProcess(processInfo.th32ProcessID)) {
				log_error("Failed to terminate process!");
			}
			Sleep(64);
		}
		IsolateFile(filePath);
	} else if (MsgRs == IDCANCEL) { //���账��
		if (riskLevel.find("Malware") != std::string::npos) {//ȷ�ϲ�������Ϊ��⣩�ĳ���
			if (!ReleaseFile(hash, filePath)) { //�ͷ��ļ�
				log_error("Failed to release file!");
			}
		} else if (riskLevel.find("MidRisk") != std::string::npos) { //��ͣ���������
			if (!PauseProcess(processInfo.th32ProcessID, false)) {
				log_error("Failed to continue the process!");
			}
		}
		//���������ͷ��ա��߷��գ����账��
	}
}