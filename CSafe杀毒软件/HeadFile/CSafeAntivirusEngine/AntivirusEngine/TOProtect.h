/*
 * TOProtect.h
 * CSafeɱ������������TOProtect��API��װ�������һЩ������Ϊ�ļ��API��װ
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
//Windows API��⺯��
//ͨ�����һЩ����Ҫע������⼼���Ϳ��Ի�ȡ������Ϣ�����ɷ��յȼ�
//======================================//

bool HideFileDetection(PROCESSENTRY32 TargetProcess) {//����ļ��Ƿ�����
	if (IsFileHidden(GetProcessFullPath(TargetProcess)))
		return true;
	return false;
}

bool HideExeDetection(PROCESSENTRY32 TargetProcess) {//����ļ���Ŀ¼����������exe
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

		// ȷ������Ŀ¼��ֻ�г��ļ�
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	FindClose(hFind); // �ر��������
	return false;
}

bool HideDllDetection(PROCESSENTRY32 TargetProcess) {//����ļ���Ŀ¼����������dll
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

		// ȷ������Ŀ¼��ֻ�г��ļ�
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	FindClose(hFind); // �ر��������
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
//DLLע�벿�ּ�⺯��
//ͨ��DLLע�����һ�����̵ķ���
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

	//���Ϊʲô�Ҳ��Լӿǲ����ĵ����©ɱ���Ż���
	//��ΪLSProtect����Ե�������ص��Ż���
	//����ܻ�˵�ȼ�ȫ����1���᲻����
	//ù�ţ�˭�Һó��򿪾־͸���ôը�ѵĶ���
	std::vector<std::string> RiskFunctions = {//�������յȼ�����һ����ɱ
		"WinStationTerminateProcess",//��������
		"NtTerminateProcess",//��������
		"ZwTerminateProcess",//��������
		"PsTerminateProcess",//��������
		"PspTerminateProcess",//��������
		"PspTerminateThreadByPoint",//��������
		"PspExitThread",//��������
		"LoadLibraryA",//DLLע��
		"LoadLibraryW",//DLLע��
		"GetProcAddress",//DLLע��
		"ExitProcess",//ע��������̵Ĵ���
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
		//�ڷ��صĺ������ҵ��˿����з��յĺ���
		if (strBuffer.find(RiskFunctions[i]) != std::string::npos) {
			++RiskLevel;
		}
	}

	if (RiskLevel >= 1) { //��Ϊ����������ٳ�������������������ֻҪ��һ��ƥ���ֱ�ӷ���true
		return true;
	}
	return false;
}

bool OpenProcessDetection(PROCESSENTRY32 TargetProcess) {
	HANDLE CreateFileHandle = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, TargetProcess.th32ProcessID);
	char buffer[MAX_MAPSIZE] = {0};
	ReadMap(CreateFileHandle, buffer, sizeof(buffer));
	std::string strBuffer = buffer;

	if (std::string(buffer).find("-1") != std::string::npos || std::string(buffer).find(std::to_string(GetCurrentProcessId())) != std::string::npos) { //��⵽Ԥ���Σ�ս��̻��ߵ�ǰɱ�����
		return true;
	}

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return false;
	}
	// ��ʼ�� PROCESSENTRY32 �ṹ��
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	// ��ȡ��һ�����̵���Ϣ
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return false;
	}
	// �������н���
	do {
		if (std::string(pe32.szExeFile).find("explorer.exe") != std::string::npos ||
		        std::string(pe32.szExeFile).find("winlogon.exe") != std::string::npos ||
		        std::string(pe32.szExeFile).find("cmd.exe") != std::string::npos) {//��exe���յ�
			if (std::string(buffer).find(std::to_string(pe32.th32ProcessID)) != std::string::npos) { //���������̳��Է�������Щ�����Ľ���
				CloseHandle(hProcessSnap);
				return true;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
	// �رվ��
	CloseHandle(hProcessSnap);

	return false;
}



//======================================//
//ע����API
//======================================//

//��ʼ��TOProtect���棬ִ��DLLע�룬����true˵��ע��ɹ�������false˵��ע��ʧ��(����һЩ�����Ľ�����˵����ν)
//DLLPath����ʡ�ԣ�����������false��������������DLLע���������Կɼ�������
bool TOProtect_InitInject(PROCESSENTRY32 TargetProcess, std::string DLLPath = nullptr) {
	return InjectDLL(TargetProcess.th32ProcessID, DLLPath.c_str());
}
void TOProtect_EndInject(PROCESSENTRY32 TargetProcess) {//����ĳһ�����̵Ĺ����ڴ�
	HANDLE Map = CreateMap("toMap_bFlag", MAX_MAPSIZE, TargetProcess.th32ProcessID);//���������ڴ�
	const char *bFlagBuffer = std::to_string(TargetProcess.th32ProcessID).data();
	WriteMap(Map, bFlagBuffer, strlen(bFlagBuffer) + 1);//д�빲���ڴ�

	const char ClearBuffer[MAX_MAPSIZE] = {0};//�������һ�¹����ڴ������
	HANDLE toMap_CreateFile = CreateMap("toMap_CreateFile", MAX_MAPSIZE, TargetProcess.th32ProcessID);//ɾ�������ڴ�
	WriteMap(toMap_CreateFile, ClearBuffer, strlen(ClearBuffer) + 1);//д�빲���ڴ�
	DeleteMap(toMap_CreateFile);
	HANDLE toMap_GetProcAddress = CreateMap("toMap_GetProcAddress", MAX_MAPSIZE, TargetProcess.th32ProcessID);//ɾ�������ڴ�
	WriteMap(toMap_GetProcAddress, ClearBuffer, strlen(ClearBuffer) + 1);//д�빲���ڴ�
	DeleteMap(toMap_GetProcAddress);
	HANDLE toMap_OpenProcess = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, TargetProcess.th32ProcessID);//ɾ�������ڴ�
	WriteMap(toMap_OpenProcess, ClearBuffer, strlen(ClearBuffer) + 1);//д�빲���ڴ�
	DeleteMap(toMap_OpenProcess);
}


//======================================//
//������ڲ�API
//======================================//

//�ڲ�API������������յȼ��ַ��������ĵȼ�����������޸�
inline std::string strGenerateRiskLevel(short RiskLevel) {
	if (RiskLevel <= 0) { //RiskLevel <= 0���޷���
		return "Risk.NoRisk";
	} else if (RiskLevel >= 1 && RiskLevel <= 3) { //1 <= RiskLevel <= 3���ͷ���
		return "Risk.LowRisk";
	} else if (RiskLevel >= 4 && RiskLevel <= 6) { //4 <= RiskLevel <= 6���еȷ���
		return "Risk.MidRisk";
	} else if (RiskLevel >= 7 && RiskLevel <= 8) { //7 <= RiskLevel <= 8��Σ��
		return "Risk.HighRisk";
	}

	//RiskLevel > 8(RiskLevel >= 9)������
	return "Risk.Malware";
}

//�����ʵ���ڲ�API�ģ������ڷ�ע��ģʽ�»�ȡ���̵ķ��յȼ�������ʵ�ʵ����õ���Ӧ���Ƿ����ַ���
inline short TOProtect_NoInject_LEVEL(PROCESSENTRY32 TargetProcess) {
	short RiskLevel = 0;

	//����Windows API�Ķ�̬���
	(AdminDetection(TargetProcess)) ? RiskLevel += 2 : 0;//FirstRiskLevel�ڵ�һ�׶μ��֮����Զ���գ������⼸����Ŀ����ٶȽϿ����ڽ��̸�������ʱ����ܼ�⵽�ĸ��ʲ��ߣ����Եڶ���ѭ�����ټ�һ��
	(IEFODetection(TargetProcess)) ? RiskLevel += 8 : 0;
	(StartItemDetection(TargetProcess)) ? RiskLevel += 3 : 0;

	(HideFileDetection(TargetProcess) ||
	 HideExeDetection(TargetProcess) ||
	 HideDllDetection(TargetProcess)) ? RiskLevel += 7 : 0;//�������ϵ�һ��(��Ϊ�������ơ����յȼ���ͬ)��ͬʱ��Ϊ�ļ�����������ֻ����һ�Σ������SecondRiskLevel�������㣬�̳���ȥ

	return RiskLevel;
}

//ע��ģʽ�»�ȡ���̷��յȼ�
inline short TOProtect_Injected_LEVEL(PROCESSENTRY32 TargetProcess) {
	short RiskLevel = 0;

	//����ע�����DLL�Ķ�̬����
	(MBRDetection(TargetProcess)) ? RiskLevel += 9 : 0;
	(PEDetection(TargetProcess)) ? RiskLevel += 8 : 0;
	(AutoRunDetection(TargetProcess)) ? RiskLevel += 6 : 0;
	(SettingFilesDetection(TargetProcess)) ? RiskLevel += 4 : 0;
	(RiskFunctionsDetection(TargetProcess)) ? RiskLevel += 8 : 0;
	(OpenProcessDetection(TargetProcess)) ? RiskLevel += 7 : 0;

	return RiskLevel;
}


//======================================//
//���API
//======================================//

//��ݼ��һ�����̵ķ��յȼ�������Ҫע��
std::string TOProtect_NoInject(PROCESSENTRY32 TargetProcess) {
	return strGenerateRiskLevel(TOProtect_NoInject_LEVEL(TargetProcess));
}

std::string TOProtect_Injected(PROCESSENTRY32 TargetProcess) {
	return strGenerateRiskLevel(TOProtect_Injected_LEVEL(TargetProcess));
}

//��ʼע��
bool TOProtect_Begin(PROCESSENTRY32 TargetProcess, std::string DLLPath) {
	if (access(DLLPath.c_str(), F_OK) == -1) {
		return false;
	}
	return TOProtect_InitInject(TargetProcess, DLLPath);
}

//����ע�벢���ط��յȼ�
std::string TOProtect_End(PROCESSENTRY32 TargetProcess) {
	short RiskLevel = 0;

	//����Windows API�Ķ�̬���
	RiskLevel += TOProtect_NoInject_LEVEL(TargetProcess);

	//����ע�����DLL�Ķ�̬����
	RiskLevel += TOProtect_Injected_LEVEL(TargetProcess);

	TOProtect_EndInject(TargetProcess);//���ù����ڴ�

	return strGenerateRiskLevel(RiskLevel);
}

//��ʾ��
//ע����д��"Խ��"����ɱ��������Ϊ�����жϵ��������󣬻��ߵȼ����ֲ�����������һ�������ϳ���Σ����Ϊ�ĵȼ��������
//���籾��Σ�յȼ�Ӧ����6��������ɱ������ȴ������9�����������ϵķ��յȼ��������ⲻ����Ϊ������ߴ���������ˣ�
//����ɱ���������Եȼ����ӵ����û��߸���Ϊ�ĵȼ����岻������ô���Ǿͳ�֮Ϊ"Խ��"��

//��ǰ�汾���յȼ�����ճ̶ȶ��ձ�
//0�����޷���
//1-3�����ͷ���
//4-6�����߷���
//7-8����Σ��
//9�������ϣ�����

//�����ǲ�ͬ���ճ̶Ƚ������Ĵ���
//�޷��գ����账��
//�ͷ���-�߷��գ�������򲢼�¼
//Σ��-�������������̲�����

//ע�⣺���޷������⣬�������������Ӧ�ø�֪�û���
//����Ӧ�����û����������Ĵ���ʽ(��ɾ���ļ��������ļ������账����Ӱ������ȴ���ʽ)��