/*
 * Initalization.h
 * ����CSafeɱ������ĳ�ʼ������
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <tchar.h>
#include <direct.h>
#include "AntivirusSoftHeadFile/Log.h"
#include "AntivirusSoftHeadFile/Else.h"
#include "AntivirusSoftHeadFile/Authority.h"
#include "AntivirusSoftHeadFile/MBR.h"
#include "MainAntivirus.h"
#include "MainUI.h"

BOOL WINAPI shieldHandler(DWORD signal) {
	switch (signal) {
		default: {
			saveSetting();

			HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//���������ڴ�
			char buffer[MAX_MAPSIZE];
			buffer[0] = 0;
			WriteMap(Map, buffer, MAX_MAPSIZE);
			DeleteMap(Map);

			return TRUE;
		}
	}
}

void DisableCloseButton() {
	HWND hWnd = GetConsoleWindow(); // ��ȡ����̨���ھ��
	HMENU hMenu = GetSystemMenu(hWnd, FALSE); // ��ȡϵͳ�˵����

	if (hMenu != NULL) {
		EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED); // ���ùرղ˵���
	}
}

char autoMainInit() {
	GetAdmin(SW_SHOW);

	LogInit();
	log("Initialization: Start init.");

	log("Initialization: Set window protect...");
	DisableCloseButton();//���ùرհ�ť(���û����ֹ���ھ�������������̣�ֻ���������ֲе�)
	SetConsoleCtrlHandler(shieldHandler, TRUE);//���ý���Ctrl+C/Ctrl+Z��ݼ���������

	log("Initialization: Set current directory...");
	char Name[MAX_PATH] = { 0 };
	DWORD resultGetModuleFileNameA = GetModuleFileNameA(NULL, Name, MAX_PATH);
	if (resultGetModuleFileNameA == 0) {
		log_error("Initialization: Failed to get the current path: ", GetLastError());
	}
	(_tcsrchr(Name, _T('\\')))[0] = 0;//ɾ���ļ�����ֻ���·�� �ִ�
	log("Initialization: Current directory: ", Name);
	_chdir(Name);
	_chdrive(Name[0]);
	char Pathcmd[MAX_PATH];
	sprintf(Pathcmd, "cd /d %s", Name);
	system(Pathcmd);
	DWORD resultSetModuleFileNameA = SetCurrentDirectoryA(Name);
	if (resultSetModuleFileNameA == 0) {
		log_error("Initialization: Failed to set the current path: ", GetLastError());
	}

	log("Initialization: Get the priviledges...");
	if (!GetDebugPrivilege()) {
		log_error("Initialization: Failed to get the privilege!");
	}

	log("Set startup items...");
	if (!SetStart(true)) {
		log_error("Initialization: Failed to set the startup item!");
	}

	//���ô��ڱ���
	log("Initialization: Set window title...");
	SetConsoleTitle(TEXT("CSafe"));

	//�Ƴ����ٱ༭
	log("Initialization: Disable FastMake...");
	DisableFastMake();

	//���س�������
	log("Initialization: Loading settings...");
	if (fopen("CSafeData\\CSafeSetting.csdata", "r") == NULL) {
		log_warn("Initialization: No setting file! Create it.");
		saveSetting();
	} else {
		loadSetting();
	}

	//ԭ������һ��������������Ӱ������Ĺ��ܣ�������Ϊ�о�̬�����ӳֲ��Ҵ����������˹���Ա���̣������󱨣����û�мӰ�����

	log("Initialization: Detection MBR backup...");
	if (!fopen("CSafeData\\MBRData.data", "rb")) {
		log_warn("Initialization: MBR is not backed up! Backuping...");
		CopyMBR();
	} else {
		log("MBR has been backuped.");
	}

	return 0;
}

//���ó�ʼ������ʵ����main����֮ǰִ�У�ͬʱ���԰�staticȥ��ʵ�ֻ�ȡ�����Ƿ�ִ�гɹ�
static const char autoInitLoader = autoMainInit();