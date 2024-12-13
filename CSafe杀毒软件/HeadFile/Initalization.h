/*
 * Initalization.h
 * 包含CSafe杀毒软件的初始化部分
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

			HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//创建共享内存
			char buffer[MAX_MAPSIZE];
			buffer[0] = 0;
			WriteMap(Map, buffer, MAX_MAPSIZE);
			DeleteMap(Map);

			return TRUE;
		}
	}
}

void DisableCloseButton() {
	HWND hWnd = GetConsoleWindow(); // 获取控制台窗口句柄
	HMENU hMenu = GetSystemMenu(hWnd, FALSE); // 获取系统菜单句柄

	if (hMenu != NULL) {
		EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED); // 禁用关闭菜单项
	}
}

char autoMainInit() {
	GetAdmin(SW_SHOW);

	LogInit();
	log("Initialization: Start init.");

	log("Initialization: Set window protect...");
	DisableCloseButton();//禁用关闭按钮(这个没法防止窗口句柄攻击结束进程，只是用来防手残的)
	SetConsoleCtrlHandler(shieldHandler, TRUE);//设置禁用Ctrl+C/Ctrl+Z快捷键结束进程

	log("Initialization: Set current directory...");
	char Name[MAX_PATH] = { 0 };
	DWORD resultGetModuleFileNameA = GetModuleFileNameA(NULL, Name, MAX_PATH);
	if (resultGetModuleFileNameA == 0) {
		log_error("Initialization: Failed to get the current path: ", GetLastError());
	}
	(_tcsrchr(Name, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串
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

	//设置窗口标题
	log("Initialization: Set window title...");
	SetConsoleTitle(TEXT("CSafe"));

	//移除快速编辑
	log("Initialization: Disable FastMake...");
	DisableFastMake();

	//加载程序设置
	log("Initialization: Loading settings...");
	if (fopen("CSafeData\\CSafeSetting.csdata", "r") == NULL) {
		log_warn("Initialization: No setting file! Create it.");
		saveSetting();
	} else {
		loadSetting();
	}

	//原本会有一个检测白名单并添加白名单的功能，但是因为有静态启发加持并且处理函数过滤了管理员进程，不易误报，因此没有加白名单

	log("Initialization: Detection MBR backup...");
	if (!fopen("CSafeData\\MBRData.data", "rb")) {
		log_warn("Initialization: MBR is not backed up! Backuping...");
		CopyMBR();
	} else {
		log("MBR has been backuped.");
	}

	return 0;
}

//利用初始化函数实现在main函数之前执行，同时可以把static去掉实现获取操作是否执行成功
static const char autoInitLoader = autoMainInit();