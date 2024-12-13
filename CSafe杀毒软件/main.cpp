/*
 * main.cpp
 * 主文件
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "HeadFile/Initalization.h"//这个头文件自己会有main函数执行之前的初始化，因此提权、设置启动项等操作不需要处理
#include "HeadFile/MainAntivirus.h"
#include "HeadFile/MainUI.h"

int main(int argc, char *argv[]) {
	log("Detecting CSafe whether it's been on running...");
	HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//创建共享内存
	char buffer[MAX_MAPSIZE];
	ReadMap(Map, buffer, MAX_MAPSIZE);
	if (buffer[0] == 1) {
		log_error("CSafe is already running!");
		return 1;
	}
	buffer[0] = 1;
	WriteMap(Map, buffer, MAX_MAPSIZE);
	//动态引擎
	log("Starting Dynamic Engine...");
	std::thread DynamicDetectThread(DynamicAntivirusThread);
	DynamicDetectThread.detach();
	//静态引擎
	log("Starting Static Engine...");
	std::thread StaticDetectThread(FileAntivirusThread);
	StaticDetectThread.detach();
	//加载托盘图标
	log("Starting notify icon...");
	std::thread NotifyIconThread(SetNotIcon);
	NotifyIconThread.detach();
	//加载主界面
	log("Entering main UI...");
	MainUI();//进入主界面

	log("Main UI exit!");
	log("Exiting...");
	return 0;
}