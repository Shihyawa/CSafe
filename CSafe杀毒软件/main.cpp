/*
 * main.cpp
 * ���ļ�
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "HeadFile/Initalization.h"//���ͷ�ļ��Լ�����main����ִ��֮ǰ�ĳ�ʼ���������Ȩ������������Ȳ�������Ҫ����
#include "HeadFile/MainAntivirus.h"
#include "HeadFile/MainUI.h"

int main(int argc, char *argv[]) {
	log("Detecting CSafe whether it's been on running...");
	HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//���������ڴ�
	char buffer[MAX_MAPSIZE];
	ReadMap(Map, buffer, MAX_MAPSIZE);
	if (buffer[0] == 1) {
		log_error("CSafe is already running!");
		return 1;
	}
	buffer[0] = 1;
	WriteMap(Map, buffer, MAX_MAPSIZE);
	//��̬����
	log("Starting Dynamic Engine...");
	std::thread DynamicDetectThread(DynamicAntivirusThread);
	DynamicDetectThread.detach();
	//��̬����
	log("Starting Static Engine...");
	std::thread StaticDetectThread(FileAntivirusThread);
	StaticDetectThread.detach();
	//��������ͼ��
	log("Starting notify icon...");
	std::thread NotifyIconThread(SetNotIcon);
	NotifyIconThread.detach();
	//����������
	log("Entering main UI...");
	MainUI();//����������

	log("Main UI exit!");
	log("Exiting...");
	return 0;
}