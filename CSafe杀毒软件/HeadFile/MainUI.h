/*
 * MainUI.h
 * ������ҪUI����Ķ���
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <conio.h>
#include <iostream>
#include "MainAntivirus.h"
#include "AntivirusSoftHeadFile/Log.h"
#include "VirusHandle.h"
#include "AntivirusSoftHeadFile/MBR.h"
#include "AntivirusSoftHeadFile/Console.h"
#include <Windows.h>
#include <tlhelp32.h>
#include "AntivirusSoftHeadFile/ProcessHandle.h"
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)//��ⰴ��

//��ȡ�����ڴ�ռ��
size_t GetProcessMemorySize(DWORD processID) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (hProcess == NULL) {
		return 0;
	}

	PROCESS_MEMORY_COUNTERS pmc;
	if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
		size_t size = pmc.WorkingSetSize;
		CloseHandle(hProcess);
		return size;
	}

	CloseHandle(hProcess);
	return 0;
}

static volatile bool leftButton = false, rightButton = false;

void HideUI(void) {
	log("Hiding main window...");
	Sleep(500);//���û�ע�⵽���
	HWND MainHwnd = GetConsoleWindow();
	ShowWindow(MainHwnd, SW_HIDE);
	log("Main window is hidden!"/*, " You can use \"Ctrl + Alt + C\" to wake up the window!"*/);
//	MessageBox(NULL, "���������أ�������ʹ��Ctrl + Alt + C���ٳ����壡", "CSafe��ȫ", MB_OK);

	while (true) {
		if (KEY_DOWN(VK_CONTROL)) {//�����ʾ�����ݼ�
			if (KEY_DOWN(VK_MENU)) {
				if (KEY_DOWN(VK_C)) {
					log("Wake up main window...");
					ShowWindow(MainHwnd, SW_SHOW);
					return;
				}
			}
		}
		if (rightButton) {
			rightButton = false;
		}
		if (leftButton) {
			leftButton = false;
			log("Wake up main window...");
			ShowWindow(MainHwnd, SW_SHOW);
			return;
		}
		Sleep(100);//����Sleep��Ӱ��������ɱ����Ϊ�Ƿ��̵߳�
	}
}

//����ͼ�����Ϣ����
void HandleTrayMessage(HWND hWnd, UINT message) {
	switch (message) {
		case WM_LBUTTONUP://�������������ͼ��
			leftButton = true;
			break;

		case WM_RBUTTONUP:
			rightButton = true;
			break;

		default:
			break;
	}
}

//����ͼ��
LRESULT CALLBACK WindowProcedure(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	switch (message) {
		case WM_USER + 1: // ����ͼ����Ϣ
			HandleTrayMessage(hWnd, lParam);
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}
//��������ͼ��(ע��������������Ҫ�����߳�ά��)
void SetNotIcon() {
	HINSTANCE hInstance     = GetModuleHandle(NULL);
	const char CLASS_NAME[] = "CSafe";

	WNDCLASSEX wc = {};

	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WindowProcedure;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszClassName = CLASS_NAME;

	if (!RegisterClassEx(&wc)) {
		return;
	}

	// �������ش���
	HWND hWnd = CreateWindowExA(
	                WS_EX_TOOLWINDOW,
	                CLASS_NAME,
	                "CSafe Hidden Window",
	                WS_POPUP,
	                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
	                NULL, NULL, hInstance, NULL
	            );

	if (hWnd == NULL) {
		return;
	}

	ShowWindow(hWnd, SW_HIDE); // ���ش���

	// ����ϵͳ����ͼ��
	NOTIFYICONDATA nid = {};
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.hWnd = hWnd;
	nid.uID = 1;
	nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	nid.uCallbackMessage = WM_USER + 1;
	nid.hIcon = (HICON)LoadImageA(NULL, "CSafeData\\CSafe_Small.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
	strcpy(nid.szTip, "CSafe");

	Shell_NotifyIcon(NIM_ADD, &nid); // ��������ͼ��

	MSG msg = {};
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	Shell_NotifyIcon(NIM_DELETE, &nid); // ɾ������ͼ��
	UnregisterClass(CLASS_NAME, hInstance);

	return;
}

//����ɨ�赽�Ĳ���
void Handler(std::string path, std::string riskLevel) {
	IsConsoleOutOK = true;//������־���
	log("Scanning file: ", path);
	if (riskLevel.find("Error") == std::string::npos && riskLevel.find("disVirus") == std::string::npos && !WhiteList(path)) {
		log("\n================================\n",
		    "Scanned a virus file! \nFile path: ", path, "\n",
		    "Virus type: ", riskLevel, "\n",
		    "================================\n");
		IsolateFile(path);
	}
	IsConsoleOutOK = false;//�ر���־���
}

void MainUI(bool enableNoUI = false) {
	log("================================================");
	log("Welcome to the CSafe security software!");
	log("Copyright (C) 2022 Ternary_Operator");
	log("CSafe website address: https://csafe.pages.dev/");
	log("================================================");
commandline:
	IsConsoleOutOK = true;
	log("Press \"c\" to enter the console, type \"help\" in the console to get help.");
	if (fopen("CSafeData\\isFirstRunned", "r") != NULL) {
		HideUI();
	} else {
		FILE *fp = fopen("CSafeData\\isFirstRunned", "w+");
		fclose(fp);
	}
	while (true) {
		if (!_kbhit()) {
			if (leftButton) { //�������������ʾUI
				leftButton = false;
			}
			if (rightButton) { //�Ҽ�������������UI
				leftButton = false;
				HideUI();
			}
			continue;
		}
		char CtrlChar = getch();
		if (CtrlChar != 'c' && CtrlChar != 'C')
			continue;
		IsConsoleOutOK = false;//�ر���־���
		log("Enter the console...");
		while (true) {
			IsConsoleOutOK = false;//�ر���־���
			std::string command;
			std::cout << "[CSafe Console]$ >.";
			std::cin >> command;
			std::cin.ignore();
			log("Run command:", "\"", command, "\"");
			if (command == "help" || command == "HELP") {
				std::cout << "help---------------------Get help." << std::endl;
				std::cout << "exitcm-------------------Exit the CSafe console." << std::endl;
				std::cout << "exit---------------------Exit the CSafe Antivirus Software." << std::endl;
				std::cout << "=======================AntivirusEngine commands=======================" << std::endl;
				std::cout << "start--------------------Start antivirus engine." << std::endl;
				std::cout << "stop---------------------Stop antivirus engine." << std::endl;
				std::cout << "setting------------------Set the antivirus engine settings." << std::endl;
				std::cout << "save---------------------Save the settings that you set." << std::endl;
				std::cout << "scan---------------------Scan a folder" << std::endl;
				std::cout << "fscan--------------------Do a quick scan for a folder" << std::endl;
				std::cout << "rembr--------------------Restore MBR startup information." << std::endl;
				std::cout << "addlist------------------Add a new whitelist exception." << std::endl;
				std::cout << "whitelist----------------View whitelist exceptions." << std::endl;
				std::cout << "release------------------Release the file from the isolated zone." << std::endl;
				std::cout << "hide---------------------Hide Main Window." << std::endl;
				std::cout << "detectproc---------------Get the risk type of a process." << std::endl;
				std::cout << "detectfile---------------Detect a target file." << std::endl;
				std::cout << "========================System Control commands=======================" << std::endl;
				std::cout << "list---------------------List all processes." << std::endl;
				std::cout << "getpath------------------Get the path of a process." << std::endl;
				std::cout << "topid--------------------Get the process id of a process with its' name" << std::endl;
				std::cout << "kill---------------------Kill a process even if it's not a virus." << std::endl;
				std::cout << "remove-------------------Forcefully delete a file (requires restart)." << std::endl;
				std::cout << "lock---------------------Lock a process even if it's not a virus." << std::endl;
				std::cout << "unlock-------------------Unlock a process." << std::endl;
				std::cout << "hash---------------------Get SHA-256 hash code from a file." << std::endl;
			} else if (command == "exitcm" || command == "EXITCM") {
				goto commandline;
			} else if (command == "exit" || command == "EXIT") {
				saveSetting();
				return;
			} else if (command == "start" || command == "START") {
				std::cout << "What engine do you wanna start? (enter 1 to start the dynamic engine, 2 to start the static engine, 3 to start all of the engine): ";
				int code;
				std::cin >> code;
				std::cin.ignore();
				IsConsoleOutOK = true;//������־���
				if (code == 1) {
					log("Start the dynamic engine.");
					EnableDynamicEngine = true;
				} else if (code == 2) {
					log("Start the static engine.");
					EnableStaticEngine = true;
				} else if (code == 3) {
					log("Start all of the antivirus engine.");
					EnableDynamicEngine = true, EnableStaticEngine = true;
				} else {
					log_error("Unknown code!");
				}
				IsConsoleOutOK = false;//�ر���־���
			} else if (command == "stop" || command == "STOP") {
				std::cout << "What engine do you wanna stop? (enter 1 to stop the dynamic engine, 2 to stop the static engine, 3 to stop all of the engine): ";
				int code;
				std::cin >> code;
				std::cin.ignore();
				IsConsoleOutOK = true;//������־���
				if (code == 1) {
					log("Stop the dynamic engine.");
					EnableDynamicEngine = false;
				} else if (code == 2) {
					log("Stop the static engine.");
					EnableStaticEngine = false;
				} else if (code == 3) {
					log("Stop all of the antivirus engine.");
					EnableDynamicEngine = false, EnableStaticEngine = false;
				} else {
					log_error("Unknown code!");
				}
				IsConsoleOutOK = false;//�ر���־���
			} else if (command == "setting" || command == "SETTING") {
				std::cout << "What engine do you wanna edit? Enter 1 to edit the TOProtect engine(dynamic), enter 2 to edit the BITProtect & LSProtect engine(static): ";
				int mod;
				std::cin >> mod;
				std::cin.ignore();
				IsConsoleOutOK = true;//������־���
				if (mod == 1) {
					IsConsoleOutOK = false;//������־���
					std::cout << "Enter 1 to enable DLL injection in detection, 2 to disable DLL injection in detection: ";
					int code;
					std::cin >> code;
					std::cin.ignore();
					IsConsoleOutOK = true;//������־���
					if (code == 1) {
						log("Enable the DLL injection.");
						EnableDLLInject = true;
					} else if (code == 2) {
						log("Disable the DLL injection.");
						EnableDLLInject = false;
					}
				} else if (mod == 2) {
					IsConsoleOutOK = false;//������־���
					std::cout << "Enter 1 to enable high sensitive mode with LSProtect engine, 2 to disable high sensitive mode with LSProtect engine, 3 to set the sensitive value with BITProtect engine, 4 to enable/disable LSProtect, 5 to set the sensitive value with WhiteProtect engine: ";
					int code;
					std::cin >> code;
					std::cin.ignore();
					IsConsoleOutOK = true;//������־���
					if (code == 1) {
						log("Enable the LSProtect high sensitive mode.");
						CSafeAntivirusEngine::enableLSProtectSensitiveMode();
					} else if (code == 2) {
						log("Disable the LSProtect high sensitive mode.");
						CSafeAntivirusEngine::disableLSProtectSensitiveMode();
					} else if (code == 3) {
						IsConsoleOutOK = false;//������־���
						std::cout << "Please enter the sensitive value with BITProtect engine(float type, default 1.0, more killed with greater, less killed with lesser, set 0.0 to disable this engine): ";
						float sensitiveValue;
						std::cin >> sensitiveValue;
						std::cin.ignore();
						IsConsoleOutOK = true;
						log("Set the BITProtect sensitive value with ", sensitiveValue);
						CSafeAntivirusEngine::setBITProtectWeight(sensitiveValue);
					} else if (code == 4) {
						if (CSafeAntivirusEngine::EnableLSProtect) {
							log("Disable the LSProtect.");
							CSafeAntivirusEngine::EnableLSProtect = false;
						} else {
							log("Enable the LSProtect.");
							CSafeAntivirusEngine::EnableLSProtect = true;
						}
					} else if (code == 5) {
						IsConsoleOutOK = false;//������־���
						std::cout << "Please enter the sensitive value with WhiteProtect engine(float type, default 1.0, less killed with greater, set 0.0 to disable this engine): ";
						double sensitiveValue;
						std::cin >> sensitiveValue;
						std::cin.ignore();
						IsConsoleOutOK = true;
						log("Set the WhiteProtect sensitive value with ", sensitiveValue);
						CSafeAntivirusEngine::WhiteProtectSensitiveValue = sensitiveValue;
					}
				} else {
					log_error("Unknown engine!");
				}
				IsConsoleOutOK = false;//�ر���־���
			} else if (command == "save" || command == "save") {
				saveSetting();
			} else if (command == "scan" || command == "SCAN") {
				std::cout << "Please enter the path of scanning: " << std::endl;
				std::string scanpath;
				std::getline(std::cin, scanpath);
				std::cout << "Initalizing, please wait..." << std::endl;
				CSafeAntivirusEngine::scanFolder(scanpath, Handler);
			} else if (command == "fscan" || command == "FSCAN") {
				std::cout << "Please enter the path of scanning: " << std::endl;
				std::string scanpath;
				std::getline(std::cin, scanpath);
				std::cout << "Initalizing, please wait..." << std::endl;
				CSafeAntivirusEngine::scanFolder(scanpath, Handler, true);
			} else if (command == "rembr" || command == "REMBR") {
				int hand = MessageBox(NULL, "ȷ�ϻָ�MBR��\n�˲��������棡", "CSafe", MB_YESNO);
				if (hand == IDYES) {
					bool doOK = ReMBR();
					IsConsoleOutOK = true;//������־���
					log("Restore the MBR! ", doOK);
					IsConsoleOutOK = false;//�ر���־���
				}
			} else if (command == "addlist" || command == "ADDLIST") {
				std::cout << "Please enter the file path: " << std::endl;
				std::string path;
				std::getline(std::cin, path);

				bool doOK = WriteList(path);

				IsConsoleOutOK = true;
				if (doOK) {
					log("Add successfully!");
				} else {
					log("Add failed!");
				}
				IsConsoleOutOK = false;
			} else if (command == "whitelist") {
				std::ifstream WhiteList("CSafeData\\WhiteList.csdata");
				std::string LineData;
				while (std::getline(WhiteList, LineData)) {
					std::cout << LineData << std::endl;
				}
			} else if (command == "release") {
				std::cout << "There is the isolated numbers and times of the isolated files: " << std::endl;
				std::vector<std::pair<std::string, std::string>> FileList = ExportIsolatedFileList();
				for (int i = 0; i < FileList.size(); ++i) {
					std::cout << i << "     " << FileList[i].first << "     " << FileList[i].second << std::endl;
				}
				std::cout << "Please enter the number of the file: ";
				int num;
				std::cin >> num;
				std::cin.ignore();
				std::cout << "Please enter the file path of released file: " << std::endl;
				std::string path;
				std::getline(std::cin, path);
				IsConsoleOutOK = true;
				log("Releasing file ", ("IsolatedZone\\" + FileList[num].first + "_" + FileList[num].second + ".isofile"), " to ", path);
				IsConsoleOutOK = false;
				bool doOK = ReleaseFile(calculate_file_sha256("IsolatedZone\\" + FileList[num].first + "_" + FileList[num].second + ".isofile"), path);
				if (!doOK) {
					IsConsoleOutOK = true;//������־���
					log("Release failed!");
					IsConsoleOutOK = false;//�ر���־���
				} else {
					IsConsoleOutOK = true;//������־���
					log("Release done!");
					IsConsoleOutOK = false;//�ر���־���
				}
			} else if (command == "hide") {
				IsConsoleOutOK = true;//������־���
				HideUI();
				goto commandline;//Ĭ��Ϊ��ʾ����֮���˳������н���
			} else if (command == "detectproc") {
				std::cout << "Please enter the ID of the process(PID code): ";
				DWORD pid;
				std::cin >> pid;
				std::cin.ignore();
				PROCESSENTRY32 pe = PIDtoEntry32(pid);
				if (pe.dwSize == 0) {
					IsConsoleOutOK = true;//������־���
					log("Failed to get process handle! Please check your process id for input!");
					IsConsoleOutOK = false;//�ر���־���
					continue;
				}
				CSafeAntivirusEngine::detectProcess_Begin(pe, "CSafeData\\toInjectDLL.dll");
				std::string rl = CSafeAntivirusEngine::detectProcess_End(pe);
				std::cout << "Process risk level: " << rl << std::endl;
			} else if (command == "detectfile") {
				std::cout << "Please enter the path of the file(full path): ";
				std::string path;
				std::getline(std::cin, path);
				std::cout << "Detecting..." << std::endl;
				std::string riskLevel = CSafeAntivirusEngine::detectFile(path);
				std::cout << "Risk type: " << riskLevel << std::endl;
			} else if (command == "list") {
				PrintOfWidth(32, "������");
				PrintOfWidth_Right(8, "����PID");
				PrintOfWidth_Right(8, "�߳���");
				PrintOfWidth_Right(8, "���ȼ�");
				PrintOfWidth_Right(12, "��ռ�ڴ�");
				printf("\n");

				for (int i = 0; i < 68; i++) //30+10+8+8+10=66
					printf("=");

				printf("\n");
				HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};

				while (Process32Next(hProcessSnap, &process)) {
					PrintOfWidth(32, process.szExeFile);
					PrintOfWidth_Right(8, to_string(process.th32ProcessID).c_str());
					PrintOfWidth_Right(8, to_string(process.cntThreads).c_str());
					PrintOfWidth_Right(8, to_string(process.pcPriClassBase).c_str());
					string Temp = to_string(int(double((double)GetProcessMemorySize(process.th32ProcessID) / 1024.0))) + " KB";
					PrintOfWidth_Right(12, Temp.c_str());
					printf("\n");
				}

				printf("ע�������޷����ʵĽ������ڴ�ռ�ô�Сһ�����ݿ���Ϊ0��\n");
			} else if (command == "getpath") {
				std::cout << "Please enter the id of the target process(PID): ";
				DWORD pid;
				std::cin >> pid;
				std::cin.ignore();
				PROCESSENTRY32 pe32 = PIDtoEntry32(pid);
				if (pe32.dwSize == 0) {
					IsConsoleOutOK = true;//������־���
					log("Failed to get process handle! Please check your process id for input!");
					IsConsoleOutOK = false;//�ر���־���
					continue;
				}
				std::cout << "Process path: " << GetProcessFullPath(pe32) << std::endl;
			} else if (command == "topid") {
				std::cout << "Please enter the name of the process: ";
				std::string name;
				std::cin >> name;
				std::cin.ignore();

				std::cout << "Process id: " << NameToPID(name.c_str()) << std::endl;
			} else if (command == "kill") {
				std::cout << "Please enter the process id that you wanna terminate: ";
				DWORD dwProcessId;
				std::cin >> dwProcessId;
				std::cin.ignore();
				bool res = ForceTerminateProcess(dwProcessId);
				IsConsoleOutOK = true;//������־���
				log("Kill: ", res);
				IsConsoleOutOK = false;//�ر���־���
			} else if (command == "remove") {
				std::cout << "Please enter the file path that you wanna remove: ";
				std::string filePath;
				std::getline(std::cin, filePath);
				bool res = forceRemove(filePath);
				IsConsoleOutOK = true;//������־���
				log("Remove: ", res);
				IsConsoleOutOK = false;//�ر���־���
				std::cout << "Please reboot." << std::endl;
			} else if (command == "lock") {
				std::cout << "Please enter the process id that you wanna lock: ";
				DWORD pid;
				std::cin >> pid;
				std::cin.ignore();
				bool res = PauseProcess(pid, true);
				IsConsoleOutOK = true;//������־���
				log("Lock: ", res);
				IsConsoleOutOK = false;//�ر���־���
			} else if (command == "unlock") {
				std::cout << "Please enter the process id that you wanna unlock: ";
				DWORD pid;
				std::cin >> pid;
				std::cin.ignore();
				bool res = PauseProcess(pid, false);
				IsConsoleOutOK = true;//������־���
				log("UnLock: ", res);
				IsConsoleOutOK = false;//�ر���־���
			} else if (command == "hash") {
				std::cout << "Please input target file path: ";
				std::string path;
				std::getline(std::cin, path);
				std::cout << "SHA-256 Hash code: " << calculate_file_sha256(path) << std::endl;
			} else {
				IsConsoleOutOK = true;//������־���
				log_error("Unknown command.");
				IsConsoleOutOK = false;//�ر���־���
			}
		}
		Sleep(100);//����Sleep��Ӱ��������ɱ����Ϊ�Ƿ��̵߳�
	}
}