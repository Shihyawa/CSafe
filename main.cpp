#include "Header/SHA256.h"      //自定义头文件，主要就是包装完的API
#include "Header/Button.h"
#include "Header/GetPower.h"
#include "Header/PrintScreen.h"
#include "Header/DeleteVirus.h"
#include "Header/ElseFunctions.h"
#include "Header/ExecuseDestoryProcess.h"
#include <cmath>     //主要头文件
#include <ctime>
#include <time.h>
#include <cstdio>
#include <string>
#include <tchar.h>
#include <fstream>
#include <cstdlib>
#include <conio.h>
#include <iostream>
#include <windows.h>
#include <algorithm>
#include <tlhelp32.h>             //检查进程用的
using namespace std;
#define cls system("cls");
#define sys system
#define VI_SMRISK 0x1E
#define VI_HIRISK 0x2E
#define VI_DANGER 0x3E
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)//检测按键


void GetInput();
char VirusData[1024] = {0};       //这个变量是全局的，为了多个程序都好用
int IfOpen = 1, IfCSafe = 0, BigSafe = 0;
time_t DelVirTime;
HWND MainHwnd;
LPCSTR TextIn, TitleIn;
UINT TypeIn;
int TypeReturn;




/*_________________________________________________________________杀毒过程所用函数_______________________________________________________________*/
bool OnFileDelete(TCHAR DeleteFile[MAX_PATH] = {0}) {                                   //移动文件到隔离区
	strftime(VirusData, sizeof(VirusData), "Data\\VirusPath\\%Y_%m_%d_%H_%S.VirusFile",
	         localtime(&DelVirTime));//将时间信息作为文件名写入变量

	if (MoveFileTo(DeleteFile, VirusData))//移动文件，用了上面那个包装好的函数
		return true;
	else
		return false;
}

/*
 *注意：这里的__WhiteList函数和__WriteList函数通常调用方式应该去掉下划线，
 *双下划线开头的这两个函数多了一个参数，USE_NAME参数，
 *这个参数为真的时候，
 *程序将会使用文件作为白名单内容
 *这个参数为假的时候，
 *程序将会使用哈希码作为白名单检测内容
 *这种情况适用于哈希码计算错误、无法打开目标文件等情况
 *为防止误报做出了重要贡献
*/

bool __WhiteList(string VirName, bool USE_NAME) {//读取白名单，有目标程序输出true，没有则输出false
	string ListName;
	string VirusName = calculate_file_sha256(VirName, USE_NAME);
	fstream WhiteList("Data\\WhiteList.VirusDat");                //打开文件

	while (getline(WhiteList, ListName)) {
		string StrVirusName = VirusName;                          //string类型

		if (StrVirusName ==
		        ListName) {    //这个一定不要改，我测了好多遍就是卡在这里了，这里只要把同类型的变量的所有可能性搓到一起枚举就可以了
			WhiteList.close();//关闭文件
			return true;//return
		}
	}

	WhiteList.close();//关闭文件
	return false;//return
}

bool __WriteList(string VirName, bool USE_NAME) {                              //写入白名单
	ofstream WhiteListFile;
	WhiteListFile.open("Data\\WhiteList.VirusDat", ios::app);//打开文件

	string VirusName = calculate_file_sha256(VirName, USE_NAME);

	if (!WhiteListFile) {//失败
		WhiteListFile.close();
		return false;
	}

	if (!__WhiteList(VirusName, USE_NAME) && !VirusName.empty())
		WhiteListFile << VirusName << endl;//写入
	WhiteListFile.close();
	return true;
}

bool WhiteList(string VirName) {//读取白名单，有目标程序输出true，没有则输出false
	char ExeName[MAX_PATH] = {0};//CSafe程序本体全路径
	GetModuleFileName(NULL, ExeName, MAX_PATH);//获取本体全路径
	if (calculate_file_sha256(ExeName, false) == calculate_file_sha256(VirName, false)) {
		return true;//如果目标文件的哈希码与当前CSafe本体的哈希码一致，那么直接屏蔽
		//P.S.因为文件的哈希码在编译的时候会变(因为文件头和属性不一样了)，所以这里要先计算一次当前文件的哈希码
	}
	return __WhiteList(VirName, true) || __WhiteList(VirName, false);
}

bool WriteList(string VirName) {                              //写入白名单
	return __WriteList(VirName, true) && __WriteList(VirName, false);
}

int GetProcessID(LPCTSTR name) {
	PROCESSENTRY32 pe;
	int id = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe))
		return 0;             //失败

	while (1) {
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (Process32Next(hSnapshot, &pe) == FALSE)
			break;

		if (strcmp(pe.szExeFile, name) == 0) {
			id = pe.th32ProcessID;
			break;
		}
	}

	CloseHandle(hSnapshot);
	return id;
}

void HandleVirus(short Type, PROCESSENTRY32 VirusProcess) {
	char MsgSaid[4096];
	TCHAR PathAndExe[4096];
	bool IsHandleProcessOK = true;
	GetProcessPath(VirusProcess.szExeFile, PathAndExe);
	if (!WhiteList(PathAndExe)) {//如果不在白名单记录范围内
		//首先设置输出语句以及对目标进程要做的操作
		if (Type == VI_SMRISK) {
			sprintf(MsgSaid,
			        "检测到可疑程序运行！\n病毒目录：%s\n警报等级：有风险\n请问是否结束目标程序？\n点击是，将会杀死目标进程并隔离，\n点击否，将会将目标程序添加白名单例外。",
			        PathAndExe);
		}
		if (Type == VI_HIRISK) {
			IsHandleProcessOK = PauseProcess(VirusProcess.th32ProcessID, true);
			sprintf(MsgSaid,
			        "检测到疑似病毒程序运行并成功暂停！\n病毒目录：%s\n警报等级：高风险\n请问是否结束目标程序？\n点击是，将会杀死目标进程并隔离，\n点击否，将会将让目标程序继续运行并添加白名单例外，\n您可以随时访问C盾根目录下的Data\\VirusPath文件夹，\n根据文件被删除的时间恢复文件。",
			        PathAndExe);
		} else if (Type == VI_DANGER) {
			IsHandleProcessOK = KillProcess(VirusProcess.szExeFile);
			DelVirTime = time(0);
			OnFileDelete(PathAndExe);
			sprintf(MsgSaid,
			        "检测到病毒程序运行并成功结束和隔离！\n病毒目录：%s\n警报等级：危险\n请问是否删除目标程序？\n点击是，将会删除隔离区中的目标程序，\n点击否，将会将目标程序释放并添加白名单例外，\n您可以随时访问C盾根目录下的Data\\VirusPath文件夹，\n根据文件被删除的时间恢复文件。",
			        PathAndExe);
		} else if (!IsHandleProcessOK) { //处理病毒程序失败
			sprintf(MsgSaid,
			        "病毒进程处理失败！\n请您尽快保存您的文件及数据，\nC盾将在您点击\"确定\"后关闭计算机，\n您可以使用PE系统或者Windows安全模式对病毒进行手动删除！\n病毒路径：%s",
			        PathAndExe);
			MessageBox(NULL, MsgSaid, "C盾", MB_OK);
			ShutdownSystem();//为防止cmd被禁用无法关机，所以要用WindowsAPI
		}
		int MsgReturn = MessageBox(NULL, MsgSaid, "C盾", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL);//输出问题
		if (MsgReturn == IDYES) {//点击了“确定”
			//根据情报等级作出对应操作
			if (Type == VI_SMRISK) {
				IsHandleProcessOK = KillProcess(VirusProcess.szExeFile);
				DelVirTime = time(0);
				OnFileDelete(PathAndExe);
			} else if (Type == VI_HIRISK) {
				PauseProcess(VirusProcess.th32ProcessID, false);
				IsHandleProcessOK = KillProcess(VirusProcess.szExeFile);
				DelVirTime = time(0);
				OnFileDelete(PathAndExe);
			} else if (Type == VI_DANGER) {
				remove(VirusData);
			}
		} else {
			if (Type == VI_SMRISK) {
				WriteList(PathAndExe);
				return;
			} else if (Type == VI_HIRISK) {
				PauseProcess(VirusProcess.th32ProcessID, false);
				WriteList(PathAndExe);
			} else if (Type == VI_DANGER) {
				MoveFileTo(VirusData, PathAndExe);
				WriteList(PathAndExe);
			}
		}
	}
}

/*________________________________________________________________杀毒线程的函数定义____________________________________________________________*/
DWORD WINAPI VirusLibKill(LPVOID Parameter/*我也不知道是什么的参数*/) {
Start:
	;

	while (true) {
		string lindat;

		if (IfOpen == 1) {
			fstream virlib("Data\\VirusLibrary.libdat");                //打开病毒库文件，这行不能提前运行，这是玄学

			while (getline(virlib, lindat)) {                           //一次一行
				char *datcr = new char[strlen(lindat.c_str()) + 1];    	//将读取到的数据从string型转为char型，强制转换
				strcpy(datcr, lindat.c_str());                         	//这行也是
				PROCESSENTRY32 ProcData;

				if (GetProcess(datcr, ProcData)) {                         //发现病毒
					HandleVirus(VI_DANGER, ProcData);
				}

				delete datcr;                   //删除new出来的datcr变量防止慢慢占用内存而导致内存不足
			}

			lindat = "\0";                                        //防止溢出，因为它是全局变量
		}
	}

	goto Start;        //这里返回到最开始是因为怕有特殊情况导致循环break
	return 0;//返回0
}

DWORD WINAPI RegistryFunc(LPVOID Parameter) {
Start:
	;
	while (true) {
		if (GetFileSize("Data\\WhiteList.VirusDat") == 0) {
			if (MessageBox(NULL, "检测到您还未将启动项加入C盾白名单，\n单击“是”以将所有启动项添加进白名单，\n以防止误杀！", "C盾",
			               MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL) == IDYES) {

			}
		}
		goto Start;        //这里返回到最开始是因为怕有特殊情况导致循环break
		return 0;
	}
}

DWORD WINAPI ErgodicPathProcess(LPVOID Parameter) {
Start:
	;
	while (true) {
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};

		while (Process32Next(hProcessSnap, &process)) {
			char *ProcessExeFile = process.szExeFile;          //进程名
			TCHAR ProcessPath[MAX_PATH] = {0};                 //进程目录
			TCHAR ProcessExeFilePathAndFile[MAX_PATH] = {0};   //进程全路径
			DWORD ProcessID = process.th32ProcessID;           //进程PID码
			GetProcessPath(ProcessExeFile, ProcessPath);
			GetProcessPath(ProcessExeFile, ProcessExeFilePathAndFile);

//			MessageBox(NULL, ProcessPath, ProcessPath, MB_OK);
			if (ProcessPath[0] == '\0') {
				continue;
			}

			(_tcsrchr(ProcessPath, _T('\\')))[0] = 0;
//			MessageBox(NULL, ProcessPath, ProcessPath, MB_OK);

			string WinDir = "C:\\Windows", SystemDir = "C:\\Windows\\System32";
			//吐槽一下，Windows10的优化真的拉的一批，系统进程就有200个，全部检测一遍太慢了，所以屏蔽掉Windows和System32目录优化一下

			if (WinDir == ProcessPath || SystemDir == ProcessPath) {
				continue;
			}

			if (GetExecuteFiles(ProcessPath)) {
				HandleVirus(VI_HIRISK, process);
			}
		}
	}
	goto Start;        //这里返回到最开始是因为怕有特殊情况导致循环break
}

DWORD WINAPI ErgodicAdminProcess(LPVOID Parameter) {
Start:
	;
	while (true) {
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};

		while (Process32Next(hProcessSnap, &process)) {
			char *ProcessExeFile = process.szExeFile;          //进程名
			TCHAR ProcessPath[MAX_PATH] = {0};                 //进程目录
			TCHAR ProcessExeFilePathAndFile[MAX_PATH] = {0};   //进程全路径
			DWORD ProcessID = process.th32ProcessID;           //进程PID码
			GetProcessPath(ProcessExeFile, ProcessPath);
			GetProcessPath(ProcessExeFile, ProcessExeFilePathAndFile);

//			MessageBox(NULL, ProcessPath, ProcessPath, MB_OK);
			if (ProcessPath[0] == '\0') {
				continue;
			}

			(_tcsrchr(ProcessPath, _T('\\')))[0] = 0;
//			MessageBox(NULL, ProcessPath, ProcessPath, MB_OK);

			string WinDir = "C:\\Windows", SystemDir = "C:\\Windows\\System32";
			//吐槽一下，Windows10的优化真的拉的一批，系统进程就有200个，全部检测一遍太慢了，所以屏蔽掉Windows和System32目录优化一下

			if (WinDir == ProcessPath || SystemDir == ProcessPath) {
				continue;
			}

			if (IsProcessElevatedForName(process.szExeFile) && !WhiteList(ProcessExeFilePathAndFile)) {
				HandleVirus(VI_SMRISK, process);
			}
		}
	}
	goto Start;        //这里返回到最开始是因为怕有特殊情况导致循环break
}

/*________________________________________________________________杀毒线程的函数定义End____________________________________________________________*/
void Init() {                                           //初始化
	CONSOLE_CURSOR_INFO cursor_info = {1, 0};
	SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursor_info);
	sys("mode con cols=76 lines=20");
	HWND hWnd = GetConsoleWindow(); //获得cmd窗口句柄
	RECT rc;
	GetWindowRect(hWnd, &rc); //获得cmd窗口对应矩形

	//改变cmd窗口风格
	SetWindowLongPtr(hWnd,
	                 GWL_STYLE, GetWindowLong(hWnd, GWL_STYLE) & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX);
	//因为风格涉及到边框改变，必须调用SetWindowPos，否则无效果
	SetWindowPos(hWnd,
	             NULL,
	             rc.left,
	             rc.top,
	             rc.right - rc.left, rc.bottom - rc.top,
	             NULL);
	HMENU hMenu = GetSystemMenu(hWnd, FALSE);
	RemoveMenu(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_DISABLED);
	SetConsoleTitle(TEXT("C盾"));

	DisableFastMake();//移除快速编辑

	//____________________________________________________遍历隔离区文件夹并Lock________________________________________________//
	char CdunPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, CdunPath, MAX_PATH);
	(_tcsrchr(CdunPath, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串
	string path = (string)CdunPath + "\\Data\\VirusPath";       //定位隔离区位置
	//文件句柄
	intptr_t hFile = 0;
	//文件信息
	struct _finddata_t fileinfo;
	string p;

	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1) {
		do {
			if ((fileinfo.attrib ==  _A_NORMAL)) {
//				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
//					getFiles(p.assign(path).append("\\").append(fileinfo.name), files);
//				}
			} else {
				string FileBuf = p.assign(path).append("\\").append(fileinfo.name);       //定义缓存
				char *FileBufc = new char[strlen(FileBuf.c_str()) + 1];            //定义char*型缓存
				strcpy(FileBufc, FileBuf.c_str());                            //将string型缓存强转为char*型缓存
				LockFileToEasy(FileBufc);                                  //锁定文件
				delete FileBufc;//删除New出来的char对象
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
	//____________________________________________________遍历完成________________________________________________//
	//这里的MBR备份提醒本来是打算写到主界面函数里的，
	//但是有一个奇怪的BUG导致杀软运行一会儿之后就还是会弹这个弹窗，
	//刚好考虑到优化问题，就把判断放到这里了
	if (!fopen("Data\\MBRData.data", "r")) {
		if (MessageBox(NULL, "检测到您还未备份MBR，是否对MBR进行备份？", "C盾",
		               MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL) == IDYES) {
			CopyMBR();
			MessageBox(NULL, "备份完毕！", "C盾", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
		}
	}
	if (GetFileSize("Data\\WhiteList.VirusDat") == 0) {//白名单文件为空，代表没有将任何文件列入例外
		if (MessageBox(NULL, "检测到您还未将管理员程序列入白名单，是否列入？", "C盾",
		               MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL) == IDYES) {
			HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};

			while (Process32Next(hProcessSnap, &process)) {
				char *ProcessExeFile = process.szExeFile;          //进程名
				TCHAR ProcessPath[MAX_PATH] = {0};                 //进程目录
				TCHAR ProcessExeFilePathAndFile[MAX_PATH] = {0};   //进程全路径
				DWORD ProcessID = process.th32ProcessID;           //进程PID码
				GetProcessPath(ProcessExeFile, ProcessPath);
				GetProcessPath(ProcessExeFile, ProcessExeFilePathAndFile);

//			MessageBox(NULL, ProcessPath, ProcessPath, MB_OK);
				if (ProcessPath[0] == '\0') {
					continue;
				}

				(_tcsrchr(ProcessPath, _T('\\')))[0] = 0;
//			MessageBox(NULL, ProcessPath, ProcessPath, MB_OK);

				string WinDir = "C:\\Windows", SystemDir = "C:\\Windows\\System32";
				//吐槽一下，Windows10的优化真的拉的一批，系统进程就有200个，全部检测一遍太慢了，所以屏蔽掉Windows和System32目录优化一下

				if (WinDir == ProcessPath || SystemDir == ProcessPath) {
					continue;
				}

				if (IsProcessElevatedForName(process.szExeFile) && !WhiteList(ProcessExeFilePathAndFile)) {
					WriteList(ProcessExeFilePathAndFile);
				}
			}
			MessageBox(NULL, "标记完成！", "C盾", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
		}
	}


	HANDLE VirLib, ErgodicPathVir, ErgodicAdminVir, Registry;//杀毒线程句柄
	VirLib = CreateThread(NULL, 0, VirusLibKill, NULL, 0, NULL);//创建杀毒线程
//	Registry = CreateThread(NULL, 0, RegistryFunc, NULL, 0, NULL);
	ErgodicAdminVir = CreateThread(NULL, 0, ErgodicAdminProcess, NULL, 0, NULL);
	ErgodicPathVir = CreateThread(NULL, 0, ErgodicPathProcess, NULL, 0, NULL);
	CloseHandle(VirLib);//关闭线程句柄让它自己执行
	CloseHandle(ErgodicPathVir);
	CloseHandle(ErgodicAdminVir);
}

void LLTZ_Menu() {                                    //病毒记录库
	sys("color F0");
	cls

	while (true) {
		gto(0, 0);

		if (KEY_DOWN(VK_ESCAPE))
			GetInput();
		string Names;
		fstream	NamesLib("Data\\WhiteList.VirusDat");

		for (int i = 0; getline(NamesLib, Names); i++) {
			(i % 2 == 0) ? (cout << Names << endl) : cout;
		}

		Sleep(20);
	}
}

void SleepProg() {
	MainHwnd = FindWindow(NULL, "C盾");
	ShowWindow(MainHwnd, SW_HIDE);
	MessageBox(NULL, "窗体已隐藏！您可以使用Ctrl + Alt + C键召出窗体！", "C盾安全", MB_OK);

	while (true) {
		PrintScreen();                     //包装完的截屏函数，直接调用就可以，自带按键检测的

		if (KEY_DOWN(VK_CONTROL)) {                            //检测显示窗体快捷键
			if (KEY_DOWN(VK_MENU)) {
				if (KEY_DOWN(VK_C)) {
					ShowWindow(MainHwnd, SW_SHOW);
					GetInput();
				}
			}
		}
	}
}

void GetInput() {                                       //主界面函数
	sys("color F0");
	cls
	gto(4, 14);
	printf("欢迎使用C盾安全软件");
	gto(18, 10);
	printf("注意：请使用该界面内的按键关闭及退出C盾！");
	Button LLTZ = NewButton(12, 15, "查看白名单标记文件");
	Button SAFE = NewButton(9, 17, "开启防护");
	Button MBRSAFE = NewButton(15, 16, "恢复启动信息");
	Button CloseWindow = NewButton(0, 32, "最小化");
	Button Exit = NewButton(0, 36, "退出");
	ios::sync_with_stdio(false);                       //文件读取加速，要不不能有效拦截病毒
	MainHwnd = FindWindow(NULL, "C盾");

	while (true) {                 //帧循环
		PrintScreen();                     //包装完的截屏函数，直接调用就可以，自带按键检测的
		DisableFastMake();//反复关闭快速编辑模式防止整活

		if (IfOpen == 1) {
			gto(9, 16);
			printf("√");
		}

		if (IfOpen == 0) {
			gto(9, 16);
			printf("×");
		}

		if (TestButton(CloseWindow)) {
			SleepProg();
		}

		if (TestButton(Exit)) {
			exit(0);
		}

		if (TestButton(LLTZ)) {
			LLTZ_Menu();
		}

		if (TestButton(SAFE)) {
			if (IfOpen == 1) {
				IfOpen = 0;
			} else if (IfOpen == 0) {
				IfOpen = 1;
			}

			Sleep(200);
		}

		if (TestButton(MBRSAFE)) {
			if (MessageBox(NULL, "确认将当前的MBR启动信息重置？\n此操作不可逆！", "C盾",
			               MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL) == IDYES) {
				ReMBR();        //恢复MBR
				MessageBox(NULL, "重置完毕！", "C盾", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
			}
		}

		if (KEY_DOWN(VK_CONTROL)) {                            //检测显示窗体快捷键，为了某些病毒关闭窗口用户仍然能够正常召出
			if (KEY_DOWN(VK_MENU)) {
				if (KEY_DOWN(VK_C)) {
					ShowWindow(MainHwnd, SW_SHOW);
				}
			}
		}

		Sleep(15);
	}
}

int main() {                     //主函数
	char Name[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, Name, MAX_PATH);
	(_tcsrchr(Name, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串
	char Pathcmd[MAX_PATH];
	sprintf(Pathcmd, "cd /d %s", Name);
	system(Pathcmd);
	SetCurrentDirectoryA(Name);
//	SetBypassUACReg();           //BypassUAC写入注册表
	GetAdmin(SW_SHOW);       //管理员权限
//	SetBypassUACReg();           //再写入一次防止没有权限
	GetDebugPrivilege();     //获取管理员权限后获取debug权限，因为这个函数需要管理员权限
	SetStart(true);           //写入启动项，这个要放在提权的后面，否则有几率无法访问
	Init();
	GetInput();
	return 0;
}