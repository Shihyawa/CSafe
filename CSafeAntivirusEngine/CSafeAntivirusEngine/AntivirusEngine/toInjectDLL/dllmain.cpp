/*
 * dllmain.cpp
 * CSafe杀毒引擎用来DLL注入的dll
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/
#include <cwchar>
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <thread>
#define MAX_MAPSIZE 16384

std::vector<BYTE> CAHook_CreateFileA, CAHook_CreateFileW,
    CAHook_GetProcAddress,
    CAHook_OpenProcess;

FARPROC pTargetFunction_GPA;

HANDLE CreateMap(const std::string &name, size_t size, DWORD dwProcessId) {
	// 创建一个命名的内存映射文件
	HANDLE hMapFile = CreateFileMapping(
	                      INVALID_HANDLE_VALUE,    // 使用系统分页文件
	                      NULL,                    // 默认安全属性
	                      PAGE_READWRITE,          // 读写权限
	                      0,                       // 最大对象大小（高位）
	                      static_cast<DWORD>(size), // 最大对象大小（低位）
	                      (name + std::to_string(dwProcessId)).c_str()            // 名称标识符
	                  );

	if (hMapFile == NULL) {
		return NULL;
	}
	return hMapFile;
}

bool WriteMap(HANDLE hMapFile, const void *data, size_t size) {
	if (hMapFile == NULL || data == NULL) return false;

	// 映射视图到文件
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// 写入数据
	memcpy(pBuf, data, size);

	// 同步内存
	FlushViewOfFile(pBuf, size);

	// 取消映射
	UnmapViewOfFile(pBuf);
	return true;
}

bool ReadMap(HANDLE hMapFile, void *buffer, size_t size) {
	if (hMapFile == NULL || buffer == NULL) return false;

	// 映射视图到文件
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// 读取数据
	memcpy(buffer, pBuf, size);

	// 取消映射
	UnmapViewOfFile(pBuf);
	return true;
}

bool DeleteMap(HANDLE hMapFile) {
	if (hMapFile == NULL) return false;

	// 关闭句柄
	BOOL result = CloseHandle(hMapFile);
	return result != FALSE;
}

//安装钩子
bool InstallHook(const char *DLLName, const char *FunctionName, void *hookFunction,
                 std::vector<BYTE> &originalBytes) {
	// 获取DLL模块句柄
	HMODULE hModule = GetModuleHandleA(DLLName);
	if (!hModule) {
		return false;
	}

	// 获取目标函数地址
	FARPROC pTargetFunction = GetProcAddress(hModule, FunctionName);
	if (!pTargetFunction) {
		return false;
	}

	// 保存原始字节
	originalBytes.resize(5);
	memcpy(originalBytes.data(), (void *)pTargetFunction, 5);

	// 计算跳转地址
	DWORD oldProtect;
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// 构造跳转指令
	DWORD offset = (DWORD)hookFunction - (DWORD)pTargetFunction - 5;
	BYTE jump[5] = { 0xE9, (BYTE)(offset & 0xFF), (BYTE)((offset >> 8) & 0xFF), (BYTE)((offset >> 16) & 0xFF), (BYTE)((offset >> 24) & 0xFF) };

	// 替换原始函数地址
	memcpy((void *)pTargetFunction, jump, sizeof(jump));

	// 恢复页面保护
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

// 卸载钩子的函数
bool UninstallHook(const char *DLLName, const char *FunctionName,
                   const std::vector<BYTE> &originalBytes) {
	// 获取DLL模块句柄
	HMODULE hModule = GetModuleHandleA(DLLName);
	if (!hModule) {
		return false;
	}

	// 获取目标函数地址
	FARPROC pTargetFunction = GetProcAddress(hModule, FunctionName);
	if (!pTargetFunction) {
		return false;
	}

	DWORD oldProtect;

	// 恢复原始字节
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void *)pTargetFunction, originalBytes.data(), 5);
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

//安装钩子
bool InstallHook_GPA(const char *DLLName, const char *FunctionName, void *hookFunction, std::vector<BYTE> &originalBytes, FARPROC &pTargetFunction) {
	// 获取DLL模块句柄
	HMODULE hModule = GetModuleHandleA(DLLName);
	if (!hModule) {
		return false;
	}

	// 获取目标函数地址
	pTargetFunction = GetProcAddress(hModule, FunctionName);
	if (!pTargetFunction) {
		return false;
	}

	// 保存原始字节
	originalBytes.resize(5);
	memcpy(originalBytes.data(), (void *)pTargetFunction, 5);

	// 计算跳转地址
	DWORD oldProtect;
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// 构造跳转指令
	DWORD offset = (DWORD)hookFunction - (DWORD)pTargetFunction - 5;
	BYTE jump[5] = { 0xE9, (BYTE)(offset & 0xFF), (BYTE)((offset >> 8) & 0xFF), (BYTE)((offset >> 16) & 0xFF), (BYTE)((offset >> 24) & 0xFF) };

	// 替换原始函数地址
	memcpy((void *)pTargetFunction, jump, sizeof(jump));

	// 恢复页面保护
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

// 卸载钩子的函数
bool UninstallHook_GPA(const std::vector<BYTE> &originalBytes, FARPROC pTargetFunction) {
	//检测输入的函数地址是否正确
	if (!pTargetFunction) {
		return false;
	}

	DWORD oldProtect;

	// 恢复原始字节
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void *)pTargetFunction, originalBytes.data(), 5);
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

//这是一个包装好的类，用来帮助一些函数躲避GPAHook，这对于减少误报很重要，主要利用了构造函数和析构函数
FARPROC GetProcAddress_Hooked(HMODULE hModule, LPCSTR lpProcName);//声明一下，class要用
class GPAHookProtect {
	public:
		GPAHookProtect() {
			UninstallHook_GPA(CAHook_GetProcAddress, pTargetFunction_GPA);//卸载Hook
		}
		~GPAHookProtect() {
			CAHook_GetProcAddress.clear();//这里把字节清空是为了重新装载hook
			pTargetFunction_GPA = NULL;
			InstallHook_GPA("kernel32.dll", "GetProcAddress", (void *)GetProcAddress_Hooked, CAHook_GetProcAddress, pTargetFunction_GPA);//重装hook
		}
};

//获取char*的实际大小（有字符部分大小）
size_t GetCharptrSize(const char *Charptr) {
	size_t size = 0;
	for (; Charptr[size] != '\0'; ++size);
	return size;
}



/*
 *GetProcAddress被hook后的函数
*/
FARPROC GetProcAddress_Hooked(HMODULE hModule, LPCSTR lpProcName) {
	HANDLE Map = CreateMap("toMap_GetProcAddress", MAX_MAPSIZE, GetCurrentProcessId());//创建共享内存

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//读取共享内存的已存储内容
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//共享内存数据当前大小
	size_t size_file = GetCharptrSize(lpProcName);//将要写入的数据大小

	ReadBuffer[size] = '/';//写入一个分隔符号
	size += 1;

	//将数据写入共享内存尾部，for循环用来把新数据接到ReadBuffer尾部，也就是接到已存储内容的尾部
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = lpProcName[i - size];
	}
	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//写入共享内存

	UninstallHook_GPA(CAHook_GetProcAddress, pTargetFunction_GPA);//先卸载hook才能调用原始函数
	// 调用原始的 GetProcAddress
	FARPROC ret = GetProcAddress(hModule, lpProcName);//调用原始函数

	CAHook_GetProcAddress.clear();//这里把字节清空是为了重新装载hook
	pTargetFunction_GPA = NULL;
	InstallHook_GPA("kernel32.dll", "GetProcAddress", (void *)GetProcAddress_Hooked, CAHook_GetProcAddress, pTargetFunction_GPA);//重装hook
	return ret;
}

HANDLE CreateFileA_Hooked(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile) {

	volatile GPAHookProtect ProtectClass;//设置保护，防止它装载卸载hook的行为被GPAHook钩到

	HANDLE Map = CreateMap("toMap_CreateFile", MAX_MAPSIZE, GetCurrentProcessId());//创建共享内存

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//读取共享内存的已存储内容
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//共享内存数据当前大小
	size_t size_file = GetCharptrSize(lpFileName);//将要写入的数据大小

	ReadBuffer[size] = '/';//写入一个分隔符号
	size += 1;

	//将数据写入共享内存尾部，for循环用来把新数据接到ReadBuffer尾部，也就是接到已存储内容的尾部
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = lpFileName[i - size];
	}

	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//写入共享内存

	UninstallHook("kernel32.dll", "CreateFileA", CAHook_CreateFileA);//先卸载hook才能调用原始函数
	// 调用原始的 CreateFileA
	HANDLE ret = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);//调用原始函数
	CAHook_CreateFileA.clear();//这里把字节清空是为了重新装载hook
	InstallHook("kernel32.dll", "CreateFileA", (void *)CreateFileA_Hooked, CAHook_CreateFileA);//重装hook

	return ret;
}

HANDLE CreateFileW_Hooked(
    LPCWSTR               lpFileNamew,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile) {

	volatile GPAHookProtect ProtectClass;//设置保护，防止它装载卸载hook的行为被GPAHook钩到

	//先将宽字符转换成窄字符
	size_t sizew = wcstombs(nullptr, lpFileNamew, 0) + 1;
	char *lpFileName = new char[sizew];
	wcstombs(lpFileName, lpFileNamew, sizew);

	HANDLE Map = CreateMap("toMap_CreateFile", MAX_MAPSIZE, GetCurrentProcessId());//创建共享内存

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//读取共享内存的已存储内容
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//共享内存数据当前大小
	size_t size_file = GetCharptrSize(lpFileName);//将要写入的数据大小

	ReadBuffer[size] = '/';//写入一个分隔符号
	size += 1;

	//将数据写入共享内存尾部，for循环用来把新数据接到ReadBuffer尾部，也就是接到已存储内容的尾部
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = lpFileName[i - size];
	}
	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//写入共享内存

	UninstallHook("kernel32.dll", "CreateFileW", CAHook_CreateFileW);//先卸载hook才能调用原始函数
	// 调用原始的 CreateFileW
	HANDLE ret = CreateFileW(lpFileNamew, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);//调用原始函数

	CAHook_CreateFileW.clear();//这里把字节清空是为了重新装载hook
	InstallHook("kernel32.dll", "CreateFileW", (void *)CreateFileW_Hooked, CAHook_CreateFileW);//重装hook
	delete[] lpFileName;
	return ret;
}

HANDLE WINAPI OpenProcess_Hooked(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	volatile GPAHookProtect ProtectClass;//设置保护，防止它装载卸载hook的行为被GPAHook钩到

	char processName[4096] = {0};
	//必须具有的权限
	UninstallHook("kernel32.dll", "OpenProcess", CAHook_OpenProcess);
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	CAHook_OpenProcess.clear();//这里把字节清空是为了重新装载hook
	InstallHook("kernel32.dll", "OpenProcess", (void *)OpenProcess_Hooked, CAHook_OpenProcess);

	if (processHandle == NULL) {
		return (HANDLE)ERROR_ACCESS_DENIED;
	}
	auto length = GetModuleBaseNameA(processHandle, NULL, processName, 4096);
	if (length == 0) {
		return (HANDLE)ERROR_ACCESS_DENIED;
	}
	if (std::string(processName).find("svchost.exe") != std::string::npos ||
	        std::string(processName).find("conhost.exe") != std::string::npos ||
	        std::string(processName).find("csrss.exe") != std::string::npos) {

		HANDLE Map = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, GetCurrentProcessId());//创建共享内存

		char ReadBuffer[MAX_MAPSIZE] = {0};
		if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//读取共享内存的已存储内容
			return NULL;
		}

		size_t size = GetCharptrSize(ReadBuffer);//共享内存数据当前大小
		ReadBuffer[size++] = '-';
		ReadBuffer[size++] = '1';

		if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
			WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//写入共享内存

		return (HANDLE)ERROR_ACCESS_DENIED;
	}

	std::string StrPID = std::to_string(dwProcessId);
	const char *cStrPID = StrPID.data();

	HANDLE Map = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, GetCurrentProcessId());//创建共享内存

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//读取共享内存的已存储内容
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//共享内存数据当前大小
	size_t size_file = GetCharptrSize(cStrPID);//将要写入的数据大小

	ReadBuffer[size++] = '/';//写入一个分隔符号

	//将数据写入共享内存尾部，for循环用来把新数据接到ReadBuffer尾部，也就是接到已存储内容的尾部
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = cStrPID[i - size];
	}

	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//写入共享内存

	UninstallHook("kernel32.dll", "OpenProcess", CAHook_OpenProcess);//先卸载hook才能调用原始函数
	// 调用原始的 OpenProcess
	HANDLE ret = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);//调用原始函数

	CAHook_OpenProcess.clear();//这里把字节清空是为了重新装载hook
	InstallHook("kernel32.dll", "OpenProcess", (void *)OpenProcess_Hooked, CAHook_OpenProcess);//重装hook
	return ret;
}

void UninstallHooks(void) {
	static bool isFirst = true;
	if (isFirst) {
		isFirst = false;
		UninstallHook_GPA(CAHook_GetProcAddress, pTargetFunction_GPA);//先卸载GetProcAddress的钩子才能正常卸载别的函数的钩子
		UninstallHook("kernel32.dll", "CreateFileA", CAHook_CreateFileA);
		UninstallHook("kernel32.dll", "CreateFileW", CAHook_CreateFileW);
		UninstallHook("kernel32.dll", "OpenProcess", CAHook_OpenProcess);
	}
}

void DLLThread(void) {
	InstallHook("kernel32.dll", "OpenProcess", (void *)OpenProcess_Hooked, CAHook_OpenProcess);
	InstallHook("kernel32.dll", "CreateFileA", (void *)CreateFileA_Hooked, CAHook_CreateFileA);
	InstallHook("kernel32.dll", "CreateFileW", (void *)CreateFileW_Hooked, CAHook_CreateFileW);
	InstallHook_GPA("kernel32.dll", "GetProcAddress", (void *)GetProcAddress_Hooked, CAHook_GetProcAddress, pTargetFunction_GPA);
	while (true) {
		HANDLE FlagMap = CreateMap("toMap_bFlag", MAX_MAPSIZE, GetCurrentProcessId());//创建共享内存
		char ReadBuffer[MAX_MAPSIZE] = {0};
		ReadMap(FlagMap, ReadBuffer, sizeof(ReadBuffer));

		if (strcmp(ReadBuffer, std::to_string(GetCurrentProcessId()).data()) == 0) {
			UninstallHooks();
			break;
		}
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			std::thread DLLThreadStarter(DLLThread);
			DLLThreadStarter.detach();
			break;
		}

		case DLL_PROCESS_DETACH: {
			UninstallHooks();
			break;
		}
	}
	return TRUE;
}