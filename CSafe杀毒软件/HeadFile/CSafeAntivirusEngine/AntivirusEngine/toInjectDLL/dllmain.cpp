/*
 * dllmain.cpp
 * CSafeɱ����������DLLע���dll
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
	// ����һ���������ڴ�ӳ���ļ�
	HANDLE hMapFile = CreateFileMapping(
	                      INVALID_HANDLE_VALUE,    // ʹ��ϵͳ��ҳ�ļ�
	                      NULL,                    // Ĭ�ϰ�ȫ����
	                      PAGE_READWRITE,          // ��дȨ��
	                      0,                       // �������С����λ��
	                      static_cast<DWORD>(size), // �������С����λ��
	                      (name + std::to_string(dwProcessId)).c_str()            // ���Ʊ�ʶ��
	                  );

	if (hMapFile == NULL) {
		return NULL;
	}
	return hMapFile;
}

bool WriteMap(HANDLE hMapFile, const void *data, size_t size) {
	if (hMapFile == NULL || data == NULL) return false;

	// ӳ����ͼ���ļ�
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// д������
	memcpy(pBuf, data, size);

	// ͬ���ڴ�
	FlushViewOfFile(pBuf, size);

	// ȡ��ӳ��
	UnmapViewOfFile(pBuf);
	return true;
}

bool ReadMap(HANDLE hMapFile, void *buffer, size_t size) {
	if (hMapFile == NULL || buffer == NULL) return false;

	// ӳ����ͼ���ļ�
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// ��ȡ����
	memcpy(buffer, pBuf, size);

	// ȡ��ӳ��
	UnmapViewOfFile(pBuf);
	return true;
}

bool DeleteMap(HANDLE hMapFile) {
	if (hMapFile == NULL) return false;

	// �رվ��
	BOOL result = CloseHandle(hMapFile);
	return result != FALSE;
}

//��װ����
bool InstallHook(const char *DLLName, const char *FunctionName, void *hookFunction,
                 std::vector<BYTE> &originalBytes) {
	// ��ȡDLLģ����
	HMODULE hModule = GetModuleHandleA(DLLName);
	if (!hModule) {
		return false;
	}

	// ��ȡĿ�꺯����ַ
	FARPROC pTargetFunction = GetProcAddress(hModule, FunctionName);
	if (!pTargetFunction) {
		return false;
	}

	// ����ԭʼ�ֽ�
	originalBytes.resize(5);
	memcpy(originalBytes.data(), (void *)pTargetFunction, 5);

	// ������ת��ַ
	DWORD oldProtect;
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// ������תָ��
	DWORD offset = (DWORD)hookFunction - (DWORD)pTargetFunction - 5;
	BYTE jump[5] = { 0xE9, (BYTE)(offset & 0xFF), (BYTE)((offset >> 8) & 0xFF), (BYTE)((offset >> 16) & 0xFF), (BYTE)((offset >> 24) & 0xFF) };

	// �滻ԭʼ������ַ
	memcpy((void *)pTargetFunction, jump, sizeof(jump));

	// �ָ�ҳ�汣��
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

// ж�ع��ӵĺ���
bool UninstallHook(const char *DLLName, const char *FunctionName,
                   const std::vector<BYTE> &originalBytes) {
	// ��ȡDLLģ����
	HMODULE hModule = GetModuleHandleA(DLLName);
	if (!hModule) {
		return false;
	}

	// ��ȡĿ�꺯����ַ
	FARPROC pTargetFunction = GetProcAddress(hModule, FunctionName);
	if (!pTargetFunction) {
		return false;
	}

	DWORD oldProtect;

	// �ָ�ԭʼ�ֽ�
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void *)pTargetFunction, originalBytes.data(), 5);
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

//��װ����
bool InstallHook_GPA(const char *DLLName, const char *FunctionName, void *hookFunction, std::vector<BYTE> &originalBytes, FARPROC &pTargetFunction) {
	// ��ȡDLLģ����
	HMODULE hModule = GetModuleHandleA(DLLName);
	if (!hModule) {
		return false;
	}

	// ��ȡĿ�꺯����ַ
	pTargetFunction = GetProcAddress(hModule, FunctionName);
	if (!pTargetFunction) {
		return false;
	}

	// ����ԭʼ�ֽ�
	originalBytes.resize(5);
	memcpy(originalBytes.data(), (void *)pTargetFunction, 5);

	// ������ת��ַ
	DWORD oldProtect;
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// ������תָ��
	DWORD offset = (DWORD)hookFunction - (DWORD)pTargetFunction - 5;
	BYTE jump[5] = { 0xE9, (BYTE)(offset & 0xFF), (BYTE)((offset >> 8) & 0xFF), (BYTE)((offset >> 16) & 0xFF), (BYTE)((offset >> 24) & 0xFF) };

	// �滻ԭʼ������ַ
	memcpy((void *)pTargetFunction, jump, sizeof(jump));

	// �ָ�ҳ�汣��
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

// ж�ع��ӵĺ���
bool UninstallHook_GPA(const std::vector<BYTE> &originalBytes, FARPROC pTargetFunction) {
	//�������ĺ�����ַ�Ƿ���ȷ
	if (!pTargetFunction) {
		return false;
	}

	DWORD oldProtect;

	// �ָ�ԭʼ�ֽ�
	VirtualProtect((void *)pTargetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void *)pTargetFunction, originalBytes.data(), 5);
	VirtualProtect((void *)pTargetFunction, 5, oldProtect, &oldProtect);

	return true;
}

//����һ����װ�õ��࣬��������һЩ�������GPAHook������ڼ����󱨺���Ҫ����Ҫ�����˹��캯������������
FARPROC GetProcAddress_Hooked(HMODULE hModule, LPCSTR lpProcName);//����һ�£�classҪ��
class GPAHookProtect {
	public:
		GPAHookProtect() {
			UninstallHook_GPA(CAHook_GetProcAddress, pTargetFunction_GPA);//ж��Hook
		}
		~GPAHookProtect() {
			CAHook_GetProcAddress.clear();//������ֽ������Ϊ������װ��hook
			pTargetFunction_GPA = NULL;
			InstallHook_GPA("kernel32.dll", "GetProcAddress", (void *)GetProcAddress_Hooked, CAHook_GetProcAddress, pTargetFunction_GPA);//��װhook
		}
};

//��ȡchar*��ʵ�ʴ�С�����ַ����ִ�С��
size_t GetCharptrSize(const char *Charptr) {
	size_t size = 0;
	for (; Charptr[size] != '\0'; ++size);
	return size;
}



/*
 *GetProcAddress��hook��ĺ���
*/
FARPROC GetProcAddress_Hooked(HMODULE hModule, LPCSTR lpProcName) {
	HANDLE Map = CreateMap("toMap_GetProcAddress", MAX_MAPSIZE, GetCurrentProcessId());//���������ڴ�

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//��ȡ�����ڴ���Ѵ洢����
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//�����ڴ����ݵ�ǰ��С
	size_t size_file = GetCharptrSize(lpProcName);//��Ҫд������ݴ�С

	ReadBuffer[size] = '/';//д��һ���ָ�����
	size += 1;

	//������д�빲���ڴ�β����forѭ�������������ݽӵ�ReadBufferβ����Ҳ���ǽӵ��Ѵ洢���ݵ�β��
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = lpProcName[i - size];
	}
	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//д�빲���ڴ�

	UninstallHook_GPA(CAHook_GetProcAddress, pTargetFunction_GPA);//��ж��hook���ܵ���ԭʼ����
	// ����ԭʼ�� GetProcAddress
	FARPROC ret = GetProcAddress(hModule, lpProcName);//����ԭʼ����

	CAHook_GetProcAddress.clear();//������ֽ������Ϊ������װ��hook
	pTargetFunction_GPA = NULL;
	InstallHook_GPA("kernel32.dll", "GetProcAddress", (void *)GetProcAddress_Hooked, CAHook_GetProcAddress, pTargetFunction_GPA);//��װhook
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

	volatile GPAHookProtect ProtectClass;//���ñ�������ֹ��װ��ж��hook����Ϊ��GPAHook����

	HANDLE Map = CreateMap("toMap_CreateFile", MAX_MAPSIZE, GetCurrentProcessId());//���������ڴ�

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//��ȡ�����ڴ���Ѵ洢����
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//�����ڴ����ݵ�ǰ��С
	size_t size_file = GetCharptrSize(lpFileName);//��Ҫд������ݴ�С

	ReadBuffer[size] = '/';//д��һ���ָ�����
	size += 1;

	//������д�빲���ڴ�β����forѭ�������������ݽӵ�ReadBufferβ����Ҳ���ǽӵ��Ѵ洢���ݵ�β��
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = lpFileName[i - size];
	}

	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//д�빲���ڴ�

	UninstallHook("kernel32.dll", "CreateFileA", CAHook_CreateFileA);//��ж��hook���ܵ���ԭʼ����
	// ����ԭʼ�� CreateFileA
	HANDLE ret = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);//����ԭʼ����
	CAHook_CreateFileA.clear();//������ֽ������Ϊ������װ��hook
	InstallHook("kernel32.dll", "CreateFileA", (void *)CreateFileA_Hooked, CAHook_CreateFileA);//��װhook

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

	volatile GPAHookProtect ProtectClass;//���ñ�������ֹ��װ��ж��hook����Ϊ��GPAHook����

	//�Ƚ����ַ�ת����խ�ַ�
	size_t sizew = wcstombs(nullptr, lpFileNamew, 0) + 1;
	char *lpFileName = new char[sizew];
	wcstombs(lpFileName, lpFileNamew, sizew);

	HANDLE Map = CreateMap("toMap_CreateFile", MAX_MAPSIZE, GetCurrentProcessId());//���������ڴ�

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//��ȡ�����ڴ���Ѵ洢����
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//�����ڴ����ݵ�ǰ��С
	size_t size_file = GetCharptrSize(lpFileName);//��Ҫд������ݴ�С

	ReadBuffer[size] = '/';//д��һ���ָ�����
	size += 1;

	//������д�빲���ڴ�β����forѭ�������������ݽӵ�ReadBufferβ����Ҳ���ǽӵ��Ѵ洢���ݵ�β��
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = lpFileName[i - size];
	}
	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//д�빲���ڴ�

	UninstallHook("kernel32.dll", "CreateFileW", CAHook_CreateFileW);//��ж��hook���ܵ���ԭʼ����
	// ����ԭʼ�� CreateFileW
	HANDLE ret = CreateFileW(lpFileNamew, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);//����ԭʼ����

	CAHook_CreateFileW.clear();//������ֽ������Ϊ������װ��hook
	InstallHook("kernel32.dll", "CreateFileW", (void *)CreateFileW_Hooked, CAHook_CreateFileW);//��װhook
	delete[] lpFileName;
	return ret;
}

HANDLE WINAPI OpenProcess_Hooked(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	volatile GPAHookProtect ProtectClass;//���ñ�������ֹ��װ��ж��hook����Ϊ��GPAHook����

	char processName[4096] = {0};
	//������е�Ȩ��
	UninstallHook("kernel32.dll", "OpenProcess", CAHook_OpenProcess);
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	CAHook_OpenProcess.clear();//������ֽ������Ϊ������װ��hook
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

		HANDLE Map = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, GetCurrentProcessId());//���������ڴ�

		char ReadBuffer[MAX_MAPSIZE] = {0};
		if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//��ȡ�����ڴ���Ѵ洢����
			return NULL;
		}

		size_t size = GetCharptrSize(ReadBuffer);//�����ڴ����ݵ�ǰ��С
		ReadBuffer[size++] = '-';
		ReadBuffer[size++] = '1';

		if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
			WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//д�빲���ڴ�

		return (HANDLE)ERROR_ACCESS_DENIED;
	}

	std::string StrPID = std::to_string(dwProcessId);
	const char *cStrPID = StrPID.data();

	HANDLE Map = CreateMap("toMap_OpenProcess", MAX_MAPSIZE, GetCurrentProcessId());//���������ڴ�

	char ReadBuffer[MAX_MAPSIZE] = {0};
	if (!ReadMap(Map, ReadBuffer, sizeof(ReadBuffer))) {//��ȡ�����ڴ���Ѵ洢����
		return NULL;
	}

	size_t size = GetCharptrSize(ReadBuffer);//�����ڴ����ݵ�ǰ��С
	size_t size_file = GetCharptrSize(cStrPID);//��Ҫд������ݴ�С

	ReadBuffer[size++] = '/';//д��һ���ָ�����

	//������д�빲���ڴ�β����forѭ�������������ݽӵ�ReadBufferβ����Ҳ���ǽӵ��Ѵ洢���ݵ�β��
	for (int i = size; i < MAX_MAPSIZE && i - size < size_file; i++) {
		ReadBuffer[i] = cStrPID[i - size];
	}

	if (strlen(ReadBuffer) + 1 <= MAX_MAPSIZE)
		WriteMap(Map, ReadBuffer, strlen(ReadBuffer) + 1);//д�빲���ڴ�

	UninstallHook("kernel32.dll", "OpenProcess", CAHook_OpenProcess);//��ж��hook���ܵ���ԭʼ����
	// ����ԭʼ�� OpenProcess
	HANDLE ret = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);//����ԭʼ����

	CAHook_OpenProcess.clear();//������ֽ������Ϊ������װ��hook
	InstallHook("kernel32.dll", "OpenProcess", (void *)OpenProcess_Hooked, CAHook_OpenProcess);//��װhook
	return ret;
}

void UninstallHooks(void) {
	static bool isFirst = true;
	if (isFirst) {
		isFirst = false;
		UninstallHook_GPA(CAHook_GetProcAddress, pTargetFunction_GPA);//��ж��GetProcAddress�Ĺ��Ӳ�������ж�ر�ĺ����Ĺ���
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
		HANDLE FlagMap = CreateMap("toMap_bFlag", MAX_MAPSIZE, GetCurrentProcessId());//���������ڴ�
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