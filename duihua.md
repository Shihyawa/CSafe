在Windows系统中，可以通过Windows API获取进程的句柄信息，然后根据句柄类型和进程ID筛选出目标进程的文件句柄。然而，Windows API并不直接提供获取句柄对应文件路径的方法，所以无法直接确定这些句柄是否指向可执行文件。

另外，获取句柄信息通常需要管理员权限，因此这个函数可能无法在所有环境中运行。请谨慎使用这种方法，尤其是在涉及用户隐私的场合。

以下是一个简化版的示例，展示了如何获取进程的句柄信息：

```cpp
#include <windows.h>
#include <winternl.h>
#include <vector>

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

std::vector<HANDLE> getProcessHandles(PROCESSENTRY32 pe) {
    NtQuerySystemInformation_t NtQuerySystemInformation = 
        (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");

    SYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG returnLength;
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, &handleInfo, sizeof(handleInfo), &returnLength);
    if (status != STATUS_SUCCESS) {
        // Handle error
    }

    std::vector<HANDLE> handles;
    for (ULONG i = 0; i < handleInfo.HandleCount; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo.Handles[i];
        if (handle.UniqueProcessId == pe.th32ProcessID && handle.ObjectTypeNumber == FILE_TYPE_DISK) {
            handles.push_back((HANDLE)handle.HandleValue);
        }
    }

    return handles;
}
```

这个函数返回的是一个`HANDLE`类型的数组，代表目标进程打开的所有文件句柄。但是，这些句柄只包含句柄的类型和ID，不包含句柄对应的文件路径，所以无法直接确定这些句柄是否指向可执行文件。如需获取句柄对应的文件路径，可能需要使用更复杂的方法，例如使用`NtQueryObject`函数或者`DeviceIoControl`函数。






























在Windows中，可以使用GetFinalPathNameByHandle函数来获取文件句柄对应的全路径。以下是一个简单的示例：

```cpp
#include <windows.h>
#include <iostream>

std::string getFilePath(HANDLE fileHandle) {
    char filePath[MAX_PATH];
    if (GetFinalPathNameByHandleA(fileHandle, filePath, MAX_PATH, FILE_NAME_NORMALIZED)) {
        return std::string(filePath);
    } else {
        // Handle error
        std::cerr << "Error getting file path: " << GetLastError() << std::endl;
        return "";
    }
}
```

这个函数接收一个文件句柄，然后返回这个句柄对应的文件全路径。如果获取路径失败，它会打印错误信息并返回空字符串。

请注意，GetFinalPathNameByHandle函数需要Windows Vista或更高版本的Windows。在早期版本的Windows中，你可能需要使用其他方法来获取文件路径，例如使用NtQueryObject函数。
