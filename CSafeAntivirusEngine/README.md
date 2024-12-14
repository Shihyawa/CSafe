## 头文件
```cpp
#include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"
```

## 引擎描述
#### TOProtect
基于动态行为检测的防护引擎，可以对刚启动或正在运行的程序进行动态监控，实现杀毒引擎的最后一道防护
#### LSProtect
基于PE文件导入表的静态启发引擎，优点是速度快、稳定，缺点是查杀率较低、误报率较高(用来训练的样本平均查杀率26%~35%，误报率10%)
#### BITProtect
基于PE文件可识别字符串的静态启发引擎，优点是查杀率相较LSProtect更高、误报率低(用来训练的样本平均查杀率40%+，误报率3%以下，平均误报1.5%)，缺点是速度较慢且根据文件大小不同查杀时间也不一样

## 封装API(为CSafe封装好的API，调用较为方便)
### 静态API
* `CSafeAntivirusEngine::detectFile(std::string TargetFile)`函数:
    * 基于LSProtect与BITProtect引擎的文件查杀函数，查杀率60%~80%
    * 参数：`std::string`类型，代表目标文件
    * 返回值：返回一个`std::string`类型的字符串，如果不是病毒则会返回`"disVirus"`，如果是病毒则会返回病毒的对应类型，如`"CSafe.BITProtect.Malware.Trojan.RemoteControl"`，`CSafe`后跟的是查杀引擎，可能是`LSProtect`或`BITProtect`，如果查杀过程中发生错误，则会返回以`Error`开头的字符串，字符串内容代表错误类型，检测错误只需要`find("Error")`即可
    * 用法：
        ```cpp
        std::string result = CSafeAntivirusEngine::detectFile("Trojan.exe");
        if(result.find("Error") == std::string::npos && result.find("disVirus") == std::string::npos) {
            std::cout << "Detected a virus: " << result << std::endl;
        }
        ```
    * 示例：
        ```cpp
        #include <iostream>//std::cout
        #include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"//头文件定义

        int main() {
            std::string filePath;
            std::cin >> filePath;

            std::string result = CSafeAntivirusEngine::detectFile(filePath);
            if(result.find("Error") == std::string::npos && result.find("disVirus") == std::string::npos) {
                std::cout << "Detected a virus: " << result << std::endl;
            } else {
                std::cout << "Not a virus." << std::endl;
            }
            return 0;
        }
        ```

* `CSafeAntivirusEngine::detectFile_fast(std::string TargetFile)`函数:
    * 同detectFile函数，只是去掉了BITProtect引擎使得查杀速度更快，适用于文件防护等速度需求高的引擎

* `CSafeAntivirusEngine::scanFolder(std::string path, void (*HandleFunction)(std::string, std::string), bool EnableFastMode = false)`函数:
    * 基于LSProtect与BITProtect引擎的文件夹扫描函数，查杀率60%~80%
    * 参数：
        1. `std::string`类型，代表目标文件夹
        2. 返回值为`void`，参数是`(std::string, std::string)`的函数指针，代表检测文件时调用的处理函数
        3. `bool`类型缺省参数，可以不写，代表是否启用快速检测模式(快速检测模式速度快但是会降低查杀率)
    * 返回值：无
    * 示例：
        ```cpp
        #include <iostream>//std::cout
        #include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"//头文件定义

        void HandleFile(std::string path, std::string risk) {
            if (path.find(".exe") != std::string::npos ||
                    path.find(".dll") != std::string::npos ||
                    path.find(".jar") != std::string::npos ||
                    path.find(".ps1") != std::string::npos ||
                    path.find(".bat") != std::string::npos ||
                    path.find(".msi") != std::string::npos) {//建议添加文件类型过滤，否则非PE文件的误报率不能保证(.jar、.ps1、.vbs、.bat等脚本或jar等文件除外)
                std::cout << "Detecting with CSafeAE: " << path;
                if (risk.find("Error") == std::string::npos && risk.find("disVirus") == std::string::npos) {
                    std::cout << ", it is virus: " << risk << std::endl;
                } else {
                    std::cout << std::endl;
                }
            }
        }

        int main() {
            std::string folderPath;
            std::cin >> folderPath;

            CSafeAntivirusEngine::scanFolder(folderPath, HandleFile, false);//不启用加速模式
            return 0;
        }
        ```

### 动态API
* `CSafeAntivirusEngine::detectProcess_Begin(PROCESSENTRY32 targetProcess, std::string dllPath)`函数:
    * 动态查杀的初始化函数，代表开始监控一个进程的行为
    * 参数：
        1. `PROCESSENTRY32`类型，代表目标进程
        2. `std::string`类型，代表将要注入的DLL，DLL在"CSafeAntivirusEngine/AntivirusEngine/toInjectDLL"文件夹中
    * 返回值：`bool`类型，代表操作是否成功，请不要重视该参数，因为有很多原因可能导致执行失败，正常执行下一步即可，不需要错误处理
    * 注：该函数需要与`detectProcess_End`函数搭配使用

* `CSafeAntivirusEngine::detectProcess_End(PROCESSENTRY32 targetProcess)`函数:
    * 结束对一个进程的监控，并返回它的危险程度
    * 参数：`PROCESSENTRY32`类型，代表目标进程
    * 返回值：`std::string`类型，代表风险等级，分别是`"Risk.NoRisk"`、`"Risk.LowRisk"`、`"Risk.MidRisk"`、`Risk.HighRisk`、`"Risk.Malware"`
    * 注：调用该函数之前，可以不调用`detectProcess_Begin`函数，但是如果不调用的话可能会降低查杀率
    * 示例：
        ```cpp
        #include <iostream>//std::cout
        #include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"//头文件定义

        int main() {
            PROCESSENTRY32 pe32;
            //假设这里获取到了一个进程并将其信息赋值给了pe32

            CSafeAntivirusEngine::detectProcess_Begin(pe32, "toInjectDLL.dll");
            std::string result = CSafeAntivirusEngine::detectProcess_End(pe32);
            std::cout << "Risk level: " << result << std::endl;
            return 0;
        }

* `CSafeAntivirusEngine::getNewProcess(PROCESSENTRY32 &targetProcess)`函数:
    * 检测新启动的进程
    * 参数：`PROCESSENTRY32`类型，如果有新的进程启动就会把它的信息赋值给这个参数
    * 返回值：`bool`类型，如果有新的进程启动就会返回`true`，反之`false`

* `CSafeAntivirusEngine::getProcessPath(DWORD dwProcessId)`函数:
    * 获取一个进程的路径
    * 参数：`DWORD`类型，代表进程id
    * 返回值：`string`类型，代表获取到的路径

##### 注：底层API请自行到头文件中查看
