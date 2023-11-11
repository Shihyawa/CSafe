#include <ctime>
#include <cstdio>
#include <conio.h>
#include <cstdlib>
#include <cstring>
#include <conio.h>
#include <iostream>
#include <Windows.h>
using namespace std;
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)


/*
 *函数名称：ShootScreen(filename, hWnd)
 *函数参数：
 *	filename：将要保存的截图名称
 *	hWnd：目标窗口句柄
 *函数功能：将指定的窗口句柄截图并保存到指定为位置
 *函数返回值：无
*/
void ShootScreen(const char *filename, HWND hWnd) {
	HDC hdc = CreateDC("DISPLAY", NULL, NULL, NULL);
	int32_t ScrWidth = 0, ScrHeight = 0;
	RECT rect = { 0 };
	if (hWnd == NULL) {
		ScrWidth = GetDeviceCaps(hdc, HORZRES);
		ScrHeight = GetDeviceCaps(hdc, VERTRES);
	} else {
		GetWindowRect(hWnd, &rect);
		ScrWidth = rect.right - rect.left;
		ScrHeight = rect.bottom - rect.top;
	}
	HDC hmdc = CreateCompatibleDC(hdc);

	HBITMAP hBmpScreen = CreateCompatibleBitmap(hdc, ScrWidth, ScrHeight);
	HBITMAP holdbmp = (HBITMAP)SelectObject(hmdc, hBmpScreen);

	BITMAP bm;
	GetObject(hBmpScreen, sizeof(bm), &bm);

	BITMAPINFOHEADER bi = { 0 };
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = bm.bmWidth;
	bi.biHeight = bm.bmHeight;
	bi.biPlanes = bm.bmPlanes;
	bi.biBitCount = bm.bmBitsPixel;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = bm.bmHeight * bm.bmWidthBytes;
	// 图片的像素数据
	char *buf = new char[bi.biSizeImage];
	BitBlt(hmdc, 0, 0, ScrWidth, ScrHeight, hdc, rect.left, rect.top, SRCCOPY);
	GetDIBits(hmdc, hBmpScreen, 0L, (DWORD)ScrHeight, buf, (LPBITMAPINFO)&bi, (DWORD)DIB_RGB_COLORS);

	BITMAPFILEHEADER bfh = { 0 };
	bfh.bfType = ((WORD)('M' << 8) | 'B');
	bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bi.biSizeImage;
	bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwWrite;
	WriteFile(hFile, &bfh, sizeof(BITMAPFILEHEADER), &dwWrite, NULL);
	WriteFile(hFile, &bi, sizeof(BITMAPINFOHEADER), &dwWrite, NULL);
	WriteFile(hFile, buf, bi.biSizeImage, &dwWrite, NULL);
	CloseHandle(hFile);
	hBmpScreen = (HBITMAP)SelectObject(hmdc, holdbmp);
}

/*
 *函数名称：PrintScreen()
 *函数参数：无
 *函数功能：ShootScreen函数的包装，按下Alt+Shift+S键自动保存当前置顶窗口的截屏到当前用户下的图片目录（自动根据时间设置文件名）
 *函数返回值：无
*/
void PrintScreen() {
	if (KEY_DOWN(VK_MENU)) {
		if (KEY_DOWN(VK_SHIFT)) {
			if (KEY_DOWN(VK_S)) {
				Sleep(200);
				time_t SaveImg = time(0);
				char imgtmp[32768];
				strftime(imgtmp, sizeof(imgtmp), "Pictures\\MyPic-%Y-%m-%d-%a%H.%M.%S.bmp", localtime(&SaveImg));  //命名图片
				char imgtmp2[32768];
				char currentUser[256] = {0};
				DWORD dwSize_currentUser = 256;
				GetUserName(currentUser, &dwSize_currentUser);    //获取用户名
				sprintf(imgtmp2, "C:\\Users\\%s\\%s", currentUser, imgtmp);           //设置保存目录
				ShootScreen(imgtmp2, GetForegroundWindow());         //保存
				sprintf(imgtmp, "截图保存成功！\n已保存至%s", imgtmp2);             //弹窗提示语
				MessageBox(NULL, imgtmp, "截图工具", MB_OK);                     //弹窗提示
			}
		}
	}
}