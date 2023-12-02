#include <cmath>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <windows.h>
#include <algorithm>
using namespace std;
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)//获取按键

/*_____________________________________基础类型定义_________________________________________*/

/*
 *结构体名称：Button
 *定义名称：Button
 *结构体定义：表示一个控制台按钮
 *可用于的函数：NewButton、TestButton
*/
struct Button {
	HWND hwnd;
	int x, y; //按钮位置和颜色
	const char *name;//名字
	int len;//名字的长度
};



void GetPos(POINT &pt) {
//POINT是自带类型
	HWND hwnd = GetForegroundWindow();
	GetCursorPos(&pt);
	ScreenToClient(hwnd, &pt);
	pt.y = pt.y / 16, pt.x = pt.x / 16; //除以16，想不明白自己把它去掉试试
}

void color(int a) {
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), a);
}

void gto(int x, int y) {
	COORD pos;
	pos.X = y * 2;
	pos.Y = x;
	//必须反过来
	//y*2是因为汉字是2个字符
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}



/*
 *函数名称：NewButton(x, y, name, hwnd*)
 *函数参数：
 *	x：按键的x位置
 *	y：按键的y位置
 *	name：按键将要显示的字符
 *	hwnd：按键所属窗口句柄（默认不需要输入该参数，直接为NULL）
 *函数功能：在控制台指定行列打印按钮
 *函数返回值：Button结构体类型
 *	返回值使用：
 *		Button b1 = NewButton(x, y, "A New Button")
*/
Button NewButton(int x, int y, const char *name, HWND hwnd = NULL) {
	Button t;
	t.x = x, t.y = y, t.name = name;
	t.len = strlen(name);
	t.hwnd = hwnd;
	return t;//新建按钮，返回它
}

/*
 *函数名称：TestButton(Bt)
 *函数参数：
 *	Bt：定义过的Button类型结构体
 *函数功能：检测已创建的按键状态
 *函数返回值：bool类型
 *	为true：按键被按下
 *	为false：按键未被按下
*/
bool TestButton(Button Bt) {
	gto(Bt.x, Bt.y), color(BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY), printf("%s",
	        Bt.name);
	POINT pt;
	GetPos(pt);
	if (pt.y == Bt.x && (pt.x >= Bt.y && pt.x <= Bt.y + Bt.len / 2)) {
		color(BACKGROUND_GREEN), gto(Bt.x, Bt.y), printf("%s", Bt.name);
		if (KEY_DOWN(MOUSE_MOVED)) {
			return 1;//检测到点击按钮
		}
	}
	return 0;//没有检测到
}