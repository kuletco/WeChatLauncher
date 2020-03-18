// WeChatLauncher.cpp : This file contains the "main" function. Program execution will begin and end here.
//

#include "pch.h"
#include "WeChat.h"
#include "WeChatLauncher.h"

//#ifdef _DEBUG
//#define new DEBUG_NEW
//#endif

using namespace std;

int main()
{
    int nRetCode = 0;
    DWORD pid = 0;

    std::cout << IDS_INFO_LOADING << std::endl;

    nRetCode = OpenWeChat(&pid);
    if (pid <= 0) {
        std::cout << IDS_ERROR_LAUNCHE_APP_FAILED << std::endl;
        nRetCode = -1;
    }

    return nRetCode;
}
