#pragma once

#include "targetver.h"
#include <stdio.h>
#include <tchar.h>
#include <iostream>

// Exclude rarely used content from Windows header files
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "shlwapi")
#pragma comment(lib, "Advapi32")
#pragma comment(lib, "Version.lib")

// Hide Console Window
#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")
