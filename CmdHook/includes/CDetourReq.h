#pragma once

#define _TARGET_PROCESS_NAME "hl2.exe"

// Includes win headers
// Many includes are unnnecessary for this project
#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <intrin.h>

#include <windows.h>
#include <winnt.h>
#include <WinBase.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <iostream>
#include <direct.h>
#include <time.h>
#include <Psapi.h>
#include <math.h>

// Pragma comments
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Psapi.lib")

// Namespace defines
using namespace std;

#define GET_INT(x)			(*(int *)	(x))
#define GET_SHORT(x)		(*(short *) (x))
#define GET_BYTE(x)			(*(char *)	(x))
#define GET_FLOAT(x)		(*(float *) (x))
#define GET_DWORD(x)		(*(DWORD *) (x))
#define GET_CHAR(x)			(*(char*)	(x))

typedef unsigned __int8 uint8;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;
typedef unsigned __int64 uint64;

typedef __int8	int8;
typedef __int16 int16;
typedef __int32 int32;
typedef __int64 int64;

#include "ADE32.h"
#include "CDetour.h"