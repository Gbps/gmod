#ifndef GMODMODULECONFIG_H
#define GMODMODULECONFIG_H
#undef _UNICODE


#include "ILuaInterface.h"
#include "CStateManager.h"

#include "GMLuaModule.h"
#include <windows.h>
#include "interface.h"

#ifdef GMOD_MODULE_SIGSCAN
	#pragma warning(disable:4996)
	#include "sigscan.h"
	#include "sigscan.cpp"
#endif

#ifdef GMOD_MODULE_VFNHOOK
	#include "vfnhook.h"
#endif

#ifdef GMOD_MODULE_DETOURS_15
	#include "detours1.5.h"
	#pragma comment(lib, "detours1.5.lib")
#endif

#ifdef GMOD_MODULE_DETOURS_21
	#include "detours2.1.h"
	#pragma comment(lib, "detours2.1.lib")
#endif


#ifdef GMOD_MODULE_EXTENSIONS
	#include "LuaExt.h"
#endif

GMOD_MODULE(Init, Shutdown);
//#include "csimpledetour.h"
//#include "csimplescan.h"

#define GMOD_MODULE_PRINTAUTHOR() gLua->Msg("[%s] Loaded :: By %s :: Version %s\n",GMOD_MODULE_NAME,GMOD_MODULE_AUTHOR,GMOD_MODULE_VERSION)
#endif