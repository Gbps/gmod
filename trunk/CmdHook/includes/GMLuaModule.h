//=============================================================================//
//  ___  ___   _   _   _    __   _   ___ ___ __ __
// |_ _|| __| / \ | \_/ |  / _| / \ | o \ o \\ V /
//  | | | _| | o || \_/ | ( |_n| o ||   /   / \ / 
//  |_| |___||_n_||_| |_|  \__/|_n_||_|\\_|\\ |_|  2008
//										 
//=============================================================================//

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ILuaObject.h"
#include "ILuaShared.h"

#include "ILuaModuleManager.h"

// You should place this at the top of your module
#define GMOD_MODULE( _startfunction_, _closefunction_ ) \
	ILuaModuleManager* modulemanager = NULL;\
	int _startfunction_( lua_State* L );\
	int _closefunction_( lua_State* L );\
	extern "C" int __declspec(dllexport) gmod_open( ILuaInterface* i ) \
	{ \
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		modulemanager = i->GetModuleManager();\
		lua_State* L = (lua_State*)(i->GetLuaState());\
		return _startfunction_( (lua_State*) CStateManager::GetInterface( L )->GetLuaState() );\
	}\
	extern "C" int __declspec(dllexport) gmod_close( lua_State* L ) \
	{\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		__asm { nop }\
		_closefunction_( L );\
		return 0;\
	}\

#define LUA_FUNCTION( _function_ ) static int _function_( lua_State* L )