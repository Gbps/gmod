
#define GMOD_MODULE_PRINTINFO
#define GMOD_MODULE_AUTHOR "Gbps"
#define GMOD_MODULE_NAME "gm_addonissimo"
#define GMOD_MODULE_VERSION "1.0"

#include "includes/GmodModuleConfig.h"
#include <string.h>
#include <iostream>

#include "includes/csimpledetour.h"
#include "includes/csimplescan.h"
#include "includes/cdetour.h"
#include "eiface.h"
#pragma warning (disable : 4099 4075 4996)
using namespace std; // Yeah yeah


//////////////////////////////////////////////////////////////////////////
//				       Addon Loading Detours                                        //
//////////////////////////////////////////////////////////////////////////

bool _AddonLoadDetour(const char* sScriptLoadPath, const char* sScriptSideIdent){

	string path (sScriptLoadPath); 
	size_t AddonPos = path.find("addons/");
	if (AddonPos == string::npos) return true; // Not loading an addon, so go ahead and load whatever it is...
	string SubStrCheck = path.substr(path.length()-4);
	if (SubStrCheck.compare("/lua") != 0) return true; // This should never really happen...

	string FolderName = path.substr(AddonPos+7,(path.length()-4)-(AddonPos+7)); // Extract the folder name
	ILuaObject *hookT = gLua->GetGlobal("hook");
		ILuaObject *callM = hookT->GetMember("Call");
			gLua->Push(callM);
			gLua->Push("ShouldLoadAddon");
			gLua->PushNil();
			gLua->Push(FolderName.c_str());
			gLua->Push(sScriptSideIdent);
		callM->UnReference();
		hookT->UnReference();
		gLua->Call(4, 1);

	ILuaObject *retL = gLua->GetReturn(0);

	bool bState = (retL->isNil() || retL->GetBool());

	retL->UnReference();

	return bState;
}

ILuaShared* oILuaShared = NULL;

typedef  void		(__stdcall *  MountLuaAdd_t) (const char * sPath, const char* pathID);
MountLuaAdd_t MountLuaAdd_o = NULL;

typedef DWORD (__cdecl * GetILuaShared_t)();
GetILuaShared_t GetILuaShared = NULL;

void __stdcall MountLuaAdd_d(const char * sPath, const char* pathID){
	void * pThis = NULL;
	__asm mov pThis, ecx
		
	if (_AddonLoadDetour(sPath, pathID)){
		__asm
		{
			push pathID
			push sPath
			mov ecx, pThis
			call MountLuaAdd_o;
		}
	}
}

LUA_FUNCTION (ReloadAddonList){
	int* AddonNumber = reinterpret_cast<int*>(((PBYTE)oILuaShared)+0x802C);
	if (AddonNumber == NULL) { Warning("Addon number was 0 or NULL?\n"); return 0; }
	Msg("Addon Number: %i\n",*AddonNumber);
	(*AddonNumber) = 0; // Basically we're forcing the size to 0. Not a very good way of doing it tbh, but it works.
						// It's probably a std::map, which means it will grow to the maximum size it needs.
						// Even if there were old entries, it should overwrite them, so it shouldn't be too horribly bad :F
						// But memory leaks... who knows :(

	oILuaShared->MountAddons();
	return 0;
}


CSimpleScan Scanner("lua_shared.dll");
CSimpleScan ScannerCl("client.dll");
////////////////////////////////////////////////////////////////////////////
//		                   End Addon Loading Detours                     //
//////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////
//				       Begin Command Hooking                             //
//////////////////////////////////////////////////////////////////////////

IVEngineServer* g_Engine = NULL;

typedef void (__cdecl * ExecuteCmdString_t)(const char* cmdStr);

PBYTE pb_orig_ExecuteString = NULL;
ExecuteCmdString_t tramp_ExecuteString = NULL;



void __stdcall ExecuteCmdString_d(const char* cmdStr){
	void* retAddr = NULL;
	void* pThis = NULL;
	__asm mov pThis, ecx

	ILuaObject *hookT = gLua->GetGlobal("hook");
	ILuaObject *callM = hookT->GetMember("Call");
	gLua->Push(callM);
	gLua->Push("OnCommandRan");
	gLua->PushNil();
	gLua->Push(cmdStr);
	callM->UnReference();
	hookT->UnReference();
	gLua->Call(3, 1);

	ILuaObject *retL = gLua->GetReturn(0);

	bool bState = (retL->isNil() || retL->GetBool());

	retL->UnReference();

	
	if (bState){
		__asm{
			MOV ECX,pThis
			PUSH cmdStr
			CALL tramp_ExecuteString
		}
	}

}

LUA_FUNCTION (ExecuteCmdString){
	gLua = Lua();
	gLua->CheckType(1,GLua::TYPE_STRING);
	g_Engine->ServerCommand(gLua->GetString());
	return 0;
}

CSimpleScan EngineScanner("engine.dll");

////////////////////////////////////////////////////////////////////////////
//				       End Command Hooking                                          //
//////////////////////////////////////////////////////////////////////////




CDetour cdetours;

int Init(lua_State* L) {
	gLua = Lua();
	GMOD_MODULE_PRINTAUTHOR();
	g_Engine = ( IVEngineServer* ) Sys_GetFactory("engine.dll")( INTERFACEVERSION_VENGINESERVER, NULL );

	ILuaObject* tbl = gLua->GetGlobal("Addonissimo");
		tbl->SetMember("ExecuteClientCmd",ExecuteCmdString);
		tbl->SetMember("ReloadAddonList",ReloadAddonList);
	tbl->UnReference();


	PBYTE luaSharedCallAddr = (PBYTE)ScannerCl.FindPointer("\xE8\x48\xD8\xFF\xFF\x8B\x0D\x9C\xFD\x4D\x18\x83\x79\x14\x01\x8D\x4C\x24\x03\x51\x0F\x9F\xC2\x88\x54\x24\x08\x8B\x4C\x24\x08\x8B","x????xx????xxxxxxxxxxxxxxx?xxx?x");
	DevMsg(" > Addonissimo : Lua Shared function found at %p\n",luaSharedCallAddr);
	if (luaSharedCallAddr == NULL){
		gLua->Error("*********************************************************\n");
		gLua->Error("*     Vtable signature failed... Post about it!         *\n");
		gLua->Error("*********************************************************\n");
		return 1;
	}

	int luaSharedOffset = *(reinterpret_cast<int*>(luaSharedCallAddr+1));
	PBYTE luaSharedFuncAddr = luaSharedCallAddr + luaSharedOffset + 5;
	GetILuaShared = (GetILuaShared_t)luaSharedFuncAddr;
	DWORD ILuaSharedAddr = GetILuaShared();
	oILuaShared = reinterpret_cast<ILuaShared*>(ILuaSharedAddr);
	void*** ILuaSharedVTable = (void***)ILuaSharedAddr;
	void* MountLuaAdd_a = (*ILuaSharedVTable)[16];

	pb_orig_ExecuteString = (PBYTE)EngineScanner.FindPointer("\x8B\x44\x24\x04\x50\xE8\x56\x6C\xF5\xFF\x68\x04\x8C\x2D\x10\xE8\x4C\x6C\xF5\xFF\x83\xC4\x08\xC2\x04\x00","x?xx?x????x????x????xx?xxx");
	
	if (pb_orig_ExecuteString == NULL){

		gLua->Msg("**** Addonissimo failed to load command hooking interface... Functionality has been disabled!\n");

	}else{
		tramp_ExecuteString = (ExecuteCmdString_t)cdetours.Create((PBYTE)pb_orig_ExecuteString, (PBYTE)&ExecuteCmdString_d, DETOUR_TYPE_JMP);
	}

	Msg("Add Search Path: %p\n",MountLuaAdd_a);
	if (MountLuaAdd_a != NULL){
		DevMsg(" > Addonissimo : Search Path Found At %p\n",MountLuaAdd_a);
		MountLuaAdd_o = (MountLuaAdd_t)cdetours.Create((PBYTE)MountLuaAdd_a, (PBYTE)&MountLuaAdd_d, DETOUR_TYPE_JMP);
	}else{
		gLua->Msg("*********************************************************\n");
		gLua->Msg("*      LoadAddon function failed... Post about it!      *\n");
		gLua->Msg("*********************************************************\n");
		return 1;
	}

	return 0;
}

int Shutdown(lua_State* L) {
	return 0;
}

