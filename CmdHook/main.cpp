#include "includes/GmodModuleConfig.h"
#include "includes/csimpledetour.h"
#include "includes/csimplescan.h"
#include "includes/cdetour.h"
#include "eiface.h"
#include "includes/CStateManager.h"
#pragma warning (disable : 4099 4075 4996)



typedef void (__cdecl * ExecuteCmdString_t)( byte* inCmd, bool someBool, int someInt);
PBYTE pb_orig_ExecuteString = NULL;
ExecuteCmdString_t tramp_ExecuteString = NULL;

void __cdecl ExecuteCmdString_d( byte* inCmd, bool someBool, int someInt){
	const char* cmd = reinterpret_cast<const char*>(inCmd+8);
	for ( int i=0; i <= 2; i++)
	{
		ILuaInterface* gLua = CStateManager::GetByIndex( i );
		if ( gLua == NULL ){ continue; }
		ILuaObject *hookT = gLua->GetGlobal("hook");
		ILuaObject *callM = hookT->GetMember("Call");
		gLua->Push(callM);
		gLua->Push("OnConCommand");
		gLua->PushNil();
		gLua->Push(cmd);
		callM->UnReference();
		hookT->UnReference();
		gLua->Call(3, 1);

		ILuaObject *retL = gLua->GetReturn(0);

		bool bState = (retL->isNil() || retL->GetBool());
		retL->UnReference();
		if ( bState == false ){
			return;
		}
	}

	tramp_ExecuteString( inCmd, someBool, someInt );


}



CSimpleScan EngineScanner("engine.dll");
CDetour cdetours;
bool isDetoured = false;
int Init(lua_State* L) {
	ILuaInterface* gLua = CStateManager::GetInterface( L );
	if ( isDetoured == false ){
		pb_orig_ExecuteString = (PBYTE)EngineScanner.FindPointer("\x55\x8B\x6C\x24\x08\x8B\x45\x00\x85\xC0\x75\x02\x5D\xC3\x85\xC0\x56\xBE","?xxx?x??x?x??xx??x");
		if (pb_orig_ExecuteString == NULL){
			gLua->Error("[gm_concmdhook] Failed to load hook!");
		}else{
			tramp_ExecuteString = (ExecuteCmdString_t)cdetours.Create((PBYTE)pb_orig_ExecuteString, (PBYTE)&ExecuteCmdString_d, DETOUR_TYPE_JMP);
			isDetoured = true;
		}
	}
	gLua->Msg("[gm_concmdhook] Loaded!\n");
	return 0;
}

int Shutdown(lua_State* L) {
	CStateManager::ShutdownInterface( L );
	if (CStateManager::HasState( LuaStates::MENU )){
		return 0;
	}else if( isDetoured == true){
		isDetoured = false;
		cdetours.Remove((PBYTE)pb_orig_ExecuteString, (PBYTE)tramp_ExecuteString, DETOUR_TYPE_JMP);
	}
	return 0;
}

