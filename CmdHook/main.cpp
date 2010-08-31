#include "includes/GmodModuleConfig.h"
#include "includes/csimpledetour.h"
#include "includes/csimplescan.h"
#include "includes/cdetour.h"

#include "eiface.h"
#include "includes/CStateManager.h"
#include "net_stringcmd.h"
#include <interface.h>
#include "cbase.h"
#include "inetmessage.h"
#include "inetchannel.h"
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

PBYTE processStringCmd_o;
typedef void (__stdcall * processStringCmd_t)( void* msg );
processStringCmd_t processStringCmd_f;

void __stdcall processStringCmd_d( NET_StringCmd* msg )
{
	void* oThis = NULL;
	__asm { mov oThis, ECX }
	ILuaInterface* gLua = CStateManager::GetInterface( LuaStates::SERVER );

	ILuaObject *hookT = gLua->GetGlobal("hook");
	ILuaObject *callM = hookT->GetMember("Call");
	gLua->Push(callM);
	gLua->Push("OnConCommand");
	gLua->PushNil();
	gLua->Push(msg->GetCommand());
	INetChannel* recv = msg->GetNetChannel();
	gLua->Push(recv->GetAddress());
	callM->UnReference();
	hookT->UnReference();
	gLua->Call(4, 1);

	ILuaObject *retL = gLua->GetReturn(0);

	bool bState = (retL->isNil() || retL->GetBool());
	if ( bState == false ){
		__asm{
			MOV ECX, oThis
			PUSH msg
			CALL processStringCmd_f
		}
	}
}

CSimpleScan EngineScanner("engine.dll");
CDetour cdetours;
bool isDetoured = false;
int Init(lua_State* L) {
	ILuaInterface* gLua = CStateManager::GetInterface( L );
	if ( isDetoured == false )
	{
		pb_orig_ExecuteString = (PBYTE)EngineScanner.FindPointer("\x55\x8B\x6C\x24\x08\x8B\x45\x00\x85\xC0\x75\x02\x5D\xC3\x85\xC0\x56\xBE","?xxx?x??x?x??xx??x");
		if (pb_orig_ExecuteString == NULL){
			gLua->Error("[gm_concmdhook] Failed to load hook!");
		}else{
			tramp_ExecuteString = (ExecuteCmdString_t)cdetours.Create((PBYTE)pb_orig_ExecuteString, (PBYTE)&ExecuteCmdString_d, DETOUR_TYPE_JMP);
			isDetoured = true;
		}

		//////////////////////////////////////////////////////////////////////////

		if ( CStateManager::ClassifyState( L ) == LuaStates::SERVER ){
			processStringCmd_o = (PBYTE)EngineScanner.FindPointer("\x0F\xB6\x81\x60\x4A\x00\x00\x8B\x54\x24\x04\x50\x52\x83\xC1\xF8", "xxxxxxxxxxxxxxxx");
			if (processStringCmd_o == NULL){
				gLua->Error("[gm_concmdhook] Failed to load network hook!");
			}else{
				processStringCmd_f = (processStringCmd_t)cdetours.Create((PBYTE)processStringCmd_o, (PBYTE)&processStringCmd_d, DETOUR_TYPE_JMP);
			}
		}
	}
	gLua->Msg("[gm_concmdhook] Loaded!\n");
	return 0;
}

int Shutdown(lua_State* L) {
	if ( CStateManager::HasState( LuaStates::MENU ) && 
		!CStateManager::HasState( LuaStates::CLIENT ) &&
		!CStateManager::HasState( LuaStates::SERVER ) ){
		isDetoured = false;
		cdetours.Remove((PBYTE)pb_orig_ExecuteString, (PBYTE)tramp_ExecuteString, DETOUR_TYPE_JMP);
	}
	if (CStateManager::ClassifyState( L ) == LuaStates::SERVER ){
		cdetours.Remove((PBYTE)processStringCmd_o, (PBYTE)processStringCmd_f, DETOUR_TYPE_JMP);
	}
	CStateManager::ShutdownInterface( L );
	if (CStateManager::HasState( LuaStates::MENU )){
		return 0;
	}else if( isDetoured == true){
		isDetoured = false;
		cdetours.Remove((PBYTE)pb_orig_ExecuteString, (PBYTE)tramp_ExecuteString, DETOUR_TYPE_JMP);
	}
	return 0;
}

