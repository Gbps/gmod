#include "GMLuaModule.h"
#include "CStateManager.h"

ILuaInterface* CStateManager::m_Client;
ILuaInterface* CStateManager::m_Menu;
ILuaInterface* CStateManager::m_Server;


ILuaInterface* CStateManager::GetInterface(lua_State* L)
{
	LuaState stateType = ClassifyState( L );
	switch (stateType) {
		case LuaStates::INVALID:
			return NULL;

		case LuaStates::CLIENT:
			return m_Client = modulemanager->GetLuaInterface( L );

		case LuaStates::SERVER:
			return m_Server = modulemanager->GetLuaInterface( L );

		case LuaStates::MENU:
			return m_Menu = modulemanager->GetLuaInterface( L );

		default:
			return NULL;

	}
}

LuaState CStateManager::ClassifyState(lua_State* L)
{

	return ClassifyState(modulemanager->GetLuaInterface(L));

}

LuaState CStateManager::ClassifyState(ILuaInterface* lua)
{
	if(lua == NULL) return LuaStates::INVALID;

	if(lua->IsServer() || lua->IsDedicatedServer()) {
		return LuaStates::SERVER;
	} else if(lua->IsClient()) {
		ILuaObject* MaxPlayers = lua->GetGlobal("MaxPlayers");
		if(MaxPlayers->isFunction()) {
			MaxPlayers->UnReference();
			return LuaStates::CLIENT;
		} else {
			MaxPlayers->UnReference();
			return LuaStates::MENU;
		}
	} else {
		return LuaStates::INVALID;
	}
}


ILuaInterface* CStateManager::GetInterface( LuaState interfaceType )
{

	switch ( interfaceType )
	{

		case LuaStates::CLIENT:
			return m_Client;
			break;
		case LuaStates::SERVER:
			return m_Server;
			break;
		case LuaStates::MENU:
			return m_Menu;
			break;
		default:
			return NULL;
			break;
	}
}

void CStateManager::ShutdownInterface(ILuaInterface* L) {
	LuaState State = ClassifyState(L);
	switch(State) {
		case LuaStates::CLIENT:
			m_Client = 0;
			break;
		case LuaStates::MENU:
			m_Menu = 0;
			break;
		case LuaStates::SERVER:
			m_Server = 0;
			break;
	}
}

void CStateManager::ShutdownInterface(lua_State* L) {
	return ShutdownInterface(modulemanager->GetLuaInterface(L));
}

bool CStateManager::HasState(LuaState type)
{
	return (GetInterface(type) != NULL);
}

// Menu gets first choice
// Then server
// Then client
ILuaInterface* CStateManager::GetByIndex( int idex ){
	switch ( idex ){
		case 0:
			return GetInterface( LuaStates::MENU );
		case 1:
			return GetInterface( LuaStates::SERVER );
		case 2:
			return GetInterface( LuaStates::CLIENT );
		default:
			return NULL;
	}
}