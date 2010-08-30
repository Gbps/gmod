#ifndef CSTATEMANGER_H
#define CSTATEMANGER_H

namespace LuaStates
{
	enum
	{
		INVALID = -1,
		SERVER,
		CLIENT,
		MENU
	};
}

typedef int LuaState;

class CStateManager {
private:

	static ILuaInterface* m_Client;
	static ILuaInterface* m_Server;
	static ILuaInterface* m_Menu;

public:

	static ILuaInterface* GetInterface (lua_State* L);

	static LuaState ClassifyState (lua_State* L);
	static LuaState ClassifyState (ILuaInterface* L);

	static ILuaInterface* GetInterface(LuaState interfaceType);

	static void ShutdownInterface(ILuaInterface* L);
	static void ShutdownInterface(lua_State* L);

	static bool HasState(LuaState type);
	static ILuaInterface* GetByIndex( int idex );
};

#endif // CSTATEMANGER_H