// credit to LauCorp and Gbps
#include "interface.h"
#include "filesystem.h"
#include <Windows.h>
#ifdef _WIN32
#pragma once
#endif

struct ScriptData
{
	char path[MAX_PATH];
	int crc;
	char* contents;
	int timestamp;
	bool somebool;
};

class AddonListEntry{
private:
	PBYTE m_Obj;
public:
	const char* FolderName;
	const char* AddonName;
	const char* Version;
	const char* Author;
	const char* ContactEmail;
	const char* WebAddr;
	const char* Description;
	const char* UpdateDate;

	AddonListEntry(PBYTE Obj){
		m_Obj = Obj;
		FolderName = reinterpret_cast<const char*>(m_Obj);
		AddonName  = reinterpret_cast<const char*>(m_Obj+64);
		Version  = reinterpret_cast<const char*>(m_Obj+64+128);
		Author  = reinterpret_cast<const char*>(m_Obj+64+128+32);
		ContactEmail =  reinterpret_cast<const char*>(m_Obj+64+128+32+144);
		WebAddr =  reinterpret_cast<const char*>(m_Obj+64+128+32+128+128);
		Description =  reinterpret_cast<const char*>(m_Obj+64+128+32+128+128+128);
		UpdateDate =  reinterpret_cast<const char*>(m_Obj+64+128+32+128+128+128+128);
	}

};


class ILuaShared
{

public:
	int GetNumberOfAddonsInList(){
		return *((DWORD *)this + 8203);
	}

	AddonListEntry* GetAddonEntryAtIndex(int i){
		return new AddonListEntry(reinterpret_cast<PBYTE>((i*864) + *((DWORD *)GetAddonList())));
	}

public:
	virtual void			AllocateSomething(bool arg1);
	virtual bool			Initiate(CreateInterfaceFn FileSystemInterface, bool Something, void* SteamAppsSomething);
	virtual void			Removed();
	virtual void			Removed2();
	virtual void			UpdateContentFile();
	virtual void			PrintLuaFileStats();
	virtual void*		    GetSomeMutex(void* SomeArg);
	virtual void			SetSomeMutex(void* SomeArg);
	virtual ScriptData*		LuaGetFile(const char *file);
	virtual void			LuaGetFile2(); // Only used to load entities... odd.
	virtual void*			GetSomeInterface();
	virtual void			MountDefaultGames();
	virtual void			UpdateAddonList();
	virtual void			UpdateGamemodeListAndContent(); // maybe another argument?
	virtual void			SetupDefaultSearchPaths(const char* ScriptSide, bool something); // ScriptSide = "SLUA", "CLUA", "VLUA", something = true
	virtual void			AddLuaSearchPath(const char* Path, const char* ScriptSide);
	virtual void			RemoveSearchPaths();
	virtual PBYTE			GetAddonList();
	virtual void*			GetSomeInterface2();
	virtual void*			GetSomeInterface3();
	virtual int				LZMACompress(BYTE* inputAndOutputBuffer, int& ErrorCode, int& LZMAReturnCode); // return = end size.
	virtual int				LZMADecompress(BYTE* inputBuffer, BYTE* outputBuffer);	
	virtual void*			GetSomeSQLiteOffset(void* input); // +128
	virtual int 			MountToFolder(const char* name, int repoID);
	virtual void			SetSomethingOrOther();
	virtual void			DoSomethingOrOther();
};