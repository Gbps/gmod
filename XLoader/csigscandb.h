// CSigscanDB -- A class to end all sigscan classes
// Written by Gbps.

#include <Windows.h>
#include <interface.h>
#include <string.h>
#include <vector>
#include <cstring>
#include "sigscan.h"
#include <map>
#include "dbg.h"
#include <algorithm>
#include "config.h"

using namespace std;



class CSignature;


class CSigScanDB {

private:

	static vector<CSignature*> m_Database;
	static map<const char*,CreateInterfaceFn> m_Interfaces;
	static CSigScan m_SignatureFinder;

public:

	static CSignature* CreateSignature(const char* sFuncName,const char* sSignature, const char* sMask, const char* sModuleName);

	static void Insert(CSignature* sigToInsert);

	static void Remove(CSignature* sigToRemove);

	static CSignature* SearchSig(const char* sFuncName);

	static CreateInterfaceFn FindInterface(const char* sModuleName);

	static PBYTE FindSignature(CSignature* sig);

	static PBYTE FindSignature(const char* sSigName);

	static void FindAllSignatures();

	static void FindFunction(CSignature* sig, void** fnInput);

	static void FindFunction(const char* sSigName, void** fnInput);

	static void Clear();

	static bool LoadSignatureFile(const char* sFileName);

private:

	static void _FindSignature(const pair<const char*, CSignature*>& elem);

};

class CSignature{
public:
	friend CSigScanDB;
	~CSignature();
	const char* sFuncName;
	const char* sSignature;
	const char* sMask;
	const char* sModuleName;
	bool bHasSearched;
	bool bHasFound;
	PBYTE pbSigAddr;

	PBYTE FindAddr(){
		return CSigScanDB::FindSignature (this);
	}

	void FindFunction(void** func){
		CSigScanDB::FindFunction (this,func);
	}

};