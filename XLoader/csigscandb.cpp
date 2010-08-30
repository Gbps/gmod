// CSigscanDB -- A class to end all sigscan classes
// Written by Gbps.


#include <Windows.h>
#include <interface.h>
#include <string>
#include <vector>
#include <cstring>
#include "sigscan.h"
#include <map>
#include "dbg.h"
#include <algorithm>
#include "config.h"
#include "csigscandb.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

	CSignature::~CSignature(){
		delete[] sFuncName;
		delete[] sSignature;
		delete[] sMask;
		delete[] sModuleName;
		delete pbSigAddr;
	}

	unsigned char* convert(const char *s) {
		std::string hex_chars(s);
		std::istringstream hex_chars_stream(hex_chars);
		std::vector<unsigned char> bytes;

		unsigned int c;
		while (hex_chars_stream >> std::hex >> c)
		{
			bytes.push_back(c);
		}
		return &bytes[0];

	}



	vector<CSignature*> CSigScanDB::m_Database;
	map<const char*,CreateInterfaceFn>CSigScanDB::m_Interfaces;
	CSigScan CSigScanDB::m_SignatureFinder;

	const char* AllocateToHeap(const char* sInput){
		char* alloc = new char[strlen(sInput)+1];
		strcpy(alloc,sInput);
		return alloc;
	}

	string string_removeSpaces( string stringIn )
	{
		string::size_type pos = 0;
		bool spacesLeft = true;

		while( spacesLeft )
		{
			pos = stringIn.find(" ");
			if( pos != string::npos )
				stringIn.erase( pos, 1 );
			else
				spacesLeft = false;
		}

		return stringIn;
	} 


	CSignature* CSigScanDB::CreateSignature(const char* sFuncName,const char* sSignature, const char* sMask, const char* sModuleName){
		CSignature* sigCreated = new CSignature;
		sigCreated->sFuncName = AllocateToHeap(sFuncName);
		sigCreated->sSignature = AllocateToHeap(sSignature);
		sigCreated->sMask = AllocateToHeap(sMask);
		sigCreated->sModuleName = AllocateToHeap(sModuleName);
		sigCreated->bHasFound = false;
		return sigCreated;
	}

	void CSigScanDB::Insert(CSignature* sigToInsert){
		m_Database.insert(m_Database.begin(),sigToInsert);
	}

	void CSigScanDB::Remove(CSignature* sigToRemove){
		int index = -1;
		for (uint32 i=0;i < m_Database.size();i++){
			CSignature* cs = m_Database.at(i);
			if (cs == sigToRemove){
				cs->~CSignature();
				index = i;
			}
		}

		if (index != -1){
			m_Database.erase(m_Database.begin()+index);
		}
	}

	CSignature* CSigScanDB::SearchSig(const char* sFuncName){
		for (uint32 i=0;i < m_Database.size();i++){
			CSignature* cs = m_Database.at(i);
			if (strcmp(cs->sFuncName,sFuncName) == 0){
				return m_Database.at(i);
			}
		}
		return NULL;
	}

	CreateInterfaceFn CSigScanDB::FindInterface(const char* sModuleName){
		CreateInterfaceFn fnCreate = m_Interfaces[sModuleName];
		if (fnCreate != NULL){
			return fnCreate;
		}
		fnCreate = Sys_GetFactory(sModuleName);
		m_Interfaces[sModuleName] = fnCreate;
		return fnCreate;

	}

	PBYTE CSigScanDB::FindSignature(CSignature* sig){

		if(sig->bHasSearched && sig->bHasFound){
			return sig->pbSigAddr;
		}else if (sig->bHasSearched){
			return NULL;
		}

		CreateInterfaceFn fnCreate = FindInterface(sig->sModuleName);
		CSigScan::sigscan_dllfunc = fnCreate;
		if (!CSigScan::GetDllMemInfo()){
			Warning("CSigScanDB : CSigScan::GetDllMemInfo failed for %s!\n",sig->sModuleName);
			return NULL;
		}

		unsigned char* retn = convert(sig->sSignature);
		m_SignatureFinder.Init(retn, (char *)sig->sMask, strlen(sig->sMask));

		if (!m_SignatureFinder.is_set){
			Warning("CSigScanDB : Failed to find signature for %s!\n",sig->sFuncName);
			sig->bHasFound = false;
			sig->bHasSearched = true;
			sig->pbSigAddr = NULL;
			return NULL;
		}

		sig->bHasFound = true;
		sig->bHasSearched = true;
		sig->pbSigAddr = (PBYTE)m_SignatureFinder.sig_addr;
		return sig->pbSigAddr;
	}

	PBYTE CSigScanDB::FindSignature(const char* sSigName){
		return FindSignature(SearchSig(sSigName));
	}

	void CSigScanDB::FindAllSignatures(){
		//for_each(m_Database.begin(),m_Database.end(), &_FindSignature);
	}

	void CSigScanDB::FindFunction(CSignature* sig, void** fnInput){
		PBYTE pbFound = FindSignature(sig);
		*fnInput = pbFound;
	}

	void CSigScanDB::FindFunction(const char* sSigName, void** fnInput){
		FindFunction(SearchSig(sSigName), fnInput);
	}

	void CSigScanDB::Clear(){
		m_Database.clear();
	}

	bool CSigScanDB::LoadSignatureFile(const char* sFileName){
		
		try{

			Config config(sFileName, new char*[0]);
			map<string, Config*> allsigs = config.getGroups();
			for (map<string, Config*>::iterator i = allsigs.begin(); i != allsigs.
				end(); ++i) {
					string groupName = i->first;
					Config* group = i->second;
					string sigStr = group->pString ("Signature");
					string maskStr = group->pString ("Mask");
					string modStr = group->pString ("Module");
					CSignature* sig = CreateSignature(groupName.c_str(),sigStr.c_str(),maskStr.c_str(),modStr.c_str());
					Insert(sig);
			}
			return true;
		}catch(char* str){
			Warning("CSigscanDB: Unable to load signature file! Error: %s",str);
			return false;
		}
	}

	void CSigScanDB::_FindSignature(const pair<const char*, CSignature*>& elem){
		CSignature* sig = elem.second;
		FindSignature(sig);
	}


	