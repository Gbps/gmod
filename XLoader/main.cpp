#undef Verify 


#include "includes/GmodModuleConfig.h"
#include "c5/osrng.h"
#include "c5/rsa.h"
#include "c5/modes.h"
#include "c5/aes.h"
#include "c5/pssr.h"
#include "c5/files.h"
#include "RSAKey.h"
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <strstream>
#include "cdll_int.h"
#include "includes/csimplescan.h"
#include "includes/cdetour.h"
#include "includes/base64/base64.h"

char* g_FileHeader = "if XLOAD then XLOAD() else Msg(\"This file requires XLoader 1.0 to run.\\n\") end --";
IFileSystem* g_FileSystem = NULL;


CryptoPP::RSA::PrivateKey *privateKey;
CryptoPP::RSA::PublicKey *publicKey;
CryptoPP::AutoSeededRandomPool *rng;

#define uchar unsigned char
#define __RSA_ENCENABLED

struct LoadS {
	const char *strData;
	size_t size;
};

struct Zio {
	size_t n;                     /* bytes still unread */
	const char *p;                /* current position in buffer */
	void* reader;				  /* reader function */
	LoadS* data;                   /* additional data */
	lua_State *L;                 /* Lua state (for reader) */
};


class MemReader{
private:
	void* m_FilePointer;
public:
	MemReader(void* filePointer){
		m_FilePointer = filePointer;
	}

	void mread(void* _Dest, int length){
		memcpy(_Dest,m_FilePointer,length);
		push(length);
	}

	void push(int length){
		byte* bytePtr = reinterpret_cast<byte*>(m_FilePointer);
		bytePtr += length;
		m_FilePointer = bytePtr;
	}
};


void OffsetCopy(byte *input, byte *input2, int offset1, int offset2){
	memcpy(input+offset1,input2+offset2,4);
}

void OffsetCopy2(byte *input, byte *input2, int offset1, int offset2){
	memcpy(input2+offset2,input+offset1,4);
}

struct SignatureSizes{
	int RSASignature_B64;
	int CustomSignature_B64;
	int Payload_B64;
	int RSASignature;
	int CustomSignature;
	int Payload;
};

class CDecryptor {
public:
	unsigned char* AESKey;
	unsigned char* AESIV;
	unsigned char* Payload;
	SignatureSizes sizes;
	int returnCode;

	~CDecryptor(){
		delete[] AESKey;
		delete[] AESIV;
	//	delete[] Payload;
	}

	CDecryptor( const char* input ){

		MemReader mem((void*)input);
		AESKey = new unsigned char[16];
		AESIV = new unsigned char[16];

		// Allocate space for the header
		int len = strlen(g_FileHeader);
		uchar* Header = new uchar[len];

		// Read the header into the buffer
		mem.mread(Header,len);

		// Compare the headers
		if (memcmp(Header,g_FileHeader,len) != 0){
			returnCode = 1;
			return;
		}

		// Write the three block sizes
		int pushVal = 0;
		sscanf_s(input+len,"|%d|%d|%d|%d|%d|%d|%n",
			&sizes.RSASignature_B64,
			&sizes.CustomSignature_B64,
			&sizes.Payload_B64,
			&sizes.RSASignature,
			&sizes.CustomSignature,
			&sizes.Payload,
			&pushVal);

		// Push the pointer to align with the RSA values
		mem.push(pushVal);

		// Read the RSA signature
		byte* pRSASignature_base64 = new byte[sizes.RSASignature_B64];

		mem.mread(pRSASignature_base64, sizes.RSASignature_B64);

		// THANK YOU SO MUCH HAZA YOU ARE THE BEST HOLY CRAP
		// I WOULD HAVE NEVER EVER FOUND THAT ERROR HAD YOU NOT HELPED ME

		std::string pRSASignature_base64_s = base64_decode(pRSASignature_base64,sizes.RSASignature_B64);
		byte* pRSASignature = (byte*)pRSASignature_base64_s.c_str();
		delete[] pRSASignature_base64;

		// Read custom signature
		byte* pCustSignature_base64 = new byte[sizes.CustomSignature_B64];
		mem.mread(pCustSignature_base64,sizes.CustomSignature_B64);
		std::string pCustSignature_base64_s = base64_decode(pCustSignature_base64,sizes.CustomSignature_B64);
		byte* pCustSignature = (byte*)pCustSignature_base64_s.c_str();
		delete[] pCustSignature_base64;

		// Read the payload
		uchar* pPayload_base64 = new uchar[sizes.Payload_B64];
		mem.mread(pPayload_base64,sizes.Payload_B64);
		std::string pPayload_base64_s = base64_decode(pPayload_base64,sizes.Payload_B64);
		byte* pPayload = (byte*)pPayload_base64_s.c_str();
		Payload = (unsigned char*)new char[sizes.Payload];
		delete[] pPayload_base64;


		// Import the public key
		CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA1>::Verifier dec( *publicKey );

		bool result = dec.VerifyMessage( pPayload,
			sizes.Payload, pRSASignature, sizes.RSASignature );

		if (result == false){
			sizes.Payload = 0;
			returnCode = 2;
		}else{
			// This does nothing but confuses debuggers
			sizes.CustomSignature = 0;
			returnCode = 3;
		}

		OffsetCopy2(pCustSignature,AESIV,0,0);
		OffsetCopy2(pCustSignature,AESKey,4,12); 
		OffsetCopy2(pCustSignature,AESKey,8,0);
		OffsetCopy2(pCustSignature,AESKey,12,4);
		OffsetCopy2(pCustSignature,AESIV,16,4);
		memcpy(Payload,pPayload,sizes.Payload);
		OffsetCopy2(pCustSignature,AESIV,20,8);
		OffsetCopy2(pCustSignature,AESKey,24,8);
		OffsetCopy2(pCustSignature,AESIV,28,12);

		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfbDecryption(AESKey, 16, AESIV);
		cfbDecryption.ProcessData(Payload, pPayload, sizes.Payload);
		
		returnCode = 4;
	}
};

void InitiateKeys(){
	rng = new CryptoPP::AutoSeededRandomPool();
	/////////////////////////////////////////////	

	CryptoPP::Integer n("126291968685651303138538747330922916420251250137154579085628225298184609361774212598179645401572332777180113752367416338095749244117274028516905025610538938292861009545212998011792688883749768436246825352483705633182460320559325050132126804298632470284797268467544189621718727742679712559702779077535597228397");
#ifdef __RSA_ENCENABLED
	CryptoPP::Integer d("17334191780383512195485710417969812057681544136472197129399952491907691481027833101710931721784437832161976397383763026797455778604331729404281081946544557065984946991511229014590248585539894439124049341034773177992692776292012265943318985180001023225444043412550917458688560678914550388396545357528860954685");
#endif
	CryptoPP::Integer e("17");

	/////////////////////////////////////////////
#ifdef __RSA_ENCENABLED
	privateKey = new CryptoPP::RSA::PrivateKey( );
	privateKey->Initialize(n,e,d);
#endif

	publicKey = new CryptoPP::RSA::PublicKey( );
	publicKey->Initialize(n,e);
}

#ifdef __RSA_ENCENABLED
class CEncryptor {
private:
	unsigned char* AESKey;
	unsigned char* AESIV;
	const byte* m_Payload;
public:


	CEncryptor(){
		AESKey = new unsigned char[16];
		AESIV = new unsigned char[16];
	}

	~CEncryptor(){
		delete[] AESKey;
		delete[] AESIV;
		delete[] m_Payload;
	}

	void SetPayload(const byte* Payload){
		m_Payload = Payload;
	}


	void GenerateAES(){
		// Implement
		byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
		rng->GenerateBlock(key, CryptoPP::AES::DEFAULT_KEYLENGTH);

		// Generate a random IV
		byte iv[CryptoPP::AES::BLOCKSIZE];
		rng->GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);

		// Copy to variables
		memcpy(AESKey,key,16);
		memcpy(AESIV,iv,16);

	}

	bool WriteFile(FILE* input){
		// Size of the signature
		int sigSize = 16 + 16;

		// Write a predefined header
		fwrite(g_FileHeader,sizeof(char),strlen(g_FileHeader),input);

		// Import our private key
		CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA1>::Signer enc( *privateKey );

		// Create holder objects
		byte* sigOutput = new byte[sigSize];
		int payLen = strlen((const char*)m_Payload)+1;
		unsigned char* payInputOutput = new unsigned char[payLen];

		// Generate a random AES key to use
		GenerateAES();

		// Copy the key and iv
		OffsetCopy(sigOutput,AESIV,0,0);
		OffsetCopy(sigOutput,AESKey,4,12); 
		OffsetCopy(sigOutput,AESKey,8,0);
		OffsetCopy(sigOutput,AESKey,12,4);
		OffsetCopy(sigOutput,AESIV,16,4);
		OffsetCopy(sigOutput,AESIV,20,8);
		OffsetCopy(sigOutput,AESKey,24,8);
		OffsetCopy(sigOutput,AESIV,28,12);

		// Copy the payload to the AES in/out
		memcpy(payInputOutput, m_Payload, payLen);

		// Initiate the encryption
		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(AESKey, 16, AESIV);


		cfbEncryption.ProcessData(payInputOutput, payInputOutput, payLen);


		size_t ecl = enc.MaxSignatureLength();
		CryptoPP::SecByteBlock signature( ecl );
		if (ecl == 0){
			Warning("XLoader Error: Pre-Signature Length is 0\n");
			return false;
		}

		enc.SignMessage( *rng, payInputOutput, payLen, signature );


		// Test the signature.

		CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA1>::Verifier dec( *publicKey );

		bool result = dec.VerifyMessage( payInputOutput, payLen, signature, ecl );

		if (result == false)
		{
			Warning("XLoader Error: Signature didnt veryify in Encryption state. RSA is broken.\n");
		}

		// Encode everything into base64 so there are no bad characters

		std::string base64_payload = base64_encode(payInputOutput,payLen);
		std::string base64_rsa_signature = base64_encode(signature.data(),signature.size());
		std::string base64_cust_signature = base64_encode(sigOutput,sigSize);

		SignatureSizes sizes;
		sizes.RSASignature_B64 = base64_rsa_signature.length();
		sizes.CustomSignature_B64 = base64_cust_signature.length();
		sizes.Payload_B64 = base64_payload.length();
		sizes.RSASignature = signature.size();
		sizes.CustomSignature = sigSize;
		sizes.Payload = payLen;

		// Write the three block sizes
		fprintf_s(input,"|%d|%d|%d|%d|%d|%d|",
			sizes.RSASignature_B64,
			sizes.CustomSignature_B64,
			sizes.Payload_B64,
			sizes.RSASignature,
			sizes.CustomSignature,
			sizes.Payload);

		// Write SHA signature
		fwrite(base64_rsa_signature.c_str(), sizeof(char), sizes.RSASignature_B64, input);

		// Write custom signature
		fwrite(base64_cust_signature.c_str(), sizeof(char), sizes.CustomSignature_B64, input);

		// Write payload
		fwrite(base64_payload.c_str(),sizeof(char), sizes.Payload_B64,input);

		// Cleanup
		delete[] sigOutput;
		delete[] payInputOutput;

		fclose(input);


		return true;
	}
};


LUA_FUNCTION(L_EncryptFile){
	gLua = Lua();
	gLua->CheckType(1,GLua::TYPE_STRING);
	gLua->CheckType(2,GLua::TYPE_STRING);
	gLua->CheckType(3,GLua::TYPE_STRING);

	const char* fileNameSource = gLua->GetString(1);
	const char* fileNameDestination = gLua->GetString(2);
	const char* fileNameOldFile = gLua->GetString(3);

	if (g_FileSystem->FileExists(fileNameSource,"MOD")){
		FileHandle_t fileHandle;								// Create handle
		fileHandle = g_FileSystem->Open(fileNameSource,"rb","MOD");	// Open file
		int fileSize = g_FileSystem->Size(fileHandle);			// Read file size
		char* fileContents = new char[fileSize + 1];			// Allocate space for the file
		g_FileSystem->Read(fileContents,fileSize,fileHandle);	// Read the file
		fileContents[fileSize] = '\0';							// Apply null byte to end to make it a string
		g_FileSystem->Close(fileHandle);						// Close the file

		//////////////////////////////////////////////////////////////////////////

		CEncryptor enc;
		enc.SetPayload((byte*)fileContents);

		char* extendedFileName = new char[strlen("garrysmod\\") + strlen(fileNameDestination) + 1];
		extendedFileName[0] = '\0';
		strcat(extendedFileName,"garrysmod\\");
		strcat(extendedFileName,fileNameDestination);

		FILE* fileCLua = fopen(extendedFileName,"wb");
		enc.WriteFile(fileCLua);
		fclose(fileCLua);

		delete[] extendedFileName;

		//////////////////////////////////////////////////////////////////////////

		fileHandle = g_FileSystem->Open(fileNameOldFile,"wb","MOD");
		g_FileSystem->Write(fileContents,strlen(fileContents),fileHandle);
		g_FileSystem->Close(fileHandle);

		//delete[] fileContents;

		gLua->Push(true);
		return 1;

	}else{
		gLua->Push(false);
		return 1;
	}


}

#endif

class CPrecisionTimer
{
public:
	double Stop()
	{
		LARGE_INTEGER curval;
		QueryPerformanceCounter(&curval);
		long double f = ToDouble(m_start);
		long double f1 = ToDouble(curval);
		long double f3 = ToDouble(m_freq);
		return (f1 - f)/f3;
	}
	long double ToDouble(LARGE_INTEGER& val) { long double f = val.u.HighPart; f = f * (DWORD)-1; f += val.u.LowPart; return f; }
	void Start() { QueryPerformanceCounter(&m_start); }
	CPrecisionTimer() { QueryPerformanceFrequency(&m_freq); }
	virtual ~CPrecisionTimer() {};
private:
	LARGE_INTEGER m_start;
	LARGE_INTEGER m_freq;
};

LUA_FUNCTION(L_TestLoadFile){
	/*gLua = Lua();
	gLua->CheckType(1,GLua::TYPE_STRING);

	const char* fileNameDestination = gLua->GetString(1);
	char* extendedFileName = new char[strlen("garrysmod\\") + strlen(fileNameDestination) + 1];
	extendedFileName[0] = '\0';
	strcat(extendedFileName,"garrysmod\\");
	strcat(extendedFileName,fileNameDestination);
	FILE* f = fopen(extendedFileName,"rb");
	CDecryptor dec(f);
	if (dec.returnCode == 1){
		Msg("File is not encrypted!\n");
		return 0;
	}else if(dec.returnCode == 3 || dec.returnCode == 4){
		gLua->RunString(fileNameDestination,fileNameDestination,const_cast<const char*>((char*)dec.Payload),true,true);
	}
	delete[] extendedFileName;
	return 0;
	*/
	return 0;
}

typedef int (__cdecl * luaD_protectedparser_t)(lua_State *L, Zio *z, const char *name);
luaD_protectedparser_t luaD_protectedparser_o;
luaD_protectedparser_t luaD_protectedparser_c;

int __cdecl luaD_protectedparser_d(lua_State *L, Zio *z, const char *name){
	const char* strData = z->data->strData;
	size_t strSize = z->data->size;
	if (memcmp(strData,g_FileHeader,strlen(g_FileHeader)) == 0){
		Msg("Loading encrypted Lua from: %s\n",name);
		CDecryptor dec (strData);
		z->data->size = dec.sizes.Payload-1;
		const char* strPayload = const_cast<const char*>((char*)dec.Payload);
		z->data->strData = strPayload;
	}
	int len = strlen(g_FileHeader);
	int ret = luaD_protectedparser_o(L,z,name);
	return ret;
}

CSimpleScan LuaScanner ("lua_shared.dll");
CDetour detours;

bool HasLoadedBefore = false;
int Init(lua_State* L) {
	gLua = Lua();
	gLua->Msg("[gm_xloader] Loaded!\n");
	ILuaObject* xloader = gLua->GetNewTable();
	xloader->SetMember("EncryptFile",L_EncryptFile);
	xloader->SetMember("TestLoadFile",L_TestLoadFile);
	gLua->SetGlobal("xloader",xloader);
	xloader->UnReference();

	if (HasLoadedBefore){ return 0; }
	CPrecisionTimer t;
	InitiateKeys();

	CreateInterfaceFn fileSystemFactory = Sys_GetFactory("filesystem_steam.dll");
	g_FileSystem = reinterpret_cast<IFileSystem*>(fileSystemFactory(FILESYSTEM_INTERFACE_VERSION, NULL));

	if (!g_FileSystem){
		Lua()->Error("Unable to load IFileSystem interface!\n");
		return 0;
	}
	PBYTE SomeLuaFunction = NULL;
	SomeLuaFunction = (PBYTE)LuaScanner.FindPointer("\x83\xEC\x14\x8B\x44\x24\x1C\x8B\x4C\x24\x20\x56\x8B\x74\x24\x1C\x8B\x56\x08\x57\x89\x44\x24\x08\x8B","xxxx?x?x?x??x?x?x???x?x?x");
	if (SomeLuaFunction == NULL) { Warning("[gm_xloader] Failed to find C Lua Function #1\n"); return 0; }
	luaD_protectedparser_o = (luaD_protectedparser_t)detours.Create((PBYTE)SomeLuaFunction, (PBYTE)&luaD_protectedparser_d, DETOUR_TYPE_JMP);

	HasLoadedBefore = true;

	return 0;	
}


int Shutdown(lua_State* L) {
	//delete rng;
	//delete privateKey;
	//delete publicKey;
	return 0;
}