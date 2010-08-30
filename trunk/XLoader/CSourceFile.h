

struct CEncSignature{
		char* FullData;


		const char* RelativePath;
		const char* SHA256;
		const char* AESKey;
};

struct CEncFile {
	const char* FullData;
	/////////////////////////////
	int SignatureSize;
	CEncSignature*  Signature;
	int PayloadSize;
	const char* Payload;
	/////////////////////////////
};
