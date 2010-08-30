#include "csimplescan.h"
//#include "includes/sigscan.cpp"
//#include "includes/sigscan.h"

CSimpleScan::CSimpleScan()
{
}

CSimpleScan::CSimpleScan(const char *filename)
{
	SetDLL(filename);
}

bool CSimpleScan::SetDLL(const char *filename)
{
	m_Interface = Sys_GetFactory(filename);
	m_bInterfaceSet = m_Interface != NULL;

	return m_bInterfaceSet;
}

bool CSimpleScan::FindFunction(const char *sig, const char *mask, void **func)
{
	if (!m_bInterfaceSet)
		return false;

	CSigScan::sigscan_dllfunc = m_Interface;

	if (!CSigScan::GetDllMemInfo())
		return false;

	m_Signature.Init((unsigned char *)sig, (char *)mask, strlen(mask));

	if (!m_Signature.is_set)
		return false;

	*func = m_Signature.sig_addr;

	return true;
}

void* CSimpleScan::FindPointer(const char *sig, const char *mask)
{
	if (!m_bInterfaceSet)
		return false;

	CSigScan::sigscan_dllfunc = m_Interface;

	if (!CSigScan::GetDllMemInfo())
		return false;

	m_Signature.Init((unsigned char *)sig, (char *)mask, strlen(mask));

	if (!m_Signature.is_set)
		return false;

	return m_Signature.sig_addr;
}