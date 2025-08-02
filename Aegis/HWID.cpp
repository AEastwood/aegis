#include "HWID.h"

#include <Windows.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <wincrypt.h>
#include <iostream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")

IWbemServices* HWID::pSvc = nullptr;

bool HWID::InitializeWMI()
{
	HRESULT hres;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		std::cerr << "Failed to initialize COM library. Error: 0x" << std::hex << hres << "\n";
		return false;
	}

	hres = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL);
	if (FAILED(hres))
	{
		std::cerr << "Failed to initialize security. Error: 0x" << std::hex << hres << "\n";
		CoUninitialize();
		return false;
	}

	IWbemLocator* pLoc = nullptr;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&pLoc);
	if (FAILED(hres))
	{
		std::cerr << "Failed to create IWbemLocator object. Error: 0x" << std::hex << hres << "\n";
		CoUninitialize();
		return false;
	}

	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc);
	if (FAILED(hres))
	{
		std::cerr << "Could not connect to WMI namespace ROOT\\CIMV2. Error: 0x" << std::hex << hres << "\n";
		pLoc->Release();
		CoUninitialize();
		return false;
	}

	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE);
	if (FAILED(hres))
	{
		std::cerr << "Could not set proxy blanket. Error: 0x" << std::hex << hres << "\n";
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;
	}

	pLoc->Release();
	return true;
}

void HWID::CleanupWMI()
{
	if (pSvc)
	{
		pSvc->Release();
		pSvc = nullptr;
	}
	CoUninitialize();
}

HRESULT HWID::QueryWMIProperty(const std::wstring& wql, const std::wstring& propertyName, std::string& result)
{
	if (!pSvc)
		return E_FAIL;

	IEnumWbemClassObject* pEnumerator = nullptr;
	HRESULT hr = pSvc->ExecQuery(
		bstr_t(L"WQL"),
		bstr_t(wql.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hr))
		return hr;

	IWbemClassObject* pclsObj = nullptr;
	ULONG retVal = 0;

	hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &retVal);
	if (retVal == 0)
	{
		pEnumerator->Release();
		return E_FAIL;
	}

	VARIANT vtProp;
	hr = pclsObj->Get(propertyName.c_str(), 0, &vtProp, 0, 0);
	if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR)
	{
		_bstr_t bstrVal(vtProp.bstrVal, false);
		result = (const char*)bstrVal;
	}
	else
	{
		hr = E_FAIL;
	}

	VariantClear(&vtProp);
	pclsObj->Release();
	pEnumerator->Release();

	return hr;
}

std::string HWID::GetCPUId()
{
	if (!InitializeWMI())
		return "UnknownCPU";

	std::string cpuId;
	HRESULT hr = QueryWMIProperty(L"SELECT ProcessorId FROM Win32_Processor", L"ProcessorId", cpuId);
	if (FAILED(hr) || cpuId.empty())
		cpuId = "UnknownCPU";

	CleanupWMI();
	return cpuId;
}

std::string HWID::GetMotherboardSerial()
{
	if (!InitializeWMI())
		return "UnknownBoard";

	std::string boardSerial;
	HRESULT hr = QueryWMIProperty(L"SELECT SerialNumber FROM Win32_BaseBoard", L"SerialNumber", boardSerial);
	if (FAILED(hr) || boardSerial.empty())
		boardSerial = "UnknownBoard";

	CleanupWMI();
	return boardSerial;
}

std::string HWID::GetUsername()
{
	char username[256];
	DWORD size = sizeof(username);
	if (GetUserNameA(username, &size))
		return std::string(username);

	return "UnknownUser";
}

uint32_t HWID::fnv1a_hash(const std::string& data)
{
	const uint32_t fnv_prime = 0x01000193;
	uint32_t hash = 0x811c9dc5;

	for (unsigned char c : data)
	{
		hash ^= c;
		hash *= fnv_prime;
	}
	return hash;
}

std::string HWID::GetHWID()
{
	std::string cpu = GetCPUId();
	std::string board = GetMotherboardSerial();
	std::string user = GetUsername();

	std::string combined = cpu + "|" + board + "|" + user;
	return combined;
}

std::string HWID::GetHWIDHash()
{
	std::string hwid = GetHWID();

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE hash[32];
	DWORD hashLen = sizeof(hash);
	std::stringstream ss;

	if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
		CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash) &&
		CryptHashData(hHash, (BYTE*)hwid.c_str(), hwid.size(), 0) &&
		CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
	{
		for (DWORD i = 0; i < hashLen; ++i)
			ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}

	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);

	return ss.str();
}
