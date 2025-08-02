#pragma once

#include <string>
#include <windows.h>
#include <wbemidl.h>

class HWID
{
public:
	static std::string GetHWID();
	static std::string GetHWIDHash();

private:
	static std::string GetCPUId();
	static std::string GetMotherboardSerial();
	static std::string GetUsername();

	static uint32_t fnv1a_hash(const std::string& data);

	static bool InitializeWMI();
	static void CleanupWMI();

	static HRESULT QueryWMIProperty(const std::wstring& wql, const std::wstring& propertyName, std::string& result);

	static IWbemServices* pSvc;
};