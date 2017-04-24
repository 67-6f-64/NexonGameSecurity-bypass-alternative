#include "native.hpp"

#include "blackcipher_bypass.hpp"
#include "ngs_bypass.hpp"

#include <Windows.h>
#include <iostream>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		char module_file_path[MAX_PATH];
		GetModuleFileName(GetModuleHandle(NULL), module_file_path, MAX_PATH);

		if (!lstrcmpi(module_file_path + strlen(module_file_path) - strlen("BlackCipher.aes"), "BlackCipher.aes"))
			BlackCipher::initialize_bypass(hModule);
		else if (!lstrcmpi(module_file_path + strlen(module_file_path) - strlen("MapleStory.exe"), "MapleStory.exe"))
			NexonGameSecurity::initialize_bypass();

		DisableThreadLibraryCalls(hModule);
	}

	return TRUE;
}