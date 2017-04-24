#include "ngs_bypass.hpp"
#include "detours.hpp"

#include <iostream>
#include <string>

#include <intrin.h>

#define STATUS_SUCCESS			((NTSTATUS)0x00000000)
#define STATUS_ACCESS_DENIED	((NTSTATUS)0xC0000022)

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

namespace NexonGameSecurity
{
	bool InjectDll(DWORD processid)
	{
		wchar_t module_file_path[MAX_PATH];
		GetModuleFileNameW(reinterpret_cast<HMODULE>(&__ImageBase), module_file_path, MAX_PATH);

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processid);

		if (hProcess != INVALID_HANDLE_VALUE)
		{
			FARPROC _LoadLibraryW = GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryW");

			void* allocation = VirtualAllocEx(hProcess, NULL, (2 * lstrlenW(module_file_path)) + 1, MEM_COMMIT, PAGE_READWRITE);
			WriteProcessMemory(hProcess, allocation, module_file_path, (2 * lstrlenW(module_file_path)) + 1, NULL);
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, LPTHREAD_START_ROUTINE(_LoadLibraryW), allocation, 0, NULL);
			WaitForSingleObject(hThread, INFINITE);
			VirtualFreeEx(hProcess, allocation, NULL, MEM_RELEASE);
			CloseHandle(hThread);
			return true;
		}

		return false;
	}

	bool Hook_CreateProcessInternalW(bool enable)
	{
		typedef BOOL (WINAPI* CreateProcessInternalW_t)(HANDLE hUserToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
			BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken);   

		static CreateProcessInternalW_t _CreateProcessInternalW = reinterpret_cast<CreateProcessInternalW_t>(GetProcAddress(GetModuleHandle("Kernel32"), "CreateProcessInternalW"));

		CreateProcessInternalW_t CreateProcessInternalW_hook = [](HANDLE hUserToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
			BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken) -> BOOL
		{
			if (lpCommandLine && wcsstr(lpCommandLine, L"BlackCipher.aes"))
			{
				BOOL ret = _CreateProcessInternalW(hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
					dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
				
				if (ret)
					InjectDll(lpProcessInformation->dwProcessId);
				
				ResumeThread(lpProcessInformation->hThread);
				return ret;
			}

			return _CreateProcessInternalW(hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
				dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
		};

		return detours::redirect(enable, reinterpret_cast<void**>(&_CreateProcessInternalW), CreateProcessInternalW_hook);
	}
	
	bool Hook_NtReadVirtualMemory(bool enable)
	{
		typedef NTSTATUS (NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);		
		static NtReadVirtualMemory_t _NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(GetModuleHandle("ntdll"), "NtReadVirtualMemory"));

		NtReadVirtualMemory_t NtReadVirtualMemory_hook = [](HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded) -> NTSTATUS
		{
			HMODULE hModule = NULL;
			GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule);

			if (hModule && hModule == GetModuleHandle("BlackCall.aes"))
			{
				if (ProcessHandle != GetCurrentProcess())
					return STATUS_ACCESS_DENIED;

				GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(BaseAddress), &hModule);
				
				if (hModule && hModule == GetModuleHandle(NULL))
					return STATUS_ACCESS_DENIED;
			}

			return _NtReadVirtualMemory(ProcessHandle, BaseAddress,	Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
		};

		return detours::redirect(enable, reinterpret_cast<void**>(&_NtReadVirtualMemory), NtReadVirtualMemory_hook);
	}
	
	bool initialize_memory_mapping()
	{
		std::string mapping_name = "Global\\NexonGameClient" + std::to_string(GetCurrentProcessId());
		
		unsigned char* image_base = reinterpret_cast<unsigned char*>(GetModuleHandle(NULL));
		
		IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
		IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + dos_header->e_lfanew);
		
		unsigned int image_size = nt_headers->OptionalHeader.SizeOfImage;

		HANDLE mapping_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, image_size, mapping_name.c_str());
		
		if (mapping_handle == NULL && GetLastError() != ERROR_ALREADY_EXISTS)
			return false;

		void* mapping_view = MapViewOfFile(mapping_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		if (mapping_view == NULL)
		{
			CloseHandle(mapping_handle);
			return false;
		}

		memcpy(mapping_view, image_base, image_size);
		return true;
	}

	bool initialize_bypass()
	{
		return (initialize_memory_mapping() && Hook_CreateProcessInternalW(true) && Hook_NtReadVirtualMemory(true));
	}
}