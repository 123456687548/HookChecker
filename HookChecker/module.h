#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

namespace Module {
#define MAX_MODULE_NAME (MAX_MODULE_NAME32 + 1)

	struct module {
		char szModule[MAX_MODULE_NAME];
		uintptr_t base;
		std::vector<char*> exports;
	};

	uintptr_t GetModuleBaseAddress(DWORD pid, const char* modName);
	void enumModules(DWORD pid, const char* pName, std::vector<Module::module>* modules);
	void enumFunctions(module* mod);
	bool checkHooks(HANDLE pHandle, module* mod);
}
