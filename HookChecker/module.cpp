#include "module.h"

#include <csignal>
#include <iostream>

std::string GetLastErrorAsString() {
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string();
	}

	LPSTR messageBuffer = nullptr;

	size_t size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL
	);

	std::string message(messageBuffer, size);

	LocalFree(messageBuffer);

	return message;
}

uintptr_t Module::GetModuleBaseAddress(DWORD pid, const char* modName) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!strcmp(modEntry.szModule, modName)) {
					CloseHandle(hSnap);
					return (uintptr_t)modEntry.modBaseAddr;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
}

void Module::enumModules(DWORD pid, const char* pName, std::vector<Module::module>* modules) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!strcmp(modEntry.szModule, pName)) {
					continue;
				}

				auto mod = module{};

				mod.base = (uintptr_t)modEntry.modBaseAddr;

				strcpy_s(mod.szModule, MAX_MODULE_NAME, modEntry.szModule);

				enumFunctions(&mod);

				modules->push_back(mod);
			} while (Module32Next(hSnap, &modEntry));
		}
	}
}

void Module::enumFunctions(module* mod) {
	//HMODULE lib = LoadLibraryEx(mod->szModule, NULL, DONT_RESOLVE_DLL_REFERENCES);
	HMODULE lib = LoadLibrary(mod->szModule);

	if (!lib) {
		return;
	}

	PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE*)lib + ((PIMAGE_DOS_HEADER)lib)->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY exports = 
		(PIMAGE_EXPORT_DIRECTORY)((BYTE*)lib + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	auto addressOfNames = exports->AddressOfNames;

	int* nameTable = (int*)((BYTE*)lib + addressOfNames);
	for (int i = 0; i < exports->NumberOfNames; i++) {
		mod->exports.push_back((char*)((BYTE*)lib + nameTable[i]));
		//printf("Export: %s\n", (char*)((BYTE*)lib + nameTable[i]));
	}

	//FreeLibrary(lib);
}

bool cmpBytes(char* buf1, char* buf2, int size) {
	for (int i = 0; i < size; i++) {
		if (buf1[i] != buf2[i]) {
			return false;
		}
	}
	return true;
}

bool Module::checkHooks(HANDLE pHandle, module* mod) {
	auto hModule = LoadLibrary(mod->szModule);

	if (!hModule) {
		return false;
	}

	for (auto funcName : mod->exports) {
		auto func = GetProcAddress(hModule, funcName);

		char buf[5];

		bool success = ReadProcessMemory(pHandle, (LPCVOID)func, buf, 5, 0);
		if (!success) {
			std::cout << "(" << mod->szModule << ") - [" << funcName << "] can't read" << std::endl;
			return false;
		}

		bool hasHook = !cmpBytes(buf, (char*)func, 5);

		if (hasHook) {
			std::cout << "(" << mod->szModule << ") - [" << funcName << " : 0x" << std::hex << func << "] is hooked" << std::endl;
		}
	}

	FreeLibrary(hModule);
}
