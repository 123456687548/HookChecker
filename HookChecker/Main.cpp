#include <Windows.h>
#include <iostream>

#include "module.h"
#include "process.h"



int main(int argc, char* argv[]){
	if(argc <= 1) {
		printf("Usage: HookChecker <exe name>\n");
		printf("Usage: HookChecker <exe name> -a\n");
		return 0;
	}

	auto pName = argv[1];

	bool printAll = false;
	if(argc == 3 && strcmp(argv[2], "-a") == 0) {
		printAll = true;
	}

	auto pid = Process::GetProcessId(pName);

	if(pid == NULL) {
		printf("[-] Can't find Process (%s)\n", pName);
		return 1;
	}

	auto pHandle = OpenProcess(PROCESS_VM_READ, false, pid);

	if(pHandle == NULL) {
		printf("[-] Can't open Process (%s : %ld)\n", pName, pid);
		return 1;
	}

	std::vector<Module::module> modules;

	enumModules(pid, pName, &modules);

	for (auto module : modules) {
		Module::checkHooks(pHandle, &module, printAll);
	}

	return 0;
}
