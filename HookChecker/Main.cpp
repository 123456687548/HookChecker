#include <Windows.h>
#include <iostream>

#include "module.h"
#include "process.h"



int main(int argc, char* argv[]){
	if(argc <= 1) {
		std::cout << "Usage: HookChecker <exe name>" << std::endl;
		return 0;
	}

	//auto pName = "PE-bear.exe";
	auto pName = argv[1];
	auto pid = Process::GetProcessId(pName);
	auto pHandle = OpenProcess(PROCESS_VM_READ, false, pid);

	std::vector<Module::module> modules;

	enumModules(pid, pName, &modules);

	for (auto module : modules) {
		Module::checkHooks(pHandle, &module);
	}

	return 0;
}
