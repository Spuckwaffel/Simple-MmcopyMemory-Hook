#pragma once

//we dont have to put every function in here from funcs.cpp as they're not needed 
namespace funcs {
	char* GetModuleInfo(const char* Name);
	PVOID FindPatternImage(CHAR* Base, CHAR* Pattern, CHAR* Mask);
	bool HookFunction(PVOID function, PVOID outfunction);
}
