#include "defines.h"


//print out MmCopyMemory args
NTSTATUS __fastcall MmCopyMemHook(PVOID Buffer, PVOID BaseAddress, SIZE_T NumberOfBytesToRead, int mode, PSIZE_T NumberOfBytesRead) {
	print(skCrypt("[HOOKER] MMcopymemory called!\n"));
	print(skCrypt("[HOOKER] Buffer: 0x%llX\n"), Buffer);
	print(skCrypt("[HOOKER] Address: 0x%llX\n"), BaseAddress);
	print(skCrypt("[HOOKER] Size: 0x%d\n"), NumberOfBytesToRead);

	switch (mode) {
	case MM_COPY_MEMORY_PHYSICAL:
		print(skCrypt("[HOOKER] Flag: MM_COPY_MEMORY_PHYSICAL\n"));
		break;

	case MM_COPY_MEMORY_VIRTUAL:
		print(skCrypt("[HOOKER] Flag: MM_COPY_MEMORY_VIRTUAL\n"));
		break;

	default:
		print(skCrypt("[HOOKER] Mode: 0x%d\n"), mode);
	}
	return STATUS_UNSUCCESSFUL;
}

auto Main() -> NTSTATUS {
	print("[HOOKER] Started driver!");

	//get the ImageBase
	CHAR* base = funcs::GetModuleInfo(skCrypt("ntoskrnl.exe"));

	if (!base) {
		print("[HOOKER] The requested module was not found!");
		return STATUS_UNSUCCESSFUL;
	}

	//long ass MmCopyMemory pattern (here is a pattern in case the function gets replaced with a different one)
	PVOID function = funcs::FindPatternImage(base, skCrypt("\x48\x89\x5C\x24\x00\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x45\x20\x4C\x8B\xAD\x00\x00\x00\x00"),
		skCrypt("xxxx?xxxxxxxxxxxxxxx?xxx????xxx????xxxxxxxxxx????"));

	if (!function) {
		print("[HOOKER] The requested function was not found!");
		return STATUS_UNSUCCESSFUL;
	}

	print(skCrypt("[HOOKER] MmCopyMemory: 0x%llX\n"), function);

	if (!funcs::HookFunction(function, &MmCopyMemHook)) {
		print("[HOOKER] The hook could not be placed!");
		return STATUS_UNSUCCESSFUL;
	}

	print("[HOOKER] Hook place success!");
	return STATUS_SUCCESS;
}

//driver entry function
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {

	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);
	return Main();
}