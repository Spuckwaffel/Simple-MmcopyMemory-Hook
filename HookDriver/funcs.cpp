#include <ntifs.h>
#include <IntSafe.h>
#include <ntimage.h>
#include "funcs.h"
#include "kernel.h"
namespace funcs {

	CHAR* LowerStr(CHAR* Str) {
		for (CHAR* S = Str; *S; ++S) {
			*S = (CHAR)tolower(*S);
		}
		return Str;
	}


	template <typename T = PVOID>
	T AllocatePool(SIZE_T Size) {
		return reinterpret_cast<T>(ExAllocatePool(NonPagedPool, Size));
	}

	VOID FreePool(PVOID Buffer) {
		ExFreePool(Buffer);
	}

	//get ImageBase of a loaded module
	char* GetModuleInfo(const char* Name) {
		PVOID Base = nullptr;
		DWORD RequiredSize = 0;

		//get add loaded modules

		if (ZwQuerySystemInformation(SystemModuleInformation,
			nullptr,
			NULL,
			&RequiredSize) != STATUS_INFO_LENGTH_MISMATCH) {

			return 0;
		}

		auto Modules = AllocatePool<SYSTEM_MODULE_INFORMATION*>(RequiredSize);

		//in case allocating a pool fails
		if (!Modules) {
			return 0;
		}

		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation,
			Modules,
			RequiredSize,
			nullptr))) {
			FreePool(Modules);
			return 0;
		}

		//now loop through all loaded modules

		for (DWORD i = 0; i < Modules->NumberOfModules; ++i) {
			SYSTEM_MODULE CurModule{ Modules->Modules[i] };

			//check if module name matches the module were looking for (lower string just to make sure)
			if (strstr(LowerStr((CHAR*)CurModule.FullPathName), LowerStr((CHAR*)Name)))
			{
				//get ImageBase
				Base = CurModule.ImageBase;

				//break the loop, we have our module
				break;
			}
		}

		//free the pool
		FreePool(Modules);
		return reinterpret_cast<char*>(Base);
	}


	//check mask for wildcards
	BOOLEAN CheckMask(CHAR* Base, CHAR* Pattern, CHAR* Mask) {
		for (; *Mask; ++Base, ++Pattern, ++Mask) {
			if (*Mask == 'x' && *Base != *Pattern) {
				return FALSE;
			}
		}

		return TRUE;
	}

	//find a pattern in a given region and size
	PVOID FindPattern(CHAR* Base, DWORD Length, CHAR* Pattern, CHAR* Mask) {
		Length -= (DWORD)strlen(Mask);

		for (DWORD i = 0; i <= Length; ++i) {
			PVOID Addr{ &Base[i] };

			if (CheckMask(static_cast<PCHAR>(Addr), Pattern, Mask)) {
				return Addr;
			}
		}

		return 0;
	}

	//basic pattern search function
	PVOID FindPatternImage(CHAR* Base, CHAR* Pattern, CHAR* Mask)
	{
		PVOID Match{ 0 };

		IMAGE_NT_HEADERS* Headers{ (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew) };
		IMAGE_SECTION_HEADER* Sections{ IMAGE_FIRST_SECTION(Headers) };

		for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
			IMAGE_SECTION_HEADER* Section{ &Sections[i] };

			if (*(INT*)Section->Name == 'EGAP' || memcmp(Section->Name, ".text", 5) == 0) {
				Match = FindPattern(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);

				if (Match) {
					break;
				}
			}
		}

		return Match;
	}

	//basic write to readonly memory function
	bool write_to_read_only_memory(void* address, void* buffer, size_t size) {
		PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
		if (!Mdl)
			return false;

		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
		PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

		memcpy(Mapping, buffer, size);
		MmUnmapLockedPages(Mapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return true;
	}

	//basic Hook
	bool HookFunction(PVOID function, PVOID outfunction)
	{
		//place a r11 jmp hook that returns STATUS_UNSUCCESSFUL
		unsigned char shell_code[] = {
				0x49, 0xBB, //mov r11
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //ptr
				0x41, 0xff, 0xe3,  //jmp r11
				0xb8,  0x01,  0x00,  0x00, 0xc0, //mov eax, STATUS_UNSUCCESSFUL
				0xc3 // ret
		};

		uintptr_t hook_address = reinterpret_cast<uintptr_t>(outfunction);

		//place the hook address in the shellcode
		memcpy(shell_code + 2, &hook_address, sizeof(hook_address));

		return write_to_read_only_memory(function, &shell_code, sizeof(shell_code));
	}
}
