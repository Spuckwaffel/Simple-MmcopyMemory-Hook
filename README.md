# Simple-MmcopyMemory-Hook
A simple MmCopyMemory hook.

check out the UC post.
with this Release (dedicated to the kernel newbies) I will show you how basic hooks work.
Before any flaming happens, this will:


*blue screen you because of pg within a hour
*this will get you banned (it is detected)
*this is a basic mov rax hook


[U]Why did i release it then?[/U]
Drivers that place hooks in some syscall function are nothing new, but in this project I'm hooking a function such as MmCopyMemory that EAC uses to scan the kernel memory to find manually mapped driver.
The source code of the driver will hook this function and will print out the info and what EAC copies.
I've just seen many people saying "just hook MmCopyMemory to see what EAC is scanning" but for some people this might sound like a hard or impossible task.
In this community are still many people who don't know how a hook even works and this might help you out a lot.

With this well documented driver you can place a hook on any function.

#Let's take a look at MmCopyMemory:
MmCopyMemory is located in ntoskrnl.
```
NTSTATUS __fastcall MmCopyMemory(PVOID TargetAddress, unsigned __int64 sourceaddress, unsigned __int64 size, int virtorphys, _QWORD *numberofbytestransferred)

//or from microsoft docs
NTSTATUS MmCopyMemory(
  [in]  PVOID           TargetAddress,
  [in]  MM_COPY_ADDRESS SourceAddress,
  [in]  SIZE_T          NumberOfBytes,
  [in]  ULONG           Flags,
  [out] PSIZE_T         NumberOfBytesTransferred
);
```

[QUOTE]TargetAddress
A pointer to a caller-supplied buffer. This buffer must be in nonpageable memory.

SourceAddress
An MM_COPY_ADDRESS structure, passed by value, that contains either the virtual address or the physical address of the data to be copied to the buffer pointed to by TargetAddress.

NumberOfBytes
The number of bytes to copy from SourceAddress to TargetAddress.

Flags
Flags that indicate whether SourceAddress is a virtual address or a physical address. The following flag bits are defined for this parameter.

Flag
MM_COPY_MEMORY_PHYSICAL	SourceAddress specifies a physical address.
MM_COPY_MEMORY_VIRTUAL	SourceAddress specifies a virtual address.
 
These two flag bits are mutually exclusive. The caller must set one or the other, but not both.

NumberOfBytesTransferred
A pointer to a location to which the routine writes the number of bytes successfully copied from the SourceAddress location to the buffer at TargetAddress.[/QUOTE]

Sounds pretty easy to hook. 5 args! Let's make a function in our driver:
```
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
```

Now in our driver we just have to locate the function (for example using a pattern) and hook it with a simple hook that will return at the end STATUS_UNSUCCESSFUL like following:
```
		//place a r11 jmp hook that returns STATUS_UNSUCCESSFUL
		unsigned char shell_code[] = {
				0x49, 0xBB, //mov r11
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //ptr
				0x41, 0xff, 0xe3,  //jmp r11
				0xb8,  0x01,  0x00,  0x00, 0xc0, //mov eax, STATUS_UNSUCCESSFUL
				0xc3 // ret
		};
```
Why? After our hook, we want to return asap because the rest of the MmCopyMemory function will be broken. I've used the r11 register instead of rax just to prove there's more than just rax (technically useless).

Patterns to the function can be easily created with the SigMaker plugin for IDA pro.

Now we just have to write the shellcode to the function and whenever MmCopyMemory will be called, we will see a message apprearing in DbgView (obviously enable kernel output).

That's about it! Just map the driver with kdmapper or any mappers.
The pattern in the driver is for 20H2.
