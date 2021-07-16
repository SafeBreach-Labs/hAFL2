#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <winternl.h>
#include "kafl_user.h"

#define ARRAY_SIZE 1024
#define INFO_SIZE (128 << 10)

PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func = "PsCreateSystemThread";

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function) {
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

int main(void) {
    HMODULE hNtdll = LoadLibraryA("c:\\windows\\system32\\ntdll.dll");
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)(GetProcAddress(hNtdll, "NtQuerySystemInformation"));

    char* info_buffer = (char*)VirtualAlloc(0, INFO_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(info_buffer, 0xff, INFO_SIZE);
    memset(info_buffer, 0x00, INFO_SIZE);
    int pos = 0;

    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    int cDrivers, i;
    NTSTATUS status;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
    {
        TCHAR szDriver[ARRAY_SIZE];

        cDrivers = cbNeeded / sizeof(drivers[0]);
        PRTL_PROCESS_MODULES ModuleInfo;

        ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!ModuleInfo) {
            goto fail;
        }

        if (!NT_SUCCESS(status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL))) {
            VirtualFree(ModuleInfo, 0, MEM_RELEASE);
            goto fail;
        }

        pos += sprintf(info_buffer + pos, "kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n", cDrivers);
        //_tprintf(TEXT("kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n"), cDrivers);      
        pos += sprintf(info_buffer + pos, "START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n");
        //_tprintf(TEXT("START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n"));      
        for (i = 0; i < cDrivers; i++) {
            pos += sprintf(info_buffer + pos, "0x%p\t0x%p\t%s\n", drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
            //_tprintf(TEXT("0x%p\t0x%p\t%s\n"), drivers[i], drivers[i]+ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
        }
    }
    else {
        goto fail;
    }

fail:
    kAFL_hypercall(HYPERCALL_KAFL_INFO, (UINT64)info_buffer);

    printf(info_buffer);
    return 0;
}

