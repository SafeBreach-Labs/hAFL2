#pragma once

#pragma warning(push)
#pragma warning(disable: 4201)  /* nonstandard extension used: nameless struct/union */
#include <ndis.h>
#include<ntddk.h>
#pragma warning(pop)
#include <vmbuskernelmodeclientlibapi.h>

#pragma comment(lib, "ndis.lib")

typedef struct _FILTER_DEVICE_EXTENSION
{
    IO_REMOVE_LOCK RemoveLock;
    VMBCHANNEL Channel;
} FILTER_DEVICE_EXTENSION, * PFILTER_DEVICE_EXTENSION;

typedef struct _SYSTEM_MODULE_ENTRY
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
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

PVOID NTAPI RtlImageDirectoryEntryToData(
    PVOID ImageBase,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size);