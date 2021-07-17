#pragma once

#include <aux_klib.h>
#pragma comment(lib, "aux_klib.lib")

typedef struct _KernelModules
{
	AUX_MODULE_EXTENDED_INFO* modules;
	ULONG numberOfModules;

} KERNEL_MODULES, * PKERNEL_MODULES;

NTSTATUS InitKernelModules(PKERNEL_MODULES pKernelModules);
VOID DeinitKernelModules(PKERNEL_MODULES pKernelModules);
ULONG GetKernelModulesCount(PKERNEL_MODULES pKernelModules);
PCSZ GetKernelModuleNameByIndex(PKERNEL_MODULES pKernelModules, ULONG i);
PVOID GetKernelModuleBaseAddressByIndex(PKERNEL_MODULES pKernelModules, ULONG i);
