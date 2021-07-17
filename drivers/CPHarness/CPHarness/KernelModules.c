#include "Globals.h"
#include "KernelModules.h"

NTSTATUS InitKernelModules(PKERNEL_MODULES pKernelModules)
{
    /* Based on https://github.com/thomhastings/mimikatz-en/blob/master/driver/modules.c */

    NTSTATUS status = STATUS_SUCCESS;
    ULONG modulesSize = 0;
    ULONG numberOfModules = 0;
    PVOID getRequiredBufferSize = NULL;
    AUX_MODULE_EXTENDED_INFO* modules = NULL;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
    {
        goto exit;
    }

    /* Get the size of the struct for requested information */
    status = AuxKlibQueryModuleInformation(
        &modulesSize,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        getRequiredBufferSize
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "KmdfFuzzer: Failed to get kernel modules information\n");
        goto exit;
    }

    /* Create a new buffer for the modules */
    numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
    modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(
        PagedPool,
        modulesSize,
        POOL_TAG
    );
    if (modules == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    RtlZeroMemory(modules, modulesSize);

    /* Now get the actual information... */
    status = AuxKlibQueryModuleInformation(
        &modulesSize,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules
    );
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(pKernelModules->modules, POOL_TAG);
        goto exit;
    }

    pKernelModules->modules = modules;
    pKernelModules->numberOfModules = numberOfModules;

exit:
    return status;
}

VOID DeinitKernelModules(PKERNEL_MODULES pKernelModules)
{
    ExFreePoolWithTag(pKernelModules->modules, POOL_TAG);
}

ULONG GetKernelModulesCount(PKERNEL_MODULES pKernelModules)
{
    return pKernelModules->numberOfModules;
}

PCSZ GetKernelModuleNameByIndex(PKERNEL_MODULES pKernelModules, ULONG i)
{
    if (i >= pKernelModules->numberOfModules)
    {
        return NULL;
    }
    return (PCSZ)(pKernelModules->modules[i].FullPathName);
}

PVOID GetKernelModuleBaseAddressByIndex(PKERNEL_MODULES pKernelModules, ULONG i)
{
    if (i >= pKernelModules->numberOfModules)
    {
        return NULL;
    }
    return pKernelModules->modules[i].BasicInfo.ImageBase;
}