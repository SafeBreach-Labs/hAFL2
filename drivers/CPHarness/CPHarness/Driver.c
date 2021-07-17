#include "Driver.h"
#include "Globals.h"
#include "KernelModules.h"
#include <Wdm.h>
#include <wdmsec.h>

#define IOCTL_SEND_PACKET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define NVSP_RNDIS_PKT_SIZE (0x28)
#define COMPLETION_BUFFER_SIZE (0x1000)
#define HARNESS_POOL_TAG 'SNRH'
#define DOS_DEVICE_NAME  L"\\DosDevices\\CPHarness"
#define NT_DEVICE_NAME  L"\\Device\\CPHarness"

DECLARE_CONST_UNICODE_STRING(dosDeviceName, DOS_DEVICE_NAME);
DECLARE_CONST_UNICODE_STRING(ntDeviceName, NT_DEVICE_NAME);

UNICODE_STRING ourName = RTL_CONSTANT_STRING(L"Microsoft Hyper-V Network Adapter");
PCWSTR ndisModulePath = (PCWSTR)L"\\SystemRoot\\System32\\drivers\\NDIS.SYS";
PCWSTR vmbkclModulePath = (PCWSTR)L"\\SystemRoot\\System32\\drivers\\vmbkmcl.sys";
PFN_VMB_PACKET_FREE pVmbPacketFree = NULL;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtWdfIoQueueIoDeviceControl;
EVT_WDF_DRIVER_UNLOAD EvtWdfDriverUnload;
PVOID NdisBaseAddress;
PVOID vmbkclBaseAddress;
VMBCHANNEL* channel;
PFN_VMB_PACKET_ALLOCATE pVmbPacketAllocate = NULL;
PFN_VMB_PACKET_SET_COMPLETION_ROUTINE pVmbPacketSetCompletionRoutine = NULL;
PFN_VMB_CHANNEL_SEND_SYNCHRONOUS_REQUEST pVmbChannelSendSynchronousRequest = NULL;
PFN_VMB_PACKET_SEND pVmbPacketSend = NULL;

NTSTATUS GetModuleAddress(PUNICODE_STRING targetModuleName, PVOID* targetBaseAddr)
{
    NTSTATUS status = STATUS_SUCCESS;
    KERNEL_MODULES kernelModules;
    ULONG numberOfModules;
    UNICODE_STRING currentUnicode = { 0 };
    ANSI_STRING currentAnsi = { 0 };
    LONG stringCompareRes = 0;
    BOOLEAN caseInsensitive = FALSE;
    BOOLEAN allocateDestinationString = TRUE;


    status = InitKernelModules(&kernelModules);
    if (!NT_SUCCESS(status))
    {
        goto exit;
    }

    /* Iterate on all loaded modules, find the base address of a given module */

    status = STATUS_NOT_FOUND;
    numberOfModules = GetKernelModulesCount(&kernelModules);
    for (ULONG i = 0; i < numberOfModules; i++)
    {
        RtlInitAnsiString(&currentAnsi, GetKernelModuleNameByIndex(&kernelModules, i));
        status = RtlAnsiStringToUnicodeString(&currentUnicode, &currentAnsi, allocateDestinationString);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Could not convert an Ansi string to a Unicode one\n");
            goto deinit;
        }

        stringCompareRes = RtlCompareUnicodeString(&currentUnicode, targetModuleName, caseInsensitive);
        if (stringCompareRes)
            continue;

        *targetBaseAddr = GetKernelModuleBaseAddressByIndex(&kernelModules, i);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Found Module %wZ address at %p\n", targetModuleName, *targetBaseAddr);
        status = STATUS_SUCCESS;
        break;
    }

deinit:
    DeinitKernelModules(&kernelModules);
exit:
    return status; 
}

NTSTATUS FindOurMiniportChannel(PVOID NDISBaseAddress)
{
    LONG MiniportListOffset = 0xe82e0; // ndis.sys build 21354.1, offset 0xe82e0 ==> ndis!ndisMiniportList

    NTSTATUS status = STATUS_NOT_FOUND;
    PNDIS_MINIPORT_BLOCK* NdisMiniportList = (PNDIS_MINIPORT_BLOCK*)((BYTE*)NDISBaseAddress + MiniportListOffset);
    PNDIS_MINIPORT_BLOCK currMiniport = (PNDIS_MINIPORT_BLOCK)(*NdisMiniportList);
    PVOID currContext = NULL;
    PVOID PoolVNC = NULL;
    ULONG nextGlobalMiniportOffset = 0xf08;
    ULONG poolVNCOffset = 0x488;
    ULONG vmbChannelOffset = 0x18;
    BOOLEAN caseInsensitive = TRUE;
    UNICODE_STRING currName = { 0 };
    LONG stringCompareRes = 0;

    /* Our adapter's name */
    for (currMiniport; currMiniport; currMiniport = (PNDIS_MINIPORT_BLOCK) * (PNDIS_MINIPORT_BLOCK*)((BYTE*)currMiniport + nextGlobalMiniportOffset))
    {
           
        status = NdisMQueryAdapterInstanceName(&currName, currMiniport);
        if (!NT_SUCCESS(status))
        {
            continue;
        }

        stringCompareRes = RtlCompareUnicodeString(&currName, &ourName, caseInsensitive);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Current Adapter Name: %wZ\n", currName);
        if (stringCompareRes == 0)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Found Adapter %wZ: %p\n", ourName, currMiniport);
            currContext = currMiniport->MiniportAdapterContext;
            if (currContext) {
                PoolVNC = (PLONG) * (PLONG*)((BYTE*)currContext + poolVNCOffset);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: currContext is OK\n");
                if (PoolVNC) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: PoolVNC is OK\n");
                    channel = (VMBCHANNEL*)*(VMBCHANNEL*)((BYTE*)PoolVNC + vmbChannelOffset);
                }
            }
            if (channel) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Channel is OK: %p\n", channel);
            }
            status = STATUS_SUCCESS;
            break;
        }
    }
    return status;
}

VOID EvtWdfDriverUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Driver unloading\n");
}

PVOID KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
    ASSERT(ModuleBase && pFunctionName);
    PVOID pFunctionAddress = NULL;

    ULONG size = 0;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
        RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

    ULONG_PTR addr = (ULONG_PTR)(PUCHAR)((UINT64)exports - (UINT64)ModuleBase);

    PULONG functions = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfFunctions);
    PSHORT ordinals = (PSHORT)((ULONG_PTR)ModuleBase + exports->AddressOfNameOrdinals);
    PULONG names = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfNames);
    ULONG  max_name = exports->NumberOfNames;
    ULONG  max_func = exports->NumberOfFunctions;

    ULONG i;

    for (i = 0; i < max_name; i++)
    {
        ULONG ord = ordinals[i];
        if (i >= max_name || ord >= max_func) {
            return NULL;
        }
        if (functions[ord] < addr || functions[ord] >= addr + size)
        {
            if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
            {
                pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
                break;
            }
        }
    }
    return pFunctionAddress;
}

NTSTATUS SendPacket(PVOID pNvspRndisPkt, UINT32 nvspRndisPktSize, PVOID pFuzzPayload, ULONG fuzzPayloadSize) {
    VMBPACKET vmbPacket;
    NTSTATUS status = STATUS_SUCCESS;
    PMDL pMdl = NULL;
    CHAR completionBuffer[COMPLETION_BUFFER_SIZE] = { 0 };
    UINT32 completionBufferSize = COMPLETION_BUFFER_SIZE;
    vmbPacket = pVmbPacketAllocate((VMBCHANNEL)channel);
    if (!vmbPacket)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketAllocate was failed!\n");
        goto cleanup;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketAllocate succeed!\n");

    if (fuzzPayloadSize > 0)
    {
        pMdl = IoAllocateMdl(pFuzzPayload, fuzzPayloadSize, FALSE, FALSE, NULL);
        if (!pMdl) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: IoAllocateMdl was failed!\n");
            goto cleanup;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: IoAllocateMdl Succeed!\n");
        MmBuildMdlForNonPagedPool(pMdl);
    }

    status = pVmbChannelSendSynchronousRequest((VMBCHANNEL)channel,
                                                pNvspRndisPkt, nvspRndisPktSize,
                                                pMdl,
                                                VMBUS_CHANNEL_FORMAT_FLAG_WAIT_FOR_COMPLETION,
                                                completionBuffer,
                                                &completionBufferSize, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbChannelSendSynchronousRequest was failed!\n");
        goto cleanup;
    }


cleanup:
    return status;
}

void EvtWdfIoQueueIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(Queue);

    NTSTATUS status;
    PVOID requestBuf = NULL;
    ULONG requestBufSize = 0;
    PVOID pNvspRndisPkt = NULL;
    PVOID pFuzzPayload = NULL;
    ULONG fuzzPayloadSize = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: EvtWdfIoQueueIoDeviceControl, IOCTL: 0x%x\n", IoControlCode);

    switch (IoControlCode) {
    case IOCTL_SEND_PACKET:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: EvtWdfIoQueueIoDeviceControl, IOCTL_SEND_PACKET!\n");
        break;
    default:
        break;
    }

    pNvspRndisPkt = ExAllocatePool2(POOL_FLAG_NON_PAGED, NVSP_RNDIS_PKT_SIZE, HARNESS_POOL_TAG);

    if (NULL == pNvspRndisPkt) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: ExAllocatePool2 failed\n");
        goto exit;
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Calling WdfRequestRetreiveInputBuffer\n");
    status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &requestBuf, (size_t*)&requestBufSize);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfRequestRetreiveInputBuffer Failed: %x\n", status);
        goto exit;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: InputBufSize %x, requestBufSize %x\n", InputBufferLength, requestBufSize);
    fuzzPayloadSize = requestBufSize;
    pFuzzPayload = ExAllocatePool2(POOL_FLAG_NON_PAGED, fuzzPayloadSize, HARNESS_POOL_TAG);
    if (NULL == pFuzzPayload) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: ExAllocateWithPool2 failed\n");
        goto exit;
    }

    // Initializing a generic NVSP RNDIS send packet which points to an MDL
    ((UINT*)pNvspRndisPkt)[0] = 0x0000006B;        // NVSP_RNDIS_SEND_PACKET
    ((UINT*)pNvspRndisPkt)[1] = 0x00000001;        // Channel type (control)
    ((UINT*)pNvspRndisPkt)[2] = 0xFFFFFFFF;        // send_buf_section_index
    ((UINT*)pNvspRndisPkt)[3] = (UINT)0;    // send_buf_section_size

    RtlCopyMemory(pFuzzPayload, requestBuf, requestBufSize);

    status = SendPacket(pNvspRndisPkt, (UINT32)NVSP_RNDIS_PKT_SIZE, pFuzzPayload, (ULONG)fuzzPayloadSize);

    // Complete the WDF Request (originated by the IOCTL)
    WdfRequestComplete(Request, STATUS_SUCCESS);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: SendPacket Failed: %x\n", status);
        goto exit;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: SendPacket Success\n");

exit:
    if (pNvspRndisPkt) {
        ExFreePoolWithTag(pNvspRndisPkt, HARNESS_POOL_TAG);
        pNvspRndisPkt = NULL;
    }
    if (pFuzzPayload) {
        ExFreePoolWithTag(pFuzzPayload, HARNESS_POOL_TAG);
        pFuzzPayload = NULL;
    }
}

NTSTATUS
EvtDeviceAdd(
    WDFDRIVER Driver,
    PWDFDEVICE_INIT DeviceInit
)

/*++
Routine Description:
    This routine is the AddDevice entry point for the sample device driver.
    It sets the ISR and DPC routine handlers for the interrupt and the passive
    level callback for the passive interrupt
    N.B. The sample device expects two interrupt resources in connecting its
    DIRQL ISR and PASSIVE_LEVEL callback.
Arguments:
    Driver - Supplies a handle to the driver object created in DriverEntry.
    DeviceInit - Supplies a pointer to a framework-allocated WDFDEVICE_INIT
        structure.
Return Value:
    NTSTATUS code.
--*/

{

    WDFDEVICE Device;
    WDF_OBJECT_ATTRIBUTES FdoAttributes;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG  ioQueueConfig;
    WDFQUEUE  hQueue;
    UNREFERENCED_PARAMETER(Driver);
    //
    // Initialize FDO attributes with the sample device extension.
    //

    WDF_OBJECT_ATTRIBUTES_INIT(&FdoAttributes);

    //
    // Call the framework to create the device and attach it to the lower stack.
    //

    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignName Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignName succeed\n");

    status = WdfDeviceInitAssignSDDLString(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R_RES_R);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignSDDLString Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignSDDLString succeed\n");

    status = WdfDeviceCreate(&DeviceInit, &FdoAttributes, &Device);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreate Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreate succeed\n");

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &ioQueueConfig,
        WdfIoQueueDispatchSequential
    );

    ioQueueConfig.EvtIoDeviceControl = EvtWdfIoQueueIoDeviceControl;


    status = WdfIoQueueCreate(
        Device,
        &ioQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &hQueue
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfIoQueueCreate Failed: %x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfIoQueueCreate succeed\n");

    status = WdfDeviceCreateSymbolicLink(Device, &dosDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreateSymbolicLink Failed: %x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreateSymbolicLink succeed\n");

EvtDeviceAddEnd:
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ndisModuleName;
    UNICODE_STRING vmbkclModuleName;
    CHAR vmbPacketAllocate[] = "VmbPacketAllocate";
    CHAR vmbPacketSend[] = "VmbPacketSend";
    CHAR vmbChannelSendSynchronousRequest[] = "VmbChannelSendSynchronousRequest";
    CHAR vmbPacketFree[] = "VmbPacketFree";
    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config,
        EvtDeviceAdd
    );
    config.EvtDriverUnload = EvtWdfDriverUnload;

    status = WdfDriverCreate(DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDriverCreate failed: 0x%x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDriverCreate succeed\n");


    RtlInitUnicodeString(&ndisModuleName, ndisModulePath);
    RtlInitUnicodeString(&vmbkclModuleName, vmbkclModulePath);

    status = GetModuleAddress(&ndisModuleName, &NdisBaseAddress);
    if (!NT_SUCCESS(status) || NdisBaseAddress == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: NDIS Address was not found\n");
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: NDIS Address: %p\n", NdisBaseAddress);

    status = FindOurMiniportChannel(NdisBaseAddress);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Failed to find the address of netvsc's VMBChannel\n");
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Miniport Channel: %p\n", channel);

    status = GetModuleAddress(&vmbkclModuleName, &vmbkclBaseAddress);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: vmbkcl Address was not found\n");
        return status;
    }

    pVmbPacketAllocate = (PFN_VMB_PACKET_ALLOCATE)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketAllocate);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketAllocate Address: %p\n", pVmbPacketAllocate);
    pVmbPacketSend = (PFN_VMB_PACKET_SEND)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketSend);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketSend Address: %p\n", pVmbPacketSend);
    pVmbChannelSendSynchronousRequest = (PFN_VMB_CHANNEL_SEND_SYNCHRONOUS_REQUEST)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbChannelSendSynchronousRequest);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: pVmbChannelSendSynchronousRequest Address: %p\n", pVmbChannelSendSynchronousRequest);
    pVmbPacketFree = (PFN_VMB_PACKET_FREE)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketFree);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketFree Address: %p\n", pVmbPacketFree);



    if (NULL == pVmbPacketAllocate || NULL == pVmbPacketSend || NULL == pVmbPacketSetCompletionRoutine) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: KernelGetProcAddress was failed!\n");
    }

    return status;
}