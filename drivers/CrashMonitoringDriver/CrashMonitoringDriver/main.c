#define _NO_CRT_STDIO_INLINE

#include <ntddk.h>
#include <aux_klib.h>
#include <Wdm.h>
#include <Wdmsec.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "module.h"

#define BUF_SIZE 0x1000

// kAFL Hypercalls
#define HYPERCALL_KAFL_CRASH_DUMP 22
#define HYPERCALL_KAFL_CRASH_SIZE 23
#define HYPERCALL_KAFL_PANIC    8

// Other
#define UNW_FLAG_NHANDLER   0
#define UNW_FLAG_EHANDLER   1
#define UNW_FLAG_UHANDLER   2

extern VOID
RtlCaptureContext(
    __out PCONTEXT    Context
);


// Defined in hypercall.asm
extern void kAFL_Hypercall(UINT64 dwHypercall, UINT64 buf);
KBUGCHECK_CALLBACK_ROUTINE BugcheckCallback;
KBUGCHECK_CALLBACK_RECORD  BugcheckCallbackRecord;

static VOID
BugCheckStackDump(
    IN  PCONTEXT    Context
)
{
#define PARAMETER_COUNT     4
#define MAXIMUM_ITERATIONS  20

    __try {
        ULONG   Iteration;

        for (Iteration = 0; Iteration < MAXIMUM_ITERATIONS; Iteration++) {
            PRUNTIME_FUNCTION   FunctionEntry;
            ULONG64             ImageBase;
            ULONG64             RIP;
            ULONG64             RSP;
            ULONG64             Parameter[PARAMETER_COUNT] = { 0 };
            ULONG               Index;
            PCHAR               Name;
            ULONG64             Offset;
            char buffer[BUF_SIZE] = { 0 };

            if (Context->Rip == 0)
                break;

            FunctionEntry = RtlLookupFunctionEntry(Context->Rip,
                &ImageBase,
                NULL);

            if (FunctionEntry != NULL) {
                CONTEXT                         UnwindContext;
                ULONG64                         ControlPc;
                PVOID                           HandlerData;
                ULONG64                         EstablisherFrame;
                KNONVOLATILE_CONTEXT_POINTERS   ContextPointers;

                UnwindContext = *Context;
                ControlPc = Context->Rip;
                HandlerData = NULL;
                EstablisherFrame = 0;
                RtlZeroMemory(&ContextPointers, sizeof(KNONVOLATILE_CONTEXT_POINTERS));

                (VOID)RtlVirtualUnwind(UNW_FLAG_UHANDLER,
                    ImageBase,
                    ControlPc,
                    FunctionEntry,
                    &UnwindContext,
                    &HandlerData,
                    &EstablisherFrame,
                    &ContextPointers);

                *Context = UnwindContext;
            }
            else {
                Context->Rip = *(PULONG64)(Context->Rsp);
                Context->Rsp += sizeof(ULONG64);
            }

            RSP = Context->Rsp;
            RIP = Context->Rip;

            Index = 0;
            Offset = 0;
            for (;;) {
                if (Index == PARAMETER_COUNT)
                    break;

                Parameter[Index] = *(PULONG64)(RSP + Offset);

                Index += 1;
                Offset += 8;
            }

            ModuleLookup(RIP, &Name, &Offset);

            if (Name != NULL) {
                RtlStringCchPrintfA(buffer, BUF_SIZE, "BUGCHECK: %016X: (%016X %016X %016X %016X) %s + %p\n",
                    RSP,
                    Parameter[0],
                    Parameter[1],
                    Parameter[2],
                    Parameter[3],
                    Name,
                    (PVOID)Offset);
            }
            else {
                RtlStringCchPrintfA(buffer, BUF_SIZE, "BUGCHECK: %016X: (%016X %016X %016X %016X) %p\n",
                    RSP,
                    Parameter[0],
                    Parameter[1],
                    Parameter[2],
                    Parameter[3],
                    (PVOID)RIP);
            }

            kAFL_Hypercall(HYPERCALL_KAFL_CRASH_SIZE, (UINT64)strlen(buffer));
            kAFL_Hypercall(HYPERCALL_KAFL_CRASH_DUMP, (UINT64)buffer);
        }

        char final_buffer[BUF_SIZE] = { 0 };
        RtlStringCchPrintfA(final_buffer, BUF_SIZE, "======================================\n\n");
        kAFL_Hypercall(HYPERCALL_KAFL_CRASH_SIZE, (UINT64)strlen(final_buffer));
        kAFL_Hypercall(HYPERCALL_KAFL_CRASH_DUMP, (UINT64)final_buffer);
    }


    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

VOID
BugcheckCallback(
    IN  PVOID               Argument,
    IN  ULONG               Length
)
{
    KBUGCHECK_DATA KiBugCheckData = { 0 };

    ULONG                   Code;
    ULONG_PTR               Parameter1;
    ULONG_PTR               Parameter2;
    ULONG_PTR               Parameter3;
    ULONG_PTR               Parameter4;
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Length);

    AuxKlibGetBugCheckData(&KiBugCheckData);

    Code = (ULONG)KiBugCheckData.BugCheckCode;
    Parameter1 = KiBugCheckData.Parameter1;
    Parameter2 = KiBugCheckData.Parameter2;
    Parameter3 = KiBugCheckData.Parameter3;
    Parameter4 = KiBugCheckData.Parameter4;

    __try {
        CONTEXT Context;

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
        kAFL_Hypercall(HYPERCALL_KAFL_PANIC, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }

}


VOID
Unload(
    IN WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);

    KeDeregisterBugCheckCallback(&BugcheckCallbackRecord);
    ModuleTeardown();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    BOOLEAN res;
    
    WDF_DRIVER_CONFIG_INIT(&config, NULL);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = Unload;

    // Create a WDFDRIVER object
    status = WdfDriverCreate(
            DriverObject,
            RegistryPath,
            NULL,
            &config,
            &driver
    );

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Created Driver: 0x%x\n", status);

    KeInitializeCallbackRecord(&BugcheckCallbackRecord);
    res = KeRegisterBugCheckCallback(&BugcheckCallbackRecord,
        BugcheckCallback,
        NULL, 0,
        (PUCHAR)"BugcheckCallback");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Registered BugCheck Callback: 0x%x\n", res);
    ModuleInitialize();
  

    return status;
}