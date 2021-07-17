#pragma once
#pragma warning(disable : 4201)

#include <ntddk.h>
#include <aux_klib.h>

NTSTATUS
ModuleInitialize(
    VOID);

VOID
ModuleTeardown(
    VOID
);

VOID
ModuleLookup(
    IN  ULONG_PTR   Address,
    OUT PCHAR* Name,
    OUT PULONG_PTR  Offset
);


typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
    ULONG Count;
    UCHAR Search;
    UCHAR RaiseStatusIndex;
    BOOLEAN Unwind;
    BOOLEAN Exception;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;

extern PRUNTIME_FUNCTION
RtlLookupFunctionEntry(
    __in ULONG64 ControlPc,
    __out PULONG64 ImageBase,
    __inout_opt PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
);

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };
} KNONVOLATILE_CONTEXT_POINTERS, * PKNONVOLATILE_CONTEXT_POINTERS;

extern PEXCEPTION_ROUTINE
RtlVirtualUnwind(
    __in ULONG HandlerType,
    __in ULONG64 ImageBase,
    __in ULONG64 ControlPc,
    __in PRUNTIME_FUNCTION FunctionEntry,
    __inout PCONTEXT ContextRecord,
    __out PVOID* HandlerData,
    __out PULONG64 EstablisherFrame,
    __inout_opt PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
);
