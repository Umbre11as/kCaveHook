#pragma once

#include <ntifs.h>
#include "Errors.h"

typedef struct {
    UCHAR* buffer;
    SIZE_T size;
} ByteBuffer;

typedef struct HOOK_DATA_ {
    ULONGLONG Target;
    PVOID Detour;
    PVOID Trampoline;
    ByteBuffer Prologue;
} HOOK_DATA, *PHOOK_DATA, *LPHOOK_DATA;

BOOLEAN CaveHookEx(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original, OUT HOOK_DATA* hookData);
BOOLEAN CaveHook(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original);
int CaveLastError();
