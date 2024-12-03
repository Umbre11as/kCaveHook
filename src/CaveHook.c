// ReSharper disable All
#include "CaveHook.h"

#include <Zydis/Zydis.h>

int lastError = 0;

BOOLEAN ReadReadOnly(IN ULONGLONG address, IN PVOID buffer, IN SIZE_T size) {
    PMDL mdl = IoAllocateMdl((PVOID)(address), size, FALSE, FALSE, NULL);
    if (!mdl)
        return FALSE;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mappedAddress)
        return FALSE;

    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

    memcpy(buffer, (PVOID)(address), size);

    MmUnmapLockedPages(mappedAddress, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return TRUE;
}

BOOLEAN WriteReadOnly(IN ULONGLONG address, IN PVOID buffer, IN SIZE_T size) {
    PMDL mdl = IoAllocateMdl((PVOID)(address), size, FALSE, FALSE, NULL);
    if (!mdl)
        return FALSE;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mappedAddress)
        return FALSE;

    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

    memcpy(mappedAddress, buffer, size);

    MmUnmapLockedPages(mappedAddress, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return TRUE;
}


BOOLEAN FindPrologue(IN ULONGLONG address, IN SIZE_T jmpLength, OUT ByteBuffer* byteBuffer) {
    UCHAR* buffer = (UCHAR*)(ExAllocatePool(NonPagedPool, jmpLength + 10));
    if (!buffer) {
        lastError = BUFFER_NOT_ALLOCATED;
        return FALSE;
    }

    if (!ReadReadOnly(address, buffer, jmpLength + 10)) {
        lastError = CANNOT_READ_MEMORY;
        return FALSE;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    SIZE_T readOffset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status;

    SIZE_T prologueLength = 0;
    while ((status = ZydisDecoderDecodeFull(&decoder, buffer + readOffset, (jmpLength + 10) - readOffset, &instruction, operands)) != ZYDIS_STATUS_NO_MORE_DATA) {
        if (!ZYAN_SUCCESS(status)) {
            readOffset++;
            continue;
        }

        if (prologueLength > jmpLength)
            break;

        prologueLength += instruction.length;
        readOffset += instruction.length;
    }

    byteBuffer->buffer = buffer;
    byteBuffer->size = prologueLength;
    return TRUE;
}

BOOLEAN PlaceDetourJmp(IN ULONGLONG target, IN ULONGLONG detour) {
    UCHAR* buffer = (UCHAR*)(ExAllocatePool(NonPagedPool, 14));
    if (!buffer) {
        lastError = BUFFER_NOT_ALLOCATED;
        return FALSE;
    }

    memcpy(buffer, "\xFF\x25\x00\x00\x00\x00", 6);
    memcpy(buffer + 6, &detour, sizeof(detour));

    if (!WriteReadOnly(target, buffer, 14)) {
        lastError = CANNOT_WRITE_MEMORY;
        return FALSE;
    }

    return TRUE;
}

BOOLEAN CreateTrampoline(IN ULONGLONG target, IN ByteBuffer prologue, OUT PVOID* outTrampoline) {
    if (!outTrampoline)
        return FALSE;

    PVOID trampoline = ExAllocatePool(NonPagedPool, prologue.size + 14);
    if (!trampoline) {
        lastError = BUFFER_NOT_ALLOCATED;
        return FALSE;
    }

    UCHAR* buffer = (UCHAR*)(ExAllocatePool(NonPagedPool, 14));
    if (!buffer) {
        lastError = BUFFER_NOT_ALLOCATED;
        return FALSE;
    }

    memcpy(buffer, "\xFF\x25\x00\x00\x00\x00", 6);
    ULONGLONG address = target + prologue.size;
    memcpy(buffer + 6, &address, sizeof(address));

    memcpy(trampoline, prologue.buffer, prologue.size);
    memcpy((PVOID)((ULONGLONG)(trampoline) + prologue.size), buffer, 14);

    *outTrampoline = trampoline;
    return TRUE;
}

BOOLEAN CaveHookEx(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original, OUT HOOK_DATA* hookData) {
    ByteBuffer prologue;
    if (!FindPrologue(target, 14, &prologue))
        return FALSE;

    if (!PlaceDetourJmp(target, (ULONGLONG)(detour)))
        return FALSE;

    if (original) {
        PVOID trampoline;
        if (!CreateTrampoline(target, prologue, &trampoline))
            return FALSE;

        hookData->Trampoline = trampoline;
        *original = trampoline;
    }

    hookData->Target = target;
    hookData->Detour = detour;
    hookData->Prologue = prologue;
    return TRUE;
}

BOOLEAN CaveHook(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original) {
    HOOK_DATA ignored;
    return CaveHookEx(target, detour, original, &ignored);
}

int CaveLastError() {
    return lastError;
}
