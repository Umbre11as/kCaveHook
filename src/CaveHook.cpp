#include "CaveHook.h"

#include "Allocator.h"
#include "Memory.h"
#include <Zydis/Zydis.h>

int lastError = 0;

bool FindPrologue(IN ULONGLONG address, IN SIZE_T jmpLength, OUT ByteBuffer* byteBuffer) {
    auto* buffer = static_cast<UCHAR*>(Allocator::AllocateKernel(jmpLength + 10));
    if (!buffer) {
        lastError = Errors::BUFFER_NOT_ALLOCATED;
        return false;
    }

    if (!Memory::ReadReadOnly(address, buffer, jmpLength + 10)) {
        lastError = Errors::CANNOT_READ_MEMORY;
        return false;
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
    return true;
}

bool PlaceDetourJmp(IN ULONGLONG target, IN ULONGLONG detour) {
    auto* buffer = static_cast<UCHAR*>(Allocator::AllocateKernel(14));
    if (!buffer) {
        lastError = Errors::BUFFER_NOT_ALLOCATED;
        return false;
    }

    memcpy(buffer, "\xFF\x25\x00\x00\x00\x00", 6);
    memcpy(buffer + 6, &detour, sizeof(detour));

    if (!Memory::WriteReadOnly(target, buffer, 14)) {
        lastError = Errors::CANNOT_WRITE_MEMORY;
        return false;
    }

    return true;
}

bool CreateTrampoline(IN ULONGLONG target, IN ByteBuffer prologue, OUT PVOID* outTrampoline) {
    if (!outTrampoline)
        return false;

    PVOID trampoline = Allocator::AllocateKernel(prologue.size + 14);
    if (!trampoline) {
        lastError = Errors::BUFFER_NOT_ALLOCATED;
        return false;
    }

    auto* buffer = static_cast<UCHAR*>(Allocator::AllocateKernel(14));
    if (!buffer) {
        lastError = Errors::BUFFER_NOT_ALLOCATED;
        return false;
    }

    memcpy(buffer, "\xFF\x25\x00\x00\x00\x00", 6);
    ULONGLONG address = target + prologue.size;
    memcpy(buffer + 6, &address, sizeof(address));

    memcpy(trampoline, prologue.buffer, prologue.size);
    memcpy(reinterpret_cast<PVOID>(reinterpret_cast<ULONGLONG>(trampoline) + prologue.size), buffer, 14);

    *outTrampoline = trampoline;
    return true;
}

bool CaveHookEx(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original, OUT HOOK_DATA* hookData) {
    ByteBuffer prologue{};
    if (!FindPrologue(target, 14, &prologue))
        return false;

    if (!PlaceDetourJmp(target, reinterpret_cast<ULONGLONG>(detour)))
        return false;

    if (original) {
        PVOID trampoline;
        if (!CreateTrampoline(target, prologue, &trampoline))
            return false;

        hookData->Trampoline = trampoline;
        *original = trampoline;
    }

    hookData->Target = target;
    hookData->Detour = detour;
    hookData->Prologue = prologue;
    return true;
}

bool CaveHook(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original) {
    HOOK_DATA ignored{};
    return CaveHookEx(target, detour, original, &ignored);
}

int CaveLastError() {
    return lastError;
}
