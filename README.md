# kCaveHook
Lightweight library for hooking functions in kernel mode

### Quick example
```cpp
QWORD original;

void __fastcall Detour(int arg1, int arg2) {
    DbgPrintEx(0, 0, "Hooked\n");
    return reinterpet_cast<decltype(&Detour)>(original)(arg1, arg2);
}

bool status = CaveHook(0x123, &Detour, reinterpret_cast<LPVOID*>(&original));
if (!status) {
    DbgPrintEx(0, 0, "%d\n", CaveLastError());
}
```

### Real example
https://github.com/Umbre11as/NoBsodDriver/blob/master/src/main.cpp#L6-L16

https://github.com/Umbre11as/NoBsodDriver/blob/master/src/main.cpp#L21-L27

### How it works
Look at my past hooks in usermode: https://github.com/Umbre11as/CaveHook

### References
[Zydis](https://github.com/zyantific/zydis)
