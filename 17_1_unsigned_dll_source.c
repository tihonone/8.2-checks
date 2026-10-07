/*
 * Benign native Windows x64 test DLL; do not sign.
 * No imports, network, file/registry changes, threads or service entry point.
 * DllMain returns TRUE; the optional test export returns the constant 13.
 * Build in x64 Native Tools Command Prompt:
 * cl /nologo /TC /LD /O2 /GS- /Zl EDR_Unsigned_Module.c /link /NODEFAULTLIB /ENTRY:DllMain /MACHINE:X64 /OUT:EDR_Unsigned_Module.dll
 * This deliberately CRT-free entry point is only for this minimal test source.
 */
typedef void *EDR_HANDLE;
typedef unsigned long EDR_DWORD;
typedef int EDR_BOOL;

EDR_BOOL __stdcall DllMain(EDR_HANDLE module, EDR_DWORD reason, void *reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return 1;
}

__declspec(dllexport) int EDRModuleSelfTest(void)
{
    return 13;
}