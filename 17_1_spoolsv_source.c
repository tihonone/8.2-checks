/* BENIGN LAB SERVICE V3, not Windows Print Spooler.
 * Build x64: cl /nologo /TC /W4 /O2 /MT EDR_Spoolsv_LabService.c /Fe:spoolsv.exe /link /MACHINE:X64 Advapi32.lib
 * Reads only its own Parameters\ServiceDll, LogPath, HoldSeconds.
 * No networking or service/registry installation.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef _WIN64
#error Build this lab service with the x64 MSVC toolchain.
#endif
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
static const wchar_t *name = L"EDRSafeUnsignedDllService";
static const wchar_t *key = L"SYSTEM\\CurrentControlSet\\Services\\EDRSafeUnsignedDllService\\Parameters";
static SERVICE_STATUS_HANDLE sh;
static SERVICE_STATUS ss;
static HANDLE stopEvent;
static wchar_t logPath[32768];
/* Avoid SDK/target-version-dependent RegGetValue subkey flags.
 * Select the 64-bit registry view when opening, then read this exact handle.
 */
static DWORD readParameter(const wchar_t *value, DWORD flags, void *data, DWORD *bytes) {
    HKEY parameters = NULL;
    LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0,
        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &parameters);
    if (result != ERROR_SUCCESS) return (DWORD)result;
    result = RegGetValueW(parameters, NULL, value, flags | RRF_ZEROONFAILURE,
        NULL, data, bytes);
    RegCloseKey(parameters);
    return (DWORD)result;
}
static void report(DWORD state, DWORD error) {
    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS; ss.dwCurrentState = state;
    ss.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    ss.dwWin32ExitCode = error;
    ss.dwCheckPoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 1 : 0;
    ss.dwWaitHint = ss.dwCheckPoint ? 10000 : 0;
    SetServiceStatus(sh, &ss);
}
static DWORD WINAPI handler(DWORD control, DWORD event, void *data, void *context) {
    (void)event; (void)data; (void)context;
    if ((control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) && stopEvent)
        SetEvent(stopEvent);
    return NO_ERROR;
}
static BOOL record(const char *message, DWORD error) {
    SYSTEMTIME t; char buffer[512]; DWORD written;
    GetSystemTime(&t);
    int n = sprintf_s(buffer, sizeof(buffer),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ PID=%lu %s Win32=%lu\r\n",
        (unsigned)t.wYear,(unsigned)t.wMonth,(unsigned)t.wDay,(unsigned)t.wHour,
        (unsigned)t.wMinute,(unsigned)t.wSecond,(unsigned)t.wMilliseconds,
        GetCurrentProcessId(),message,error);
    HANDLE f = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE || n <= 0) {
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f); return FALSE;
    }
    BOOL ok = WriteFile(f, buffer, (DWORD)n, &written, NULL);
    CloseHandle(f); return ok && written == (DWORD)n;
}
static BOOL validDll(const wchar_t *path) {
    const wchar_t *prefix = L"C:\\Windows\\System32\\spool\\drivers\\EDR_Module_";
    size_t n = wcslen(prefix);
    if (_wcsnicmp(path,prefix,n) || wcslen(path) != n+36 || _wcsicmp(path+n+32,L".dll")) return FALSE;
    for (size_t i=n; i<n+32; ++i)
        if (!((path[i]>=L'0' && path[i]<=L'9') || (path[i]>=L'a' && path[i]<=L'f'))) return FALSE;
    return TRUE;
}
static void WINAPI serviceMain(DWORD argc, wchar_t **argv) {
    wchar_t dll[32768],loaded[32768],image[32768],expected[32768];
    DWORD bytes,hold=0,error=0,length; HMODULE module=NULL;
    (void)argc; (void)argv;
    sh=RegisterServiceCtrlHandlerExW(name,handler,NULL); if (!sh) return;
    report(SERVICE_START_PENDING,0);
    bytes=sizeof(dll);
    error=readParameter(L"ServiceDll",RRF_RT_REG_SZ|RRF_RT_REG_EXPAND_SZ,dll,&bytes);
    if (error || !validDll(dll)) { report(SERVICE_STOPPED,error?error:ERROR_INVALID_DATA); return; }
    bytes=sizeof(logPath);
    error=readParameter(L"LogPath",RRF_RT_REG_SZ,logPath,&bytes);
    if (error) { report(SERVICE_STOPPED,error); return; }
    length=GetModuleFileNameW(NULL,image,32768);
    wchar_t *slash=length && length<32768 ? wcsrchr(image,L'\\') : NULL;
    if (!slash) { report(SERVICE_STOPPED,ERROR_INVALID_DATA); return; }
    *slash=L'\0';
    if (swprintf_s(expected,32768,L"%s\\module.log",image)<0 || _wcsicmp(expected,logPath)) {
        report(SERVICE_STOPPED,ERROR_INVALID_DATA); return;
    }
    bytes=sizeof(hold);
    error=readParameter(L"HoldSeconds",RRF_RT_REG_DWORD,&hold,&bytes);
    if (error || hold<1 || hold>300) { report(SERVICE_STOPPED,ERROR_INVALID_DATA); return; }
    stopEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (!stopEvent) { report(SERVICE_STOPPED,GetLastError()); return; }
    module=LoadLibraryExW(dll,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) { error=GetLastError(); record("MODULE LOAD FAILED",error); }
    else {
        length=GetModuleFileNameW(module,loaded,32768);
        if (!length || length>=32768 || _wcsicmp(loaded,dll)) {
            error=ERROR_INVALID_DATA; record("MODULE PATH FAILED",error);
        } else if (!record("MODULE LOAD VERIFIED process=spoolsv.exe role=LAB_SERVICE_V3",0)) {
            error=ERROR_WRITE_FAULT;
        } else {
            report(SERVICE_RUNNING,0); WaitForSingleObject(stopEvent,hold*1000);
        }
        report(SERVICE_STOP_PENDING,0);
        if (!FreeLibrary(module)) { error=GetLastError(); record("MODULE UNLOAD FAILED",error); }
        else if (!record("MODULE UNLOAD VERIFIED",0)) error=ERROR_WRITE_FAULT;
    }
    CloseHandle(stopEvent); stopEvent=NULL;
    record("SERVICE STOPPED",error); report(SERVICE_STOPPED,error);
}
int wmain(int argc,wchar_t **argv) {
    if (argc==2 && !_wcsicmp(argv[1],L"--version")) { printf("EDR_LAB_SERVICE_V3\n"); return 0; }
    if (argc!=3 || _wcsicmp(argv[1],L"--service") || wcscmp(argv[2],name)) {
        printf("Use --service EDRSafeUnsignedDllService via SCM or --version.\n"); return 2;
    }
    SERVICE_TABLE_ENTRYW table[]={{(LPWSTR)name,serviceMain},{NULL,NULL}};
    if (!StartServiceCtrlDispatcherW(table)) {
        printf("StartServiceCtrlDispatcherW failed: %lu\n",GetLastError()); return 3;
    }
    return 0;
}