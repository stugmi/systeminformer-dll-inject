#pragma once 

#ifndef _PLUGIN_H
#define _PLUGIN_H

#include <phdk.h>
#include <phapppub.h>
#include <settings.h>
#include <phappresource.h>

// Plugin identification
#define PLUGIN_NAME L"ProcessHacker.DllInject"

// Settings
#define SETTINGS_SHOW_DLL_INJECT (PLUGIN_NAME L".ShowDllInjectEntry")
#define SETTINGS_SHOW_MANUAL_MAPPING (PLUGIN_NAME L".ShowDllManualMapping")

// Menu item identifier
#define ID_USER_LOAD_DLL 313371
#define ID_USER_MANUAL_MAP_DLL 313372

// Function declarations
LOGICAL DllMain(
    _In_ HINSTANCE Instance,
    _In_ ULONG Reason,
    _Reserved_ PVOID Reserved
);

VOID NTAPI MenuItemCallback(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
);

VOID NTAPI ProcessMenuInitializingCallback(
    _In_ PVOID Parameter,
    _In_ PVOID Context
);

VOID CreateInjectMenu(
    _In_ PPH_PLUGIN_MENU_INFORMATION MenuInfo
);

VOID HandleInjectDllCommand(
    _In_ HWND WindowHandle
);

VOID HandleManualMapDllCommand(
    _In_ HWND WindowHandle
);

NTSTATUS ManualMapDll(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize
);

PVOID GetProcAddressManual(
    _In_ PVOID ModuleBase,
    _In_ PCHAR FunctionName
);


extern PPH_PLUGIN PluginInstance;
extern PH_CALLBACK_REGISTRATION MenuItemCallbackRegistration;
extern PH_CALLBACK_REGISTRATION ProcessMenuInitializingCallbackRegistration;


#define LOG(fmt, ...) PhpLogEntry(PH_LOG_ENTRY_MESSAGE, fmt, __VA_ARGS__)
#define LOG_PROC(fmt, ...) PhpLogEntry(PH_LOG_ENTRY_PROCESS_CREATE, fmt, __VA_ARGS__)

FORCEINLINE VOID PhpLogEntry(UCHAR type, const char* fmt, ...)
{
    char buf[512];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    char prefixBuf[512];
    _snprintf_s(prefixBuf, sizeof(prefixBuf), _TRUNCATE, "[DLL Injection] %s", buf);

    PPH_STRING msg = PhConvertMultiByteToUtf16(prefixBuf);
    if (msg)
    {
        PhLogMessageEntry(type, msg);
        PhDereferenceObject(msg);
    }
}


#endif // _PLUGIN_H