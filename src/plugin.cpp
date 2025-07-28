/*
 * DLL Injection Plugin for System Informer
 * Adds DLL injection capability to process context menu
 * Includes both LoadLibrary and Manual Mapping methods
 */

#include "plugin.h"

// to build your own build the sdk from https://github.com/winsiderss/systeminformer
#pragma comment(lib, "SystemInformer.lib")

static PPH_PLUGIN PluginInstance;
static PH_CALLBACK_REGISTRATION MenuItemCallbackRegistration;
static PH_CALLBACK_REGISTRATION ProcessMenuInitializingCallbackRegistration;

LOGICAL DllMain(
    _In_ HINSTANCE Instance,
    _In_ ULONG Reason,
    _Reserved_ PVOID Reserved)
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        PPH_PLUGIN_INFORMATION info;
        PH_SETTING_CREATE settings[] =
        {
            {IntegerSettingType, (PWSTR)SETTINGS_SHOW_DLL_INJECT, (PWSTR)L"1"},
            {IntegerSettingType, (PWSTR)SETTINGS_SHOW_MANUAL_MAPPING, (PWSTR)L"1"}
        };

        PluginInstance = PhRegisterPlugin(PLUGIN_NAME, Instance, &info);
        if (!PluginInstance)
            return FALSE;

        info->DisplayName = L"DLL Injection Plugin";
        info->Author = L"Smug";
        info->Description = L"Adds DLL injection capability with LoadLibrary and Manual Mapping";

        PhAddSettings(settings, RTL_NUMBER_OF(settings));

        PhRegisterCallback(
            PhGetPluginCallback(PluginInstance, PluginCallbackMenuItem),
            MenuItemCallback,
            NULL,
            &MenuItemCallbackRegistration);

        PhRegisterCallback(
            PhGetGeneralCallback(GeneralCallbackProcessMenuInitializing),
            ProcessMenuInitializingCallback,
            NULL,
            &ProcessMenuInitializingCallbackRegistration);
    }
    break;
    }

    return TRUE;
}

VOID HandleInjectDllCommand(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process)
{
    LOG("Injecting DLL with default systeminformer method");

    PhReferenceObject(Process);
    PhUiLoadDllProcess(WindowHandle, Process);
    PhDereferenceObject(Process);
}

VOID HandleManualMapDllCommand(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process)
{

    LOG("Injecting DLL with manual mapping method");

    static PH_FILETYPE_FILTER filters[] =
        {
            {(PWSTR)L"DLL files (*.dll)", (PWSTR)L"*.dll"},
            {(PWSTR)L"All files (*.*)", (PWSTR)L"*.*"}};

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE processHandle = NULL;
    PVOID dllBuffer = NULL;
    SIZE_T dllSize = 0;
    PVOID fileDialog;
    PPH_STRING fileName;
    HANDLE fileHandle;
    FILE_STANDARD_INFORMATION fileStandardInfo;
    IO_STATUS_BLOCK ioStatusBlock;

    fileDialog = PhCreateOpenFileDialog();
    PhSetFileDialogOptions(fileDialog, PH_FILEDIALOG_DONTADDTORECENT);
    PhSetFileDialogFilter(fileDialog, filters, RTL_NUMBER_OF(filters));

    if (!PhShowFileDialog(WindowHandle, fileDialog))
    {
        PhFreeFileDialog(fileDialog);
        return;
    }

    fileName = (PPH_STRING)PH_AUTO(PhGetFileDialogFileName(fileDialog));
    PhFreeFileDialog(fileDialog);

    TOKEN_PRIVILEGES priv = {0};
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

        CloseHandle(hToken);
    }
    DWORD pid = (DWORD)(ULONG_PTR)Process->ProcessId;

    // // Open target process with comprehensive access rights
    // status = PhOpenProcess(
    //     &processHandle,
    //           PROCESS_QUERY_LIMITED_INFORMATION
    //         | PROCESS_SET_LIMITED_INFORMATION
    //         | PROCESS_QUERY_INFORMATION
    //         | PROCESS_CREATE_THREAD
    //         | PROCESS_VM_OPERATION
    //         | PROCESS_VM_READ
    //         | PROCESS_VM_WRITE
    //         | SYNCHRONIZE,
    //     Process->ProcessId
    // );

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!processHandle)
    {
        DWORD Err = GetLastError();
        PhShowStatus(WindowHandle, L"Unable to open process", Err, 0);
        return;
    }

    // Read DLL file into memory manually
    status = PhCreateFileWin32(
        &fileHandle,
        PhGetString(fileName),
        FILE_GENERIC_READ,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (NT_SUCCESS(status))
    {
        status = NtQueryInformationFile(
            fileHandle,
            &ioStatusBlock,
            &fileStandardInfo,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation);

        if (NT_SUCCESS(status))
        {
            dllSize = (SIZE_T)fileStandardInfo.EndOfFile.QuadPart;
            dllBuffer = PhAllocate(dllSize);

            if (dllBuffer)
            {
                status = NtReadFile(
                    fileHandle,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatusBlock,
                    dllBuffer,
                    (ULONG)dllSize,
                    NULL,
                    NULL);

                if (NT_SUCCESS(status))
                    status = ManualMapDll(processHandle, dllBuffer, dllSize);

                PhFree(dllBuffer);
            }
            else
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        NtClose(fileHandle);
    }

    NtClose(processHandle);

    if (!NT_SUCCESS(status))
    {
        PhShowStatus(WindowHandle, L"Failed to manually map DLL", status, 0);
    }
}

VOID CreateInjectMenu(_In_ PPH_PLUGIN_MENU_INFORMATION MenuInfo)
{
    PPH_EMENU_ITEM parentMenu = MenuInfo->Menu;
    PPH_EMENU_ITEM injectSubmenu = NULL;
    PPH_EMENU_ITEM injectMenuItem;
    PPH_EMENU_ITEM manualMapMenuItem = NULL;
    PPH_EMENU_ITEM referenceMenuItem;
    ULONG insertIndex = ULONG_MAX;
    BOOLEAN showManualMapping;

    // Only show menu if setting is enabled
    if (!PhGetIntegerSetting(SETTINGS_SHOW_DLL_INJECT))
        return;

    showManualMapping = !!PhGetIntegerSetting(SETTINGS_SHOW_MANUAL_MAPPING);

    injectMenuItem = PhPluginCreateEMenuItem(
        PluginInstance,
        0,
        ID_USER_LOAD_DLL,
        showManualMapping ? L"&LoadLibrary Injection" : L"&Inject DLL (LoadLibrary)",
        NULL);

    if (!injectMenuItem)
        return;

    if (showManualMapping)
    {
        manualMapMenuItem = PhPluginCreateEMenuItem(
            PluginInstance,
            0,
            ID_USER_MANUAL_MAP_DLL,
            L"&Manual Map DLL",
            NULL);

        if (!manualMapMenuItem)
        {
            PhDestroyEMenuItem(injectMenuItem);
            return;
        }

        injectSubmenu = PhPluginCreateEMenuItem(
            PluginInstance, 0, 0, L"I&nject DLL", NULL
        );

        if (!injectSubmenu)
        {
            PhDestroyEMenuItem(injectMenuItem);
            PhDestroyEMenuItem(manualMapMenuItem);
            return;
        }

        PhInsertEMenuItem(injectSubmenu, manualMapMenuItem, ULONG_MAX);
        PhInsertEMenuItem(injectSubmenu, injectMenuItem, ULONG_MAX);
    }

    referenceMenuItem = PhFindEMenuItem(parentMenu, 0, NULL, PHAPP_ID_PROCESS_WINDOW);
    if (referenceMenuItem)
    {
        insertIndex = PhIndexOfEMenuItem(parentMenu, referenceMenuItem);
    }
    else
    {
        referenceMenuItem = PhFindEMenuItem(parentMenu, 0, NULL, PHAPP_ID_PROCESS_COPY);
        if (referenceMenuItem)
            insertIndex = PhIndexOfEMenuItem(parentMenu, referenceMenuItem) + 1;
    }

    if (showManualMapping && injectSubmenu)
    {
        PhInsertEMenuItem(parentMenu, injectSubmenu, insertIndex + 1);
    }
    else
    {
        PhInsertEMenuItem(parentMenu, injectMenuItem, insertIndex + 1);
    }
}

_Function_class_(PH_CALLBACK_FUNCTION)
    VOID NTAPI ProcessMenuInitializingCallback(
        _In_ PVOID Parameter,
        _In_ PVOID Context)
{
    PPH_PLUGIN_MENU_INFORMATION menuInfo = (PPH_PLUGIN_MENU_INFORMATION)Parameter;

    if (!menuInfo)
        return;

    CreateInjectMenu(menuInfo);
}

_Function_class_(PH_CALLBACK_FUNCTION)
    VOID NTAPI MenuItemCallback(
        _In_opt_ PVOID Parameter,
        _In_opt_ PVOID Context)
{
    PPH_PLUGIN_MENU_ITEM menuItem = (PPH_PLUGIN_MENU_ITEM)Parameter;
    PPH_PROCESS_ITEM process;

    if (!menuItem)
        return;

    process = PhGetSelectedProcessItem();

    if (!process)
        return;

    PhReferenceObject(process);

    switch (menuItem->Id)
    {
    case ID_USER_LOAD_DLL:
        HandleInjectDllCommand(menuItem->OwnerWindow, process);
        break;
    case ID_USER_MANUAL_MAP_DLL:
        HandleManualMapDllCommand(menuItem->OwnerWindow, process);
        break;
    }

    PhDereferenceObject(process);
}