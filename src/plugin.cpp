/*
 * DLL Injection Plugin for System Informer
 * Adds DLL injection capability to process context menu
 * Includes both LoadLibrary and Manual Mapping methods
 */

// #include "injector.h"
#include "plugin.h"

#pragma comment(lib, "SystemInformer.lib")

// Plugin globals
static PPH_PLUGIN PluginInstance;
static PH_CALLBACK_REGISTRATION MenuItemCallbackRegistration;
static PH_CALLBACK_REGISTRATION ProcessMenuInitializingCallbackRegistration;

// DLL entry point
LOGICAL DllMain(
    _In_ HINSTANCE Instance,
    _In_ ULONG Reason,
    _Reserved_ PVOID Reserved
)
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        PPH_PLUGIN_INFORMATION info;

        // Plugin settings
        PH_SETTING_CREATE settings[] =
        {
            { IntegerSettingType, (PWSTR)SETTINGS_SHOW_DLL_INJECT, (PWSTR)L"1"  },
            { IntegerSettingType, (PWSTR)SETTINGS_SHOW_MANUAL_MAPPING, (PWSTR)L"1" }
        };

        // Register plugin with System Informer
        PluginInstance = PhRegisterPlugin(PLUGIN_NAME, Instance, &info);
        if (!PluginInstance)
            return FALSE;

        // Set plugin information
        info->DisplayName = L"DLL Injection Plugin";
        info->Author = L"Smug";
        info->Description = L"Adds DLL injection capability with LoadLibrary and Manual Mapping";

        // Register plugin settings
        PhAddSettings(settings, RTL_NUMBER_OF(settings));

        // Register callback for menu item clicks
        PhRegisterCallback(
            PhGetPluginCallback(PluginInstance, PluginCallbackMenuItem),
            MenuItemCallback,
            NULL,
            &MenuItemCallbackRegistration
        );

        // Register callback for process menu initialization
        PhRegisterCallback(
            PhGetGeneralCallback(GeneralCallbackProcessMenuInitializing),
            ProcessMenuInitializingCallback,
            NULL,
            &ProcessMenuInitializingCallbackRegistration
        );
    }
    break;
    }

    return TRUE;
}


// Handle the standard DLL injection command
VOID HandleInjectDllCommand(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process
)
{
    LOG("Injecting DLL with default systeminformer method");

    PhReferenceObject(Process);
    PhUiLoadDllProcess(WindowHandle, Process);
    PhDereferenceObject(Process);
}

// Handle the manual mapping DLL injection command
VOID HandleManualMapDllCommand(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process
)
{

    LOG("Injecting DLL with manual mapping method");

    static PH_FILETYPE_FILTER filters[] =
    {
        { (PWSTR)L"DLL files (*.dll)", (PWSTR)L"*.dll" },
        { (PWSTR)L"All files (*.*)", (PWSTR)L"*.*" }
    };


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

    TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
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
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (NT_SUCCESS(status))
    {
        status = NtQueryInformationFile(
            fileHandle,
            &ioStatusBlock,
            &fileStandardInfo,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation
        );

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
                    NULL
                );

                if (NT_SUCCESS(status))
                {
                    // Perform manual mapping
                    status = ManualMapDll(processHandle, dllBuffer, dllSize);
                }

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

// // Create and insert the DLL injection menu items
// VOID CreateInjectMenu(_In_ PPH_PLUGIN_MENU_INFORMATION MenuInfo)
// {
//     PPH_EMENU_ITEM parentMenu = MenuInfo->Menu;
//     PPH_EMENU_ITEM injectMenuItem;
//     PPH_EMENU_ITEM manualMapMenuItem;
//     PPH_EMENU_ITEM referenceMenuItem;
//     ULONG insertIndex = ULONG_MAX;

//     // Only show menu if setting is enabled
//     if (!PhGetIntegerSetting(SETTINGS_SHOW_DLL_INJECT))
//         return;

//     // Create the standard injection menu item
//     injectMenuItem = PhPluginCreateEMenuItem(
//         PluginInstance,
//         0,
//         ID_USER_LOAD_DLL,
//         L"&Inject DLL (LoadLibrary)",
//         NULL
//     );

//     // Create the manual mapping menu item
//     manualMapMenuItem = PhPluginCreateEMenuItem(
//         PluginInstance,
//         0,
//         ID_USER_MANUAL_MAP_DLL,
//         L"&Manual Map DLL",
//         NULL
//     );

//     if (!injectMenuItem || !manualMapMenuItem)
//         return;

//     // Find a good position to insert the menu items
//     referenceMenuItem = PhFindEMenuItem(parentMenu, 0, NULL, PHAPP_ID_PROCESS_SEARCHONLINE);
//     if (referenceMenuItem)
//     {
//         insertIndex = PhIndexOfEMenuItem(parentMenu, referenceMenuItem);
//     }
//     else
//     {
//         referenceMenuItem = PhFindEMenuItem(parentMenu, 0, NULL, PHAPP_ID_PROCESS_COPY);
//         if (referenceMenuItem)
//             insertIndex = PhIndexOfEMenuItem(parentMenu, referenceMenuItem) + 1;
//     }

//     // Insert menu items
//     PhInsertEMenuItem(parentMenu, injectMenuItem, insertIndex + 1);
//     PhInsertEMenuItem(parentMenu, manualMapMenuItem, insertIndex + 2);
//     PhInsertEMenuItem(parentMenu, PhCreateEMenuSeparator(), insertIndex + 3);
// }


// Create and insert the DLL injection submenu
// Create and insert the DLL injection menu items
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

    // Create the standard injection menu item
    injectMenuItem = PhPluginCreateEMenuItem(
        PluginInstance,
        0,
        ID_USER_LOAD_DLL,
        showManualMapping ? L"&LoadLibrary Injection" : L"&Inject DLL (LoadLibrary)",
        NULL
    );

    if (!injectMenuItem)
        return;

    // Create manual mapping item only if enabled
    if (showManualMapping)
    {
        manualMapMenuItem = PhPluginCreateEMenuItem(
            PluginInstance,
            0,
            ID_USER_MANUAL_MAP_DLL,
            L"&Manual Map DLL",
            NULL
        );

        if (!manualMapMenuItem)
        {
            PhDestroyEMenuItem(injectMenuItem);
            return;
        }

        // Create submenu when both options are available
        injectSubmenu = PhPluginCreateEMenuItem(
            PluginInstance,
            0,
            0,  // No ID for the parent submenu
            L"I&nject DLL",
            NULL
        );

        if (!injectSubmenu)
        {
            PhDestroyEMenuItem(injectMenuItem);
            PhDestroyEMenuItem(manualMapMenuItem);
            return;
        }

        // Add both items to the submenu
        PhInsertEMenuItem(injectSubmenu, manualMapMenuItem, ULONG_MAX);
        PhInsertEMenuItem(injectSubmenu, injectMenuItem, ULONG_MAX);
    }

    // Find a good position to insert the menu item(s)
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

    // Insert the appropriate menu structure
    if (showManualMapping && injectSubmenu)
    {
        // Insert submenu with both options
        PhInsertEMenuItem(parentMenu, injectSubmenu, insertIndex + 1);
        // PhInsertEMenuItem(parentMenu, PhCreateEMenuSeparator(), insertIndex + 2);
    }
    else
    {
        // Insert single menu item
        PhInsertEMenuItem(parentMenu, injectMenuItem, insertIndex + 1);
        // PhInsertEMenuItem(parentMenu, PhCreateEMenuSeparator(), insertIndex + 2);
    }
}

// Callback for process menu initialization
_Function_class_(PH_CALLBACK_FUNCTION)
VOID NTAPI ProcessMenuInitializingCallback(
    _In_ PVOID Parameter,
    _In_ PVOID Context
)
{
    PPH_PLUGIN_MENU_INFORMATION menuInfo = (PPH_PLUGIN_MENU_INFORMATION)Parameter;

    if (!menuInfo)
        return;

    CreateInjectMenu(menuInfo);
}

// Callback for menu item selection
_Function_class_(PH_CALLBACK_FUNCTION)
VOID NTAPI MenuItemCallback(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    PPH_PLUGIN_MENU_ITEM menuItem = (PPH_PLUGIN_MENU_ITEM)Parameter;
    PPH_PROCESS_ITEM process;

    if (!menuItem)
        return;

    // Get the currently selected process
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