// #include "global.h"

#include "plugin.h"
#include "injector.h"
// #include "injector.h"

// #include <Windows.h>
// #include <iostream>
// #include <fstream>
// #include <stdio.h>
// #include <string>
// #include <TlHelp32.h>
// #include <winternl.h>
// #include <ntstatus.h>


#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif


// bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, 
// 	bool ClearHeader = true, 
// 	bool ClearNonNeededSections = true,
// 	bool AdjustProtections = true,
// 	bool SEHExceptionSupport = true,
// 	DWORD fdwReason = DLL_PROCESS_ATTACH,
// 	LPVOID lpReserved = 0);

NTSTATUS ManualMapDll(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize
) {

	bool ClearHeader = true;
	bool ClearNonNeededSections = true;
	bool AdjustProtections = true;
	bool SEHExceptionSupport = true;

	DWORD fdwReason = DLL_PROCESS_ATTACH;
	LPVOID lpReserved = 0;
    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    BYTE* pTargetBase = nullptr;
    BYTE* pSrcData = reinterpret_cast<BYTE*>(DllBuffer);

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
        LOG("Invalid file");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH) {
        LOG("Invalid platform");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    LOG("File ok");

    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(ProcessHandle, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pTargetBase) {
        LOG("Target process memory allocation failed (ex) 0x%X", GetLastError());
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    DWORD oldp = 0;
    VirtualProtectEx(ProcessHandle, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
    SEHExceptionSupport = false;
#endif
    data.pbase = pTargetBase;
    data.fdwReasonParam = fdwReason;
    data.reservedParam = lpReserved;
    data.SEHSupport = SEHExceptionSupport;

    // File header
    if (!WriteProcessMemory(ProcessHandle, pTargetBase, pSrcData, 0x1000, nullptr)) { // only first 0x1000 bytes for the header
        LOG("Can't write file header 0x%X", GetLastError());
        VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
        return STATUS_ACCESS_DENIED;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(ProcessHandle, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                LOG("Can't map sections: 0x%x", GetLastError());
                VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    // Mapping params
    BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(ProcessHandle, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!MappingDataAlloc) {
        LOG("Target process mapping allocation failed (ex) 0x%X", GetLastError());
        VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    if (!WriteProcessMemory(ProcessHandle, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        LOG("Can't write mapping 0x%X", GetLastError());
        VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, MappingDataAlloc, 0, MEM_RELEASE);
        return STATUS_ACCESS_DENIED;
    }

    // Shell code
    void* pShellcode = VirtualAllocEx(ProcessHandle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        LOG("Memory shellcode allocation failed (ex) 0x%X", GetLastError());
        VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, MappingDataAlloc, 0, MEM_RELEASE);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    if (!WriteProcessMemory(ProcessHandle, pShellcode, Shellcode, 0x1000, nullptr)) {
        LOG("Can't write shellcode 0x%X", GetLastError());
        VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, pShellcode, 0, MEM_RELEASE);
        return STATUS_ACCESS_DENIED;
    }

    LOG("Mapped DLL at %p", pTargetBase);
    LOG("Mapping info at %p", MappingDataAlloc);
    LOG("Shell code at %p", pShellcode);

    LOG("Data allocated");

#ifdef _DEBUG
    LOG("My shellcode pointer %p", Shellcode);
    LOG("Target point %p", pShellcode);
    system("pause");
#endif

    HANDLE hThread = CreateRemoteThread(
		ProcessHandle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode),
		MappingDataAlloc,
		0,
		nullptr
	);


    if (!hThread) {
        LOG("Thread creation failed 0x%X", GetLastError());
        VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, pShellcode, 0, MEM_RELEASE);
        return STATUS_ACCESS_DENIED;
    }
    CloseHandle(hThread);

    LOG("Thread created at: %p, waiting for return...", pShellcode);

    HINSTANCE hCheck = NULL;
    while (!hCheck) {
        DWORD exitcode = 0;
        GetExitCodeProcess(ProcessHandle, &exitcode);
        if (exitcode != STILL_ACTIVE) {
            LOG("Process crashed, exit code: %d", exitcode);
            return STATUS_PROCESS_NOT_IN_JOB;
        }

        MANUAL_MAPPING_DATA data_checked{ 0 };
        ReadProcessMemory(ProcessHandle, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;

        if (hCheck == (HINSTANCE)0x404040) {
            LOG("Wrong mapping ptr");
            VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(ProcessHandle, MappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(ProcessHandle, pShellcode, 0, MEM_RELEASE);
            return STATUS_INVALID_ADDRESS;
        }
        else if (hCheck == (HINSTANCE)0x505050) {
            LOG("WARNING: Exception support failed!");
        }

        Sleep(10);
    }

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
    if (emptyBuffer == nullptr) {
        LOG("Unable to allocate memory");
        return STATUS_NO_MEMORY;
    }
    memset(emptyBuffer, 0, 1024 * 1024 * 20);

    // CLEAR PE HEAD
	if (ClearHeader) {
		if (!WriteProcessMemory(ProcessHandle, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
			LOG("WARNING!: Can't clear HEADER");
		}
	}

    // CLEAR NON-NEEDED SECTIONS
	if(ClearNonNeededSections){

		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if ((data.SEHSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
                strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
                strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
					LOG("Processing %s removal", pSectionHeader->Name);
					if (!WriteProcessMemory(ProcessHandle, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
						LOG("Can't clear section %s: 0x%x", pSectionHeader->Name, GetLastError());
					}
				}
			}
		}
		
	}
    // ADJUST PROTECTIONS
	if(AdjustProtections){
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;
	
				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newP = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newP = PAGE_EXECUTE_READ;
				}
				if (VirtualProtectEx(ProcessHandle, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
					LOG("section %s set as %lX", (char*)pSectionHeader->Name, newP);
				}
				else {
					LOG("FAIL: section %s not set as %lX", (char*)pSectionHeader->Name, newP);
				}
			}
		}
		DWORD old = 0;
		VirtualProtectEx(ProcessHandle, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	}

    if (!WriteProcessMemory(ProcessHandle, pShellcode, emptyBuffer, 0x1000, nullptr)) {
        LOG("WARNING: Can't clear shellcode");
    }
    if (!VirtualFreeEx(ProcessHandle, pShellcode, 0, MEM_RELEASE)) {
        LOG("WARNING: can't release shell code memory");
    }
    if (!VirtualFreeEx(ProcessHandle, MappingDataAlloc, 0, MEM_RELEASE)) {
        LOG("WARNING: can't release mapping data memory");
    }

    free(emptyBuffer);
    return STATUS_SUCCESS;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) {
        pData->hMod = (HINSTANCE)0x404040;
        return;
    }

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta) {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                    if (RELOC_FLAG(*pRelativeInfo)) {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    bool ExceptionSupportFailed = false;

#ifdef _WIN64
    if (pData->SEHSupport) {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size) {
            if (!_RtlAddFunctionTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
                ExceptionSupportFailed = true;
            }
        }
    }
#endif

    _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

    if (ExceptionSupportFailed)
        pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
    else
        pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}