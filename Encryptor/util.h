#pragma once

#include "wsinternal.h"
#include <other/memory.h>

/// <summary>
/// Execute a cmd command
/// </summary>
/// <param name="command">Command to execute.</param>
/// <param name="show">Show the window.</param>
/// <returns>TRUE if executed the command, FALSE, otherwise.</returns>
inline BOOL executeCmdCommand(const wchar_t* command, BOOL show)
{
	static const UINT EXTRA = 1 + 3 + 1;	// NT, /c , NT
	
	size_t clen = lstrlenW(command);
	wchar_t* fullCommand = (wchar_t*)smalloc(clen + EXTRA, sizeof(wchar_t));
	wsprintfW(fullCommand, L"%/c %ls", command);
	
	HINSTANCE hInstance = ShellExecuteW(NULL, L"open", L"cmd.exe", fullCommand, NULL, show ? SW_SHOW : SW_HIDE);
	sfree(fullCommand);
	
	return hInstance > 32 ? TRUE : FALSE;
}

/// <summary>
/// Check if a registry exists.
/// </summary>
/// <param name="hKey">Hive of the registry.</param>
/// <param name="lpSubKey">Path of the registry.</param>
/// <returns>TRUE if it exists, FALSE, otherwise.</returns>
inline BOOL registryExists(HKEY hKey, const wchar_t* lpSubKey)
{
	HKEY hkResult = NULL;
	if (RegOpenKeyExW(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
	{
		RegCloseKey(hkResult);
		return TRUE;
	}

	return FALSE;
}

/// <summary>
/// Get the PEB struct.
/// </summary>
/// <returns>PEB, NULL if failed.</returns>
inline FPEB* getPeb()
{
	PROCESS_BASIC_INFORMATION pbi;
	if (NT_ERROR(NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
		return NULL;
	
	return (FPEB*)pbi.PebBaseAddress;
}

/// <summary>
/// Get the current username.
/// </summary>
/// <returns>Current username, NULL if failed.</returns>
inline wchar_t* getUsername()
{
	DWORD usernameSize = UNLEN + 1;
	wchar_t* username = (wchar_t*)smalloc(usernameSize, sizeof(wchar_t));
	if (!GetUserNameW(username, &usernameSize))
	{
		sfree(username);
		return NULL;
	}
	
	return username;
}

/// <summary>
/// Get current netbios username.
/// </summary>
/// <returns>Netbios username, NULL if failed</returns>
inline wchar_t* getNetbiosHostname()
{
	wchar_t* hostname;
	DWORD nSize = MAX_COMPUTERNAME_LENGTH + 1;

	hostname = (wchar_t*)smalloc(nSize, sizeof(wchar_t));
	if (!GetComputerNameW(hostname, &nSize))
	{
		sfree(hostname);
		return NULL;
	}

	return hostname;
}

/// <summary>
/// Get current DNS hostname.
/// </summary>
/// <returns>DNS hostname, NULL if failed</returns>
static wchar_t* getDnsHostname()
{
	wchar_t* hostname;
	DWORD nSize = 0;

	GetComputerNameExW(ComputerNameDnsHostname, NULL, &nSize);
	hostname = (wchar_t*)smalloc(nSize + 1, sizeof(wchar_t));

	if (!GetComputerNameExW(ComputerNameDnsHostname, hostname, &nSize))
	{
		free(hostname);
		return NULL;
	}

	return hostname;
}

/// <summary>
/// Get system info.
/// </summary>
/// <returns>System Info.</returns>
inline SYSTEM_INFO getSystemInfo()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	return sysInfo;
}