#pragma once

#include "wsinternal.h"

/// <summary>
/// Check if the current process has admin privileges.
/// </summary>
/// <returns>True if the process has amdin privileges, FALSE, otherwise.</returns>
inline BOOL isAdmin()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;
	
	BOOL status = FALSE;
	ULONG dwSize;
	TOKEN_ELEVATION token;
	
	if (!GetTokenInformation(hToken, TokenElevation, &token, sizeof(token), &dwSize))
		goto cleanup;
	
	status = token.TokenIsElevated;
	
cleanup:
	CloseHandle(hToken);
	return status;
}

/// <summary>
/// Check if the current user is related to the administrators group.
/// </summary>
/// <returns>True if it is related, FALSE, otherwise.</returns>
BOOL isRelatedToAdminGroup();

/// <summary>
/// Attempt to get admin privileges using UAC bypass.
/// </summary>
/// <returns>True if got admin, FALSE, otherwise.</returns>
BOOL getAdmin();