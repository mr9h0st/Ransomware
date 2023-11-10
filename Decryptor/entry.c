#include "decryptor.h"
#include "pre.h"
#include <stdio.h>
#include <time.h>

/* Name of the one-instance mutex. */
#define MUTEX_NAME L"a65d3aae-80a3-4f79-9df3-32833c1109ee"

int main(int argc, char* argv[])
{
	// One-Instance mutex
	HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
	if (!hMutex)
		return 1;
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		fprintf(stderr, "Program already running\n");
		goto cleanup;
	}
	
	BOOL status = preDecryption();
	printf("Pre-Decryption returned status: %d\n\n", status);
	
	printf("Ransomware Decryption Started\n");
	time_t t0 = time(NULL);
	BOOL result = decryptDrives();
	time_t t1 = time(NULL);
	
	printf("Ransomware Decryption Ended: %s\n", result ? "Success" : "Fail");
	printf("%.03f seconds / %.03f minutes\n", (float)(t1 - t0), (float)(t1 - t0) / 60);
	
cleanup:
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	
	return 0;
}