#include "decryptor.h"

int main(int argc, char* argv[])
{
	HANDLE hMutex = CreateMutexW(NULL, TRUE, L"a65d3aae-80a3-4f79-9df3-32833c1109ee");
	if (!hMutex || hMutex == INVALID_HANDLE_VALUE)
		return 1;
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		printf("Program already running\n");
		goto cleanup;
	}
	
	printf("Ransomware Decryption Started\n");
	time_t t0 = time(NULL);
	BOOL result = decryptDrives();
	time_t t1 = time(NULL);
	
	printf("Ransomware Decryption Ended: %s\n", result ? "Success" : "Fail");
	printf("%.03f seconds / %.03f minutes\n\n", (float)(t1 - t0), (float)(t1 - t0) / 60);

cleanup:
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);

	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
	if (!_CrtDumpMemoryLeaks())
		OutputDebugStringA("------------- No memory leaks were found -------------\n");

	return 0;
}