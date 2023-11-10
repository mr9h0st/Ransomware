#include <stdio.h>
#include <other/memory.h>
#include <other/utility.h>
#include <other/settings.h>
#include "curve25519.h"
#include "ecrypt-sync.h"
#include "sha512.h"
#include "crc32.h"

/* Private key to decrypt the private key with. */
static const BYTE PRIVATE_KEY[32] = { 0x88, 0xe8, 0xa7, 0x81, 0xe2, 0x6d, 0x7b,
    0xd3, 0x70, 0x4c, 0x0c, 0x69, 0x07, 0x0c, 0xf0, 0xd5, 0x58, 0xbc, 0xfb,
    0x30, 0xec, 0xc6, 0x3a, 0xe5, 0x8e, 0xc6, 0xc3, 0xd0, 0xae, 0x1c, 0x2a, 0x6d };

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "<%s> <Private key file>\n", argv[0]);
        return 1;
    }
    const char* filePath = argv[1];
    if (!filePath)
    {
        fprintf(stderr, "File path is invalid\n");
        return 2;
    }
    
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "File %s does not exist\n", filePath);
        return 3;
    }

    LARGE_INTEGER fileSize, fileOffset;
    fileOffset.QuadPart = 0;
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        fprintf(stderr, "Failed getting file size of %s\n", filePath);
        CloseHandle(hFile);

        return 4;
    }

    // If the file is smaller, no metadata exists
    if (fileSize.QuadPart < sizeof(FileMetadata_t))
    {
        fprintf(stderr, "File %s does not contain metadata\n", filePath);
        CloseHandle(hFile);

        return 5;
    }

    DWORD dwRead, dwWrite;
    BYTE sharedSecret[32];
    Keys_t keys;
    FileMetadata_t mt;

    // Read the metadata
    fileOffset.QuadPart = fileSize.QuadPart - sizeof(FileMetadata_t);
    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
    if (!ReadFile(hFile, &mt, sizeof(FileMetadata_t), &dwRead, 0))
    {
        fprintf(stderr, "Failed reading metadata from %s\n", filePath);
        CloseHandle(hFile);

        return 6;
    }

    fileSize.QuadPart -= sizeof(FileMetadata_t);
    curve25519(sharedSecret, PRIVATE_KEY, mt.curve25519Public);
    SHA512_Simple(sharedSecret, sizeof(sharedSecret), &keys);
    if (mt.xcrc32Hash != xcrc32(&keys, sizeof(Keys_t)))
    {
        fprintf(stderr, "File %s is corrupted\n", filePath);
        CloseHandle(hFile);

        return 7;
    }
    
    // Setup the Key & IV for the decryption
    BYTE* buffer = (BYTE*)smalloc(sizeof(sharedSecret), sizeof(BYTE));
    ECRYPT_ctx ctx;
    ECRYPT_keysetup(&ctx, keys.hc256Key, 256, 256);
    ECRYPT_ivsetup(&ctx, keys.hc256Vector);

    // Go back to the start of the file
    fileOffset.QuadPart = 0;
    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);

    if (!ReadFile(hFile, buffer, sizeof(sharedSecret), &dwRead, 0))
    {
        fprintf(stderr, "Failed reading data from %s\n", filePath);
        sfree(buffer);

        CloseHandle(hFile);
        return 8;
    }
    CloseHandle(hFile);
    
    ECRYPT_process_bytes(0, &ctx, buffer, buffer, dwRead);
    wchar_t* newPath = getSpecialDirectory(&FOLDERID_Desktop);
    if (!newPath)
    {
        fprintf(stderr, "Failed reading data from %s\n", filePath);
        sfree(buffer);
        
        return 9;
    }
    lstrcatW(newPath, L"\\");
    lstrcatW(newPath, DEC_PK_FILE_NAME);
    
    HANDLE hNewFile = CreateFileW(newPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hNewFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Failed opening %ls\n", newPath);
        goto mcleanup;
    }
    
    if (!WriteFile(hNewFile, buffer, dwRead, &dwWrite, NULL))
    {
        fprintf(stderr, "Failed writing to %ls\n", newPath);
        CloseHandle(hNewFile);

        goto mcleanup;
    }
    
    CloseHandle(hNewFile);
    DeleteFileA(filePath);
    printf("Successfully wrote decrypted data to %ls\n", newPath);

mcleanup:
    sfree(buffer);
    sfree(newPath);
    
    return 0;
}