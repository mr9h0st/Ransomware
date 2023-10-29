#pragma once

#include "wsinternal.h"

#define _CRTDBG_MAP_ALLOC
#include <stdio.h>
#include <time.h>
#include <crtdbg.h>

/* Enable/Disable decryption. */
#define DEBUG

/* Max number of iterators. */
#define MAX_ITERATOR_THREADS	26

/* Size of block to read from a file. */
#define READ_BLOCK_SIZE		0x100000i64
/* Min size of a file to be considered a medium file. */
#define MEDIUM_FILE_SIZE	0x500000i64
/* Min size of a file to be considered a large file. */
#define LARGE_FILE_SIZE		0x1400000i64

typedef struct PROG_KEYS
{
	BYTE hc256Key[32];
	BYTE hc256Vector[32];
} Keys_t;

typedef struct PROG_SESSION
{
	BYTE curve25519Shared[32];
	BYTE curve25519Private[32];
} Session_t;

typedef struct FILE_METADATA
{
	BYTE curve25519Public[32];
	DWORD xcrc32Hash;
} FileMetadata_t;

/// <summary>
/// Decrypt all drives.
/// </summary>
/// <returns>TRUE if succeeded, FALSE, otherwise.</returns>
BOOL decryptDrives();

/// <summary>
/// Terminate all processes that are using a file.
/// </summary>
/// <param name="filePath">Path of the file.</param>
/// <returns>TRUE if succeeded, FALSE, otherwise.</returns>
BOOL terminateFileProcesses(const wchar_t* filePath);