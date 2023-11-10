#pragma once

#include "wsinternal.h"

/* Enable/Disable process shutdown. */
#define DEBUG

/* Max number of iterators. */
#define MAX_ITERATOR_THREADS	26

/* Size of block to read from a file. */
#define READ_BLOCK_SIZE		0x100000i64
/* Min size of a file to be considered a medium file. */
#define MEDIUM_FILE_SIZE	0x500000i64
/* Min size of a file to be considered a large file. */
#define LARGE_FILE_SIZE		0x1400000i64

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