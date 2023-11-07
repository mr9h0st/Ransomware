#pragma once

#include "util.h"

#define SIZE_OF_IMAGE_INC_SIZE 0x100000

/// <summary>
/// Make the image invalid for dump.
/// </summary>
void antiDump()
{
	PEB* peb = getPeb();
	if (!peb)
		return;
	
	// Increase SizeOfImage
	PLIST_ENTRY entry = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
	PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
	PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1];
	*pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + SIZE_OF_IMAGE_INC_SIZE);
}