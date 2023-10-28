#pragma once

#include <stdlib.h>

/// <summary>
/// Allocate memory and check that it was allocated.
/// </summary>
/// <param name="count">Count of elements.</param>
/// <param name="es">Size of each element.</param>
/// <returns>Pointer to the allocated memory.</returns>
inline void* smalloc(const size_t count, const size_t es)
{
	void* addr = malloc(count * es);
	if (!addr)
		exit(1);

	return addr;
}

/* Free memory allocated by smalloc. */
#define sfree(addr) { free(addr); }