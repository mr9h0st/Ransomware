#pragma once

#include <stdio.h>
#include <stdarg.h>

/* Enable/Disable encryption, volume mounting... */
#define DEBUG
/* Enable/Disable debug messages. */
#define DEBUGMSG

#ifdef DEBUGMSG
/* Print a debug message. */
#define dbgmsg(...) (ddbgmsg(__FUNCTION__, __LINE__, __VA_ARGS__))
#else
/* Print a debug message. */
#define dbgmsg(...) { }
#endif

/* Print a debug message with a status whether it was sucessful. */
#define dbgstatus(s, ...) dbgmsg(__VA_ARGS__);		\
	printf(": %s\n", s ? "Success" : "Fail");		\

/* Print a debug message with a status whether it was successful without its origin. */
#define ndbgstatus(s, ...) printf(__VA_ARGS__);		\
	printf(": %s\n", s ? "Success" : "Fail");		\

/* Print a debug message without its origin. */
#define ndbgmsg(...) printf(__VA_ARGS__);

/// <summary>
/// Print a debug message.
/// </summary>
/// <param name="function">Function that requested debug.</param>
/// <param name="line">Line that requested debug.</param>
/// <param name="fmt">Format of the string.</param>
inline void ddbgmsg(const char* function, const unsigned long line, const char* fmt, ...)
{
	printf("[%s:%lu]\t", function, line);
	
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}