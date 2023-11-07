#pragma once

/* Enable/Disable encryption, volume mounting... */
#define DEBUG
/* Enable/Disable debug messages. */
#define DEBUGMSG

#ifdef DEBUGMSG
/* Print a debug message. */
#define dbgmsg(...) (_sdprintf(__FUNCTION__, __LINE__, __VA_ARGS__))

/* Print a debug message without its origin. */
#define ndbgmsg(...) _sprintf(__VA_ARGS__)

/* Print a debug message with a status whether it was sucessful. */
#define dbgstatus(s, ...) dbgmsg(__VA_ARGS__);		\
	_sprintf(": %s\n", s ? "Success" : "Fail");

/* Print a debug message with a status whether it was sucessful without its origin. */
#define ndbgstatus(s, ...) _sprintf(__VA_ARGS__);	\
	_sprintf(": %s\n", s ? "Success" : "Fail");
#else
#define dbgmsg(...)			{ }
#define ndbgmsg(...)		{ }
#define dbgstatus(s, ...)	{ }
#define ndbgstatus(s, ...)	{ }
#endif

/// <summary>
/// Initialize the debug library.
/// </summary>
void dbginit();

/// <summary>
/// Print a message with a critical section.
/// </summary>
/// <param name="fmt">Format of the string.</param>
void _sprintf(const char* fmt, ...);

/// <summary>
/// Print a debug message.
/// </summary>
/// <param name="function">Function that requested debug.</param>
/// <param name="line">Line that requested debug.</param>
/// <param name="fmt">Format of the string.</param>
void _sdprintf(const char* function, const unsigned long line, const char* fmt, ...);

/// <summary>
/// Free the debug library.
/// </summary>
void dbgend();