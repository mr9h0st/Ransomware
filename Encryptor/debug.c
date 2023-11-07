#include "debug.h"
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

static CRITICAL_SECTION g_cs;

void dbginit()
{
	InitializeCriticalSection(&g_cs);
}

void _sprintf(const char* fmt, ...)
{
	EnterCriticalSection(&g_cs);

	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);

	LeaveCriticalSection(&g_cs);
}

void _sdprintf(const char* function, const unsigned long line, const char* fmt, ...)
{
	EnterCriticalSection(&g_cs);

	printf("[%s:%lu]\t", function, line);
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
	
	LeaveCriticalSection(&g_cs);
}

void dbgend()
{
	DeleteCriticalSection(&g_cs);
}