#pragma once

#include "wsinternal.h"
#include "util.h"

/// <summary>
/// Attempt to check if being debugged.
/// </summary>
/// <returns>True if detected a debugger, FALSE, otherwise.</returns>
BOOL beingDebugged()
{
	// Regular debugger
	if (IsDebuggerPresent())
		return TRUE;
	
	FPEB* peb = getPeb();
	if (peb && peb->BeingDebugged)
		return TRUE;
	
	// Remote debugger
	BOOL beingDebugged = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &beingDebugged) && beingDebugged)
		return TRUE;

	// Hardware breakpoints
	PCONTEXT ctx = (PCONTEXT)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	if (ctx)
	{
		SecureZeroMemory(ctx, sizeof(CONTEXT));
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (GetThreadContext(GetCurrentThread(), ctx))
		{
			if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
			{
				VirtualFree(ctx, 0, MEM_RELEASE);
				return TRUE;
			}
		}

		VirtualFree(ctx, 0, MEM_RELEASE);
	}
	
	return FALSE;
}