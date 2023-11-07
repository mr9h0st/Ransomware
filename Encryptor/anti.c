#include "anti.h"
#include "debug.h"
#include "antidbg.h"
#include "antivm.h"
#include "antidump.h"

BOOL skipExecution()
{
#ifdef DEBUG
	return FALSE;
#else
	if (beingDebugged() || runningOnVM())
		return FALSE;
	
	antiDump();
	return TRUE;
#endif
}