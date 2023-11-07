#pragma once

#include "wsinternal.h"

/// <summary>
/// Attempt to check if running on an isolated environment.
/// </summary>
/// <returns>True if detected a VM or debugger, FALSE, otherwise.</returns>
BOOL skipExecution();