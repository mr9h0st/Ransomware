#pragma once

#include "wsinternal.h"

#define GB 1000000000Ui64

/// <summary>
/// Attempt to check if running on a VM.
/// </summary>
/// <returns>True if detected a VM, FALSE, otherwise.</returns>
BOOL runningOnVM();