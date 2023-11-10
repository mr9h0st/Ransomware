#pragma once

#include <Windows.h>
#include <ShlObj.h>
#include <other/memory.h>

/// <summary>
/// Safe strcpy.
/// </summary>
/// <param name="a">Array to copy the data to.</param>
/// <param name="s">Size of the array.</param>
/// <param name="b">Array to copy from.</param>
inline void sstrcpy(char* a, const size_t s, const char* b)
{
	for (size_t i = 0; i < s; i++)
		a[i] = b[i];
}

/// <summary>
/// Check if a value is in an array.
/// </summary>
/// <param name="item">Value to check if it's in the array.</param>
/// <param name="arr">Array.</param>
/// <param name="size">Size of the array.</param>
/// <returns>TRUE if the value is in the array, FALSE, otherwise</returns>
inline BOOL valueInArray(const wchar_t* item, const wchar_t* arr[], const size_t size)
{
	for (size_t i = 0; i < size; i++)
	{
		if (lstrcmpW(item, arr[i]) == 0)
			return TRUE;
	}
	
	return FALSE;
}

/// <summary>
/// Check if a value is in an array case insensitive.
/// </summary>
/// <param name="item">Value to check if it's in the array.</param>
/// <param name="arr">Array.</param>
/// <param name="size">Size of the array.</param>
/// <returns>TRUE if the value is in the array, FALSE, otherwise</returns>
inline BOOL valueInArrayI(const wchar_t* item, const wchar_t* arr[], const size_t size)
{
	for (size_t i = 0; i < size; i++)
	{
		if (lstrcmpiW(item, arr[i]) == 0)
			return TRUE;
	}

	return FALSE;
}

/// <summary>
/// Get an extension from a path of a file.
/// </summary>
/// <param name="path">Path of a file.</param>
/// <returns>Extension of the file.</returns>
inline wchar_t* getExtension(const wchar_t* path)
{
	size_t i = 0;
	wchar_t* p = NULL;

	while (path[i])
	{
		if (path[i] == L'.')
			p = path + i;

		i++;
	}

	return p;
}

/// <summary>
/// Get the file name from it's path.
/// </summary>
/// <param name="path">Path of the file.</param>
/// <returns>Name of the file.</returns>
inline wchar_t* getFileName(const wchar_t* path)
{
	size_t i = 0;
	wchar_t* p = path;
	
	while (path[i])
	{
		if (path[i] == L'\\')
			p = path + i + 1;
		
		i++;
	}
	
	return p;
}

/// <summary>
/// Get a special directory path.
/// </summary>
/// <returns>directory path, NULL if failed.</returns>
inline wchar_t* getSpecialDirectory(const KNOWNFOLDERID *fid)
{
	wchar_t* path = NULL;
	HRESULT result = SHGetKnownFolderPath(fid, 0, NULL, &path);
	if (result == S_OK && path)
	{
		wchar_t* mpath = (wchar_t*)smalloc(MAX_PATH, sizeof(wchar_t));
		lstrcpyW(mpath, path);

		CoTaskMemFree(path);
		return mpath;
	}

	return NULL;
}