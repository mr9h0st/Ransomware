#include <Windows.h>

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
/// Get an extension from a path of a file.
/// </summary>
/// <param name="path">Path of a file.</param>
/// <returns>Extension of the file.</returns>
inline wchar_t* getExtension(wchar_t* path)
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