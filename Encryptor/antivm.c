#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "powrprof.lib")

#include "antivm.h"
#include "util.h"
#include <other/memory.h>
#include <other/utility.h>
#include <intrin.h>
#include <WbemCli.h>
#include <WbemIdl.h>
#include <powerbase.h>
#include <TlHelp32.h>

static const wchar_t* g_KNOWN_DLLS[] = { L"avghookx.dll", L"avghooka.dll",
	L"snxhk.dll", L"sbiedll.dll", L"dbghelp.dll", L"api_log.dll", L"dir_watch.dll",
	L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll", L"cmdvrt64.dll", L"cmdvrt32.dll" };
static const wchar_t* g_KNOWN_PROC_FILES[] = { L"sample.exe", L"bot.exe", L"sandbox.exe",
	L"malware.exe", L"test.exe", L"klavme.exe", L"myapp.exe", L"testapp.exe" };
static const wchar_t* g_KNOWN_USERNAMES[] = { L"CurrentUser", L"Sandbox", L"Emily",
	L"HAPUBWS", L"Hong Lee", L"IT-ADMIN", L"Johnson", L"Miller", L"milozs",
	L"Peter Wilson", L"timmy", L"user", L"sand box", L"malware", L"maltest", L"test user",
	L"virus", L"John Doe", L"Wilber" };
static const wchar_t* g_KNOWN_HOSTNAMES[] = { L"SANDBOX", L"7SILVIA", L"HANSPETER-PC",
	L"JOHN-PC", L"MUELLER-PC", L"WIN7-TRAPS", L"FORTINET", L"TEQUILABOOMBOOM" };
static const wchar_t* g_KNOWN_FILES[] = {
	// VirtualBox
	L"System32\\drivers\\VBoxMouse.sys",
	L"System32\\drivers\\VBoxGuest.sys",
	L"System32\\drivers\\VBoxSF.sys",
	L"System32\\drivers\\VBoxVideo.sys",
	L"System32\\vboxdisp.dll",
	L"System32\\vboxhook.dll",
	L"System32\\vboxmrxnp.dll",
	L"System32\\vboxogl.dll",
	L"System32\\vboxoglarrayspu.dll",
	L"System32\\vboxoglcrutil.dll",
	L"System32\\vboxoglerrorspu.dll",
	L"System32\\vboxoglfeedbackspu.dll",
	L"System32\\vboxoglpackspu.dll",
	L"System32\\vboxoglpassthroughspu.dll",
	L"System32\\vboxservice.exe",
	L"System32\\vboxtray.exe",
	L"System32\\VBoxControl.exe",

	// VMWare
	L"System32\\drivers\\vmnet.sys",
	L"System32\\drivers\\vmmouse.sys",
	L"System32\\drivers\\vmusb.sys",
	L"System32\\drivers\\vm3dmp.sys",
	L"System32\\drivers\\vmci.sys",
	L"System32\\drivers\\vmhgfs.sys",
	L"System32\\drivers\\vmmemctl.sys",
	L"System32\\drivers\\vmx86.sys",
	L"System32\\drivers\\vmrawdsk.sys",
	L"System32\\drivers\\vmusbmouse.sys",
	L"System32\\drivers\\vmkdb.sys",
	L"System32\\drivers\\vmnetuserif.sys",
	L"System32\\drivers\\vmnetadapter.sys",

	// KVM
	L"System32\\drivers\\balloon.sys",
	L"System32\\drivers\\netkvm.sys",
	L"System32\\drivers\\pvpanic.sys",
	L"System32\\drivers\\viofs.sys",
	L"System32\\drivers\\viogpudo.sys",
	L"System32\\drivers\\vioinput.sys",
	L"System32\\drivers\\viorng.sys",
	L"System32\\drivers\\vioscsi.sys",
	L"System32\\drivers\\vioser.sys",
	L"System32\\drivers\\viostor.sys"
};
static const wchar_t* g_KNOWN_REGISTRIES_USER[] = {
	// Wine
	L"SOFTWARE\\Wine",
};
static const wchar_t* g_KNOWN_REGISTRIES_MACHINE[] = { 
	// VirtualPC
	L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
	
	// VirtualBox
	L"HARDWARE\\ACPI\\DSDT\\VBOX__",
	L"HARDWARE\\ACPI\\FADT\\VBOX__",
	L"HARDWARE\\ACPI\\RSDT\\VBOX__",
	L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
	L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
	L"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
	L"SYSTEM\\ControlSet001\\Services\\VBoxService",
	L"SYSTEM\\ControlSet001\\Services\\VBoxSF",
	L"SYSTEM\\ControlSet001\\Services\\VBoxVideo",

	// VMWare
	L"SOFTWARE\\VMware, Inc.\\VMware Tools",

	// KVM
	L"SYSTEM\\ControlSet001\\Services\\vioscsi",
	L"SYSTEM\\ControlSet001\\Services\\viostor",
	L"SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service",
	L"SYSTEM\\ControlSet001\\Services\\VirtioSerial",
	L"SYSTEM\\ControlSet001\\Services\\BALLOON",
	L"SYSTEM\\ControlSet001\\Services\\BalloonService",
	L"SYSTEM\\ControlSet001\\Services\\netkvm"
};
static const wchar_t* g_KNOWN_PROCESSES[] = {
	// Xen
	L"xenservice.exe",

	// VirtualPC
	L"VMSrvc.exe",
	L"VMUSrvc.exe",

	// VirtualBox
	L"vboxservice.exe",
	L"vboxtray.exe",

	// VMWare
	L"vmtoolsd.exe",
	L"vmwaretray.exe",
	L"vmwareuser.exe",
	L"VGAuthService.exe",
	L"vmacthlp.exe",

	// QEMU
	L"qemu-ga.exe",
	L"vdagent.exe",
	L"vdservice.exe",

	// Parallels
	L"prl_cc.exe",
	L"prl_tools.exe"

	// Analysis
	L"ollydbg.exe",
	L"ProcessHacker.exe",
	L"tcpview.exe",
	L"autoruns.exe",
	L"autorunsc.exe",
	L"filemon.exe",
	L"procmon.exe",
	L"regmon.exe",
	L"procexp.exe",
	L"idaq.exe",
	L"idaq64.exe",
	L"ImmunityDebugger.exe",
	L"Wireshark.exe",
	L"dumpcap.exe",
	L"HookExplorer.exe",
	L"ImportREC.exe",
	L"PETools.exe",
	L"LordPE.exe",
	L"SysInspector.exe",
	L"proc_analyzer.exe",
	L"sysAnalyzer.exe",
	L"sniff_hit.exe",
	L"windbg.exe",
	L"joeboxcontrol.exe",
	L"joeboxserver.exe",
	L"joeboxserver.exe",
	L"ResourceHacker.exe",
	L"x32dbg.exe",
	L"x64dbg.exe",
	L"Fiddler.exe",
	L"httpdebugger.exe",
	L"cheatengine-i386.exe",
	L"cheatengine-x86_64.exe",
	L"cheatengine-x86_64-SSE4-AVX2.exe"
};
static const wchar_t* g_KNOWN_SERVICES[] = { L"VBoxWddm", L"VBoxSF",
	L"VBoxMouse", L"VBoxGuest", L"vmci", L"vmhgfs", L"vmmouse", L"vmmemctl",
	L"vmusb", L"vmusbmouse", L"vmx_svga", L"vmxnet", L"vmx86" };

static BOOL checkUserInput()
{
	ULONGLONG correctIdleTimeCounter = 0, currentTickCount = 0, idleTime = 0;
	LASTINPUTINFO lastInputInfo = { 0 };
	lastInputInfo.cbSize = sizeof(LASTINPUTINFO);
	
	for (size_t i = 0; i < 128; i++)
	{
		Sleep(0xb);
		if (GetLastInputInfo(&lastInputInfo))
		{
			currentTickCount = GetTickCount64();
			if (currentTickCount < lastInputInfo.dwTime)
				return TRUE;

			if (currentTickCount - lastInputInfo.dwTime < 100)
			{
				correctIdleTimeCounter++;
				if (correctIdleTimeCounter >= 10)
					return FALSE;
			}
		}
		else
			return TRUE;
	}

	return TRUE;
}

static BOOL acceleratedSleep()
{
	const ULONGLONG dwMillisecondsToSleep = 60 * 1000;
	
	ULONGLONG dwStart = GetTickCount64();
	Sleep(dwMillisecondsToSleep);
	ULONGLONG dwEnd = GetTickCount64();
	
	ULONGLONG dwDiff = dwEnd - dwStart;
	return dwDiff <= dwMillisecondsToSleep - 1000;
}

static BOOL getFanInfo()
{
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject* pclsObj = NULL;

	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
		return TRUE;

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities
		NULL);
	if (FAILED(hres))
	{
		CoUninitialize();
		return TRUE;
	}

	hres = CoCreateInstance(
		&CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		&IID_IWbemLocator,
		(LPVOID*)&pLoc);
	if (FAILED(hres))
	{
		CoUninitialize();
		return TRUE;
	}

	hres = pLoc->lpVtbl->ConnectServer(pLoc,
		L"ROOT\\CIMV2",
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc);
	if (FAILED(hres))
	{
		pLoc->lpVtbl->Release(pLoc);
		CoUninitialize();

		return TRUE;
	}
	hres = pSvc->lpVtbl->ExecQuery(pSvc,
		L"WQL",
		L"SELECT * FROM Win32_Fan",
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		pSvc->lpVtbl->Release(pSvc);
		pLoc->lpVtbl->Release(pLoc);
		CoUninitialize();

		return TRUE;
	}

	ULONG uReturn = 0, count = 0;
	while (pEnumerator)
	{
		hres = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (!uReturn)
			break;

		count++;
		pclsObj->lpVtbl->Release(pclsObj);
	}

	pSvc->lpVtbl->Release(pSvc);
	pLoc->lpVtbl->Release(pLoc);
	pEnumerator->lpVtbl->Release(pEnumerator);
	CoUninitialize();

	return count > 0;
}

BOOL runningOnVM()
{
	// Mouse movement
	static const UINT MOUSE_WAIT = 10;
	POINT p1 = { 0 }, p2 = { 0 };
	GetCursorPos(&p1);
	Sleep(MOUSE_WAIT * 1000);
	GetCursorPos(&p2);
	if (p1.x == p2.x && p1.y == p2.y)
		return TRUE;

	// User input
	if (checkUserInput())
		return TRUE;
	
	// Accelerated sleep
	if (acceleratedSleep())
		return TRUE;

	// Data about CPU fans
	if (!getFanInfo())
		return TRUE;
	
	// Loaded dlls
	for (UINT i = 0; i < _countof(g_KNOWN_DLLS); i++)
	{
		if (GetModuleHandleW(g_KNOWN_DLLS[i]))
			return TRUE;
	}

	// Current file name
	FPEB* peb = getPeb();
	if (peb && peb->ProcessParameters->ImagePathName.Buffer)
	{
		wchar_t* fileName = getFileName(peb->ProcessParameters->ImagePathName.Buffer);
		if (fileName && valueInArrayI(fileName, g_KNOWN_PROC_FILES, _countof(g_KNOWN_PROC_FILES)))
			return TRUE;
	}

	// Usernames
	wchar_t* username = getUsername();
	if (!username)
		return TRUE;
	if (valueInArrayI(username, g_KNOWN_USERNAMES, _countof(g_KNOWN_USERNAMES)))
	{
		sfree(username);
		return TRUE;
	}
	sfree(username);

	// Hostnames
	wchar_t* dnsHostname = getDnsHostname();
	if (!dnsHostname)
		return TRUE;
	if (valueInArrayI(dnsHostname, g_KNOWN_HOSTNAMES, _countof(g_KNOWN_HOSTNAMES)))
	{
		sfree(dnsHostname);
		return TRUE;
	}
	sfree(dnsHostname);

	wchar_t* netbiosHostname = getNetbiosHostname();
	if (!netbiosHostname)
		return TRUE;
	if (valueInArrayI(netbiosHostname, g_KNOWN_HOSTNAMES, _countof(g_KNOWN_HOSTNAMES)))
	{
		sfree(netbiosHostname);
		return TRUE;
	}
	sfree(netbiosHostname);

	// Number of cores
	if (getSystemInfo().dwNumberOfProcessors == 1)
		return TRUE;

	// RAM size
	MEMORYSTATUSEX mem = { 0 };
	mem.dwLength = sizeof(mem);
	if (GlobalMemoryStatusEx(&mem))
	{
		if (mem.ullTotalPhys / GB <= 4)		//  Less then 4GB
			return TRUE;
	}

	// Disk size
	ULARGE_INTEGER totalNumberOfBytes;
	if (GetDiskFreeSpaceExW(NULL, NULL, &totalNumberOfBytes, NULL))
	{
		if (totalNumberOfBytes.QuadPart < (80 * GB))
			return TRUE;
	}

	// Known vendor ID's
	int reg[4];
	__cpuid(reg, 0);

	char vendor[13];
	memcpy(vendor, &reg[1], 4);
	memcpy(vendor + 4, &reg[3], 4);
	memcpy(vendor + 8, &reg[2], 4);
	vendor[12] = '\0';
	
	static const char* BLACKLISTED_VENDORS[] = { "Microsoft Hv", "KVMKVMKVM", "prl hyperv", "VBoxVBoxVBox", "VMwareVMware", "XenVMMXenVMM" };
	for (DWORD i = 0; i < _countof(BLACKLISTED_VENDORS); i++)
	{
		if (strstr(vendor, BLACKLISTED_VENDORS[i]))
			return TRUE;
	}

	// Power capabilities
	SYSTEM_POWER_CAPABILITIES powerCaps = { 0 };
	if (GetPwrCapabilities(&powerCaps))
	{
		if ((powerCaps.SystemS1 | powerCaps.SystemS2 | powerCaps.SystemS3 | powerCaps.SystemS4) == FALSE)
		{
			if (!powerCaps.ThermalControl)
				return TRUE;
		}
	}
	
	// Existing files
	for (DWORD i = 0; i < _countof(g_KNOWN_FILES); i++)
	{
		DWORD dwAttrib = GetFileAttributesW(g_KNOWN_FILES[i]);
		if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
			return TRUE;
	}
	
	// Existing registries
	for (DWORD i = 0; i < _countof(g_KNOWN_REGISTRIES_USER); i++)
	{
		if (registryExists(HKEY_CURRENT_USER, g_KNOWN_REGISTRIES_USER[i]))
			return TRUE;
	}
	for (DWORD i = 0; i < _countof(g_KNOWN_REGISTRIES_MACHINE); i++)
	{
		if (registryExists(HKEY_LOCAL_MACHINE, g_KNOWN_REGISTRIES_MACHINE[i]))
			return TRUE;
	}

	// Running processes
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32FirstW(hProcessSnap, &pe32))
		{
			if (valueInArrayI(pe32.szExeFile, g_KNOWN_PROCESSES, _countof(g_KNOWN_PROCESSES)))
			{
				CloseHandle(hProcessSnap);
				return TRUE;
			}
			
			while (Process32NextW(hProcessSnap, &pe32))
			{
				if (valueInArrayI(pe32.szExeFile, g_KNOWN_PROCESSES, _countof(g_KNOWN_PROCESSES)))
				{
					CloseHandle(hProcessSnap);
					return TRUE;
				}
			}
		}
		
		CloseHandle(hProcessSnap);
	}
	
	// Running services
	SC_HANDLE hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCM)
	{
		DWORD dwBytesNeeded, dwServicesReturned;
		ENUM_SERVICE_STATUS_PROCESS* serviceInfo = NULL;
		EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
			SERVICE_ACTIVE | SERVICE_INACTIVE, NULL, 0, &dwBytesNeeded, &dwServicesReturned,
			NULL, NULL);
		if (GetLastError() == ERROR_MORE_DATA)
		{
			serviceInfo = (ENUM_SERVICE_STATUS_PROCESS*)smalloc(dwBytesNeeded, sizeof(BYTE));
			if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
				SERVICE_ACTIVE | SERVICE_INACTIVE, (LPBYTE)serviceInfo, dwBytesNeeded,
				&dwBytesNeeded, &dwServicesReturned, NULL, NULL))
			{
				for (DWORD i = 0; i < dwServicesReturned; i++)
				{
					if (valueInArrayI(serviceInfo[i].lpServiceName, g_KNOWN_SERVICES, _countof(g_KNOWN_SERVICES)))
					{
						sfree(serviceInfo);
						CloseServiceHandle(hSCM);
						
						return TRUE;
					}
				}
			}
			
			sfree(serviceInfo);
		}

		CloseServiceHandle(hSCM);
	}
	
	return FALSE;
}