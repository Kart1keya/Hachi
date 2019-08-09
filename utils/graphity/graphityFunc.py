#!/usr/bin/env python


funcDict = { 
    #
    'THREAD_CREATE': ['CreateThread'],
    'RTL_THREAD_CREATE': ['RtlCreateUserThread'],
    'ZW_THREAD_CREATE': ['ZwCreateThread'],

    'PROCESS_ENUM': ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next'],
    'MODULE_ENUM': ['CreateToolhelp32Snapshot', 'Module32First', 'Module32Next'],
    'PROCESS_ENUM_1': ['EnumProcesses'],
    'MODULE_ENUM_1': ['EnumProcessModules'],

    'WIN_EXEC': ['WinExec'],
    'SHELL_EXEC': ['ShellExecute'],
    'PROCESS_CREATE': ['CreateProcess'],
    'PROCESS_CREATE_INTR': ['CreateProcessInternal'],
    'PROCESS_CREATE_USER': ['CreateProcessAsUser'],
    'PROCESS_CREATE_LOGON': ['CreateProcessWithLogon'],
    'PROCESS_CREATE_1': ['system'],
    'PROCESS_CREATE_2': ['ZwCreateProcess'],

    'PROCESS_TERM': ['TerminateProcess'],
    'PROCESS_SUSPEND_': ['ZwSuspendProcess'],
    'PROCESS_TERM_1': ['ZwTerminateProcess'],

    'REMOTE_THREAD_INJECTION': ['CreateThread', 'WriteProcessMemory','ResumeThread'],
    'REMOTE_THREAD_1': ['CreateRemoteThread'],
    'RETRO_INJECTION': ['GetCurrentProcess', 'CreatePipe', 'DuplicateHandle'],
    'MEMORY_WRITE': ['WriteProcessMemory'],
    'MEMORY_READ': ['ReadProcessMemory'],
    'MEMORY_READ_1': ['Toolhelp32ReadProcessMemory'],
    'MEMORY_READ_2': ['ZwReadVirtualMemory'],

    'EXIT_SYSTEM': ['ExitWindows'],
    'EXIT_SYSTEM_1': ['InitiateSystemShutdown'],

    'ANTI-SANDBOX_1': ['GetForegroundWindow', 'Sleep'],
    'ANTI-SANDBOX_2': ['GetCursorPos', 'Sleep'],
    'ANTI-SANDBOX_3': ['GetLastInputInfo', 'Sleep'],
    'ANTI-SANDBOX_4': ['GetTickCount', 'Sleep'],

    'WINHOOK': ['SetWindowsHook'],

    'TIME_ZONE': ['GetTimeZoneInformation'],
    'USER': ['LogonUser'],
    'USER_IMPERSONATE': ['ImpersonateLoggedOnUser'],

    # Autostarts & infiltration
    'REG_SETVAL': ['RegOpenKey', 'RegSetValue'],
    'REG_QUERY': ['RegOpenKey', 'RegQueryValue'],

    'CREATE_SERVICE': ['OpenSCManager', 'CreateService'],  # 'OpenService', 'StartService'],
    'CREATE_START_SERVICE': ['OpenSCManager', 'CreateService'],

    #'RES_DROPPER_1': ['FindResource', 'LoadResource', 'CreateFile', 'WriteFile'],
    'RES_DROPPER': ['FindResource', 'LoadResource'],  # 'LockResource', 'SizeofResource'],
    'LOAD_RES': ['LoadResource'],
    'UPDATE_RESOURCE': ['BeginUpdateResource', 'UpdateResource', 'EndUpdateResource'],

    # Dynamic API loading
    'APILOADING': ['GetProcAddress'],
    #'APILOADING2': ['GetModuleHandle', 'GetProcAddress'],

    # File interaction
    'WRITE_FILE': ['CreateFile', 'WriteFile'],
    'FILE_WRITE_1': ['FlushFileBuffers'],
    'FILE_WRITE_2': ['FlushViewOfFile'],
    'FILE_WRITE_3': ['WriteFile'],
    'FILE_WRITE_4': ['fflush'],
    'FILE_WRITE_5': ['fprintf'],
    'FILE_WRITE_6': ['fputs'],
    'FILE_WRITE_7': ['fwrite'],
    'FILE_WRITE_8': ['ZwWriteFile'],

    'READ_FILE': ['CreateFile', 'ReadFile'],

    'TEMP_FILE_WRITE': ['GetTempFileName', 'CreateFile', 'WriteFile'],
    'FPRINT': ['fopen', 'fprintf'],

    'FILE_COPY': ['CopyFile'],
    'FILE_DELETE': ['DeleteFile'],
    'FILE_DELETE_1': ['ZwDeleteFile'],
    'FILE_MOVE': ['MoveFile'],
    'FILE_MOVE_1': ['MoveFileEx'],

    'DIR_DELETE': ['RemoveDirectory'],
    'DIR_SYS': ['GetSystemDirectory'],
    'DIR_SYSWIN': ['GetSystemWindowsDirectory'],
    'DIR_WIN': ['GetWindowsDirectory'],

    # Malware activity
    'DRIVES_ITER_1': ['GetLogicalDriveStrings'],
    'DRIVES_ITER_2': ['GetDriveType'],
    'FILE_ITER': ['FindFirstFile', 'FindNextFile'],
    'WINDOW': ['CreateWindow', 'RegisterClass', 'DispatchMessage'],

    'SCREENSHOT': ['CreateCompatibleDC', 'GetDeviceCaps', 'CreateCompatibleBitmap', 'BitBlt'],

    # encryption and compression
    'CRYPT_ENCRYPT': ['CryptEncrypt'],
    'CRYPT_DECRYPT': ['CryptDecrypt'],
    'CRYPT_HASH': ['CryptCreateHash', 'CryptDestroyHash', 'CryptGetHashParam', 'CryptHashData', 'CryptSetHashParam', 'CheckSumMappedFile'],

    'ENCODE': ['RtlEncodePointer'],
    'DECODE': ['RtlDecodePointer'],
    'COMPRESS': ['RtlCompressBuffer'],
    'DECOMPRESS': ['RtlDecompressBuffer'],

    'VOLUME_ENUM': ['FindFirstVolume', 'FindNextVolume'],

    # Network activity
    'WSASEND': ['gethostbyname', 'send'],
    'LISTEN': ['listen'],
    'RECV': ['recv'],
    'WSARECV': ['WSARecv'],
    'SEND': ['send'],
    'WASSEND' : ['WSASend'],
    'SEND_TO': ['sendto'],
    'WSASEND_TO': ['WSASendTo'],
    'RECV_FROM': ['recvfrom'],
    'WSARECV_FROM': ['WSARecvFrom'],

    'DOWNLOAD_FILE_CACHE': ['URLDownloadToCacheFile'],
    'DOWNLOAD_FILE': ['URLDownloadToFile'],

    'ICMP6_MGMT': ['Icmp6CreateFile', 'Icmp6SendEcho2'],
    'ICMP_MGMT': ['IcmpCreateFile', 'IcmpSendEcho'],
    'ICMP_MGMT_1': ['IcmpCreateFile', 'IcmpSendEcho2'],

    'DOWNLOADER': ['URLDownloadToCacheFile'],
    'DOWNLOADER_1': ['URLDownloadToFile', 'WinExec'],
    'DOWNLOADER_2': ['URLDownloadToFile', 'ShellExecute'],
    'DOWNLOADER_3': ['URLDownloadToFile', 'CreateProcess'],

    'INET_DOWNLOAD': ['InternetOpen', 'InternetReadFile'],
    'INET_UPLOAD': ['InternetOpen', 'InternetWriteFile'],

    'FTP_GET': ['FtpOpenFile', 'FtpGetFile'],
    'FTP_PUT': ['FtpOpenFile', 'FtpPutFile'],

    'CACHE_ENUM': ['FindFirstUrlCacheEntry', 'FindNextUrlCacheEntry'],
    'CACHE_INFO': ['GetUrlCacheEntryInfo'],

    'NET_USER_ADD': ['NetUserAdd'],
    'NET_USER_ENUM': ['NetUserEnum'],
    'NET_SHARE': ['NetShareEnum', 'NetShareAdd'],
    'WNET_SHARE': ['WNetAddConnection2'],

    # Host information
    'HOST_INFO_1': ['gethostbyname'],
    'HOST_INFO_2': ['gethostname'],
    'HOST_INFO_3': ['getnameinfo'],
    'HOST_INFO_4': ['GetNameInfo'],
    'DISK_INFO_1': ['GetDriveType'],
    'DISK_INFO_2': ['GetDiskFreeSpace'],
    'DISK_INFO_3': ['GetLogicalDrives'],
    'DISK_INFO_4': ['GetLogicalDriveStrings'],
    'DISK_INFO_5': ['ZwQueryDirectoryFile'],
    'DISK_INFO_6': ['DriveSpace'],
    'DESKTOP_ENUM': [ 'OpenWindowStation', 'EnumDesktops', 'EnumWindowStations', 'EnumDesktopWindows'],
    'OS_INFO_1': ['GetVersion'],
    'OS_INFO_2': ['GetVersionEx'],
    'OS_INFO_3': ['RtlGetVersion'],
    'SYSTEM_INFO': ['GetSystemInfo'],
    'SYSTEM_INFO_1': ['ZwQuerySystemInformation'],
    'SYSTEM_INFO_2': ['SystemParametersInfo'],
    'SYSTEM_INFO_LOCALE': ['GetLocaleInfo'],

    # misc
    'DRIVER_CTRL': ['DeviceIoControl'],
    'DRIVER_CTRL_1': ['ZwDeviceIoControlFile'],
    'SERVICE_HANDLER': ['RegisterServiceCtrlHandler'],

    'COM_OBJECT': ['CoCreateInstance', 'CoGetClassObject'],
    'COM_OBJECT_1': ['CoInitialize'],
    'LDAP': ['ldap_first_attribute'],
    'LDAP_1': ['ldap_first_entry'],
    'RANDOM_GEN_1': ['rand'],
    'RANDOM_GEN_2': ['srand'],
    'RANDOM_GEN_3': ['RtlRandom'],
    'SLEEP_1': ['Sleep'],
    'SLEEP_2': ['ZwDelayExecution'],

    # multimedia
    'AUDIO_IN': ['waveInOpen', 'waveInStart'],
    'AUDIO_OUT': ['waveOutOpen', 'waveOutWrite'],

    # keyboard
    'KEYBOARD_INFO': ['GetKeyboardLayout'],
    'KEYBOARD_INPUT_1': ['BlockInput'],
    'KEYBOARD_INPUT_2': ['GetAsyncKeyState'],
    'KEYBOARD_INPUT_3': ['GetKeyState'],
    'KEYBOARD_INPUT_4': ['GetRawInputData'],
    'KEYBOARD_INPUT_5': ['RegisterRawInputDevices'],
    'KEYBOARD_INPUT_6': ['SendInput'],
    'KEYBOARD_INPUT_7': ['VkKeyScan'],
    'MOUSE': ['TrackMouseEvent'],
    'MOUSE_1': ['_TrackMouseEvent'],

    # printer
    'PRINTER': ['EnumPrinters', 'OpenPrinter', 'GetDefaultPrinter'],

}

# TODO extend on those, and add more:
# spawn a process
# move file, delete, create dir                                          -
# regenumkey
# createmutex
# fopen, fread, fwrite
# clipboard
# screen capture etc.

