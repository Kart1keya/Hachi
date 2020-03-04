rule  screeshot_write : T1113
{
    meta:
        description = "Takes Screenshot"
    strings:
        $ie = "SCREENSHOT"
        $ff = "WRITE_FILE"
    condition:
        all of them
}

rule process_enum : T1057
{
    meta:
        description = "Enumerates Process"
    strings:
        $ie = "PROCESS_ENUM"
        $ie1 = "PROCESS_ENUM_1"
    condition:
        any of them
}

rule input_capture : T1056
{
    meta:
        descrition = "Input Capture API calls"

    strings:
        $a1 = "KEYBOARD_INFO"
        $a2 = "KEYBOARD_INPUT_1"
        $a3 = "KEYBOARD_INPUT_2"
        $a4 = "KEYBOARD_INPUT_3"
        $a5 = "KEYBOARD_INPUT_4"
        $a6 = "KEYBOARD_INPUT_5"
        $a7 = "KEYBOARD_INPUT_6"
        $a8 = "KEYBOARD_INPUT_7"
        $a9 = "MOUSE"
        $a10 = "MOUSE_1"

    condition:
        any of them
}

rule audio_capture: T1123
{
    meta:
        description = "Audio Capture API Calls"

    strings:
        $a1 = "AUDIO_IN"
        $a2 = "AUDIO_IN"

    condition:
        any of them
}


rule system_info : T1082 T1033
{
    meta:
        description = "Getting host information"

    strings:
        $a1 = "SYSTEM_INFO"
        $a2 = "SYSTEM_INFO_1"
        $a3 = "SYSTEM_INFO_2"
        $a4 = "SYSTEM_INFO_LOCALE"

    condition:
        any of them
}



rule os_info : T1135 T1033 T1057 T1012
{
    meta:
        description = "Getting os info"

    strings:
        $a1 = "OS_INFO_1"
        $a2 = "OS_INFO_2"
        $a3 = "OS_INFO_3"

    condition:
        any of them
}

rule host_info : T1082 T1033
 {
    meta:
        description = "Getting host information"

    strings:
        $a1 = "HOST_INFO_1"
        $a2 = "HOST_INFO_2"
        $a3 = "HOST_INFO_3"
        $a4 = "HOST_INFO_4"

    condition:
        any of them
}

rule disk_info : T1082 T1033
 {
    meta:
        description= "Getting host information"

    strings:
        $a1 = "DISK_INFO_1"
        $a2 = "DISK_INFO_2"
        $a3 = "DISK_INFO_3"
        $a4 = "DISK_INFO_4"
        $a5 = "DISK_INFO_5"
        $a6 = "DISK_INFO_6"

    condition:
        any of them
 }

rule window_discovery : T1010
 {
    meta:
        description= "Getting host information"

    strings:
	    $a1 = "DESKTOP_ENUM"

	condition:
	    any of them
}

rule user_impersonation: T1134
{
    meta:
        description= "Run Process as"

    strings:
        $a1 = "PROCESS_CREATE_USER"
        $a2 = "PROCESS_CREATE_LOGON"

    condition:
        any of them
}

rule send_recv : T1065 T1041
{
    meta:
        description= "Communication using send and recv"

    strings:
        $a1 = "WSASEND"
        $a2 = "LISTEN"
        $a3 = "RECV"
        $a4 = "WSARECV"
        $a5 = "SEND"
        $a6 = "WASSEND"
        $a7 = "SEND_TO"
        $a8 = "WSASEND_TO"
        $a9 = "RECV_FROM"
        $a10 = "WSARECV_FROM"

    condition:
        any of them
}

rule downloader : T1071 T1105
{
    meta:
        description = "Downloads a file"
    strings:
        $a1 = "DOWNLOAD_FILE_CACHE"
        $a2 = "DOWNLOAD_FILE"

    condition:
        any of them   
}

rule ftp_get_put : T1071 T1105
{
    meta:
        description = "Downloads a file"
    strings:
        $a1 = "FTP_GET"
        $a2 = "FTP_PUT"

    condition:
        any of them
}


rule file_enum : T1083
{
    meta:
        description = "File and drive enumeration"
    strings:
        $a1 = "DRIVES_ITER_1"
        $a2 = "DRIVES_ITER_2"
        $a3 = "FILE_ITER"

    condition:
        any of them
}

rule process_injection : T1055
{
    meta:
        description = "Remode code injection"
    strings:
        $a1 = "REMOTE_THREAD_INJECTION"
        $a2 = "REMOTE_THREAD_1"
        $a3 = "REMOTE_THREAD_INJECTION_1"

    condition:
        any of them

}

rule downloade_from_url : T1071 T1105
{
    meta:
        description = "Remode code injection"
    strings:   
        $a1 = "DOWNLOADER"
        $a2 = "DOWNLOADER_1"
        $a3 = "DOWNLOADER_2"
        $a4 = "DOWNLOADER_3"
    condition:
        any of them
}

rule query_reg : T1012
{
    meta:
        description = "Remode code injection"
    strings:
        $a1 = "REG_QUERY"
    
    condition:
        any of them
}

rule sc_screate : T1035 T1050
{
    meta:
        description = "Start Service"

    strings:
        $a1 = "CREATE_SERVICE"
        $a2 = "START_SERVICE"

    condition:
        any of them
}

rule win_hook : T1179
{
    meta:
        description = "SetWindowsHook"

    strings:
        $a1 = "WINHOOK"

    condition:
        any of them
}

rule time_zone : T1124
{
    meta:
        description = "Get time zone"

    strings:
        $a1 = "TIME_ZONE"

    condition:
        any of them
}

rule logoonuser : T1033 T1087
{
    meta:
        description = "LogonUser"

    strings:
        $a1 = "USER"

    condition:
        any of them
}

rule impersonate_user : T1134
{
    meta:
        description = "LogonUser"

    strings:
        $a1 = "USER_IMPERSONATE"

    condition:
        any of them
}
