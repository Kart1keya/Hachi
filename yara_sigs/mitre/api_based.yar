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