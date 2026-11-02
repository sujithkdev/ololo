/*
 * test_and_eicar.yar
 * Test rules used to verify the YARA engine is working correctly.
 * The EICAR rule fires on the official EICAR antivirus test string —
 * use it to confirm scanning is active without real malware.
 */

rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file — confirms YARA scanning is active"
        author      = "EDR Project"
        date        = "2026-01-01"
        severity    = "LOW"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar
}

rule EDR_Test_Marker {
    meta:
        description = "Synthetic test marker — used by smoke tests to verify YARA pipeline"
        author      = "EDR Project"
        date        = "2026-01-01"
        severity    = "LOW"

    strings:
        $marker = "EDR-YARA-TEST-TRIGGER-DO-NOT-USE-IN-PRODUCTION" ascii

    condition:
        $marker
}
