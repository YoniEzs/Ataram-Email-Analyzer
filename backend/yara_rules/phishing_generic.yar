/*
    Starter YARA rules for the email analyzer.
    Drop additional .yar/.yara files in this directory — they are compiled
    at analyzer startup (YARA_RULES_PATH).
*/

rule CredentialHarvestForm
{
    meta:
        description = "HTML form posting credentials to an external endpoint"
        severity = "high"
    strings:
        $form = "<form" nocase
        $pass = "type=\"password\"" nocase
        $pass2 = "type='password'" nocase
    condition:
        $form and any of ($pass, $pass2)
}
rule Base64EvalJavascript
{
    meta:
        description = "Obfuscated JavaScript decoding + executing payloads"
        severity = "high"
    strings:
        $atob = "atob(" nocase
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $fromcc = "fromCharCode" nocase
    condition:
        ($atob or $unescape or $fromcc) and $eval
}

rule PEExecutableDroppedInMail
{
    meta:
        description = "Windows PE executable content"
        severity = "critical"
    condition:
        uint16(0) == 0x5A4D
}
