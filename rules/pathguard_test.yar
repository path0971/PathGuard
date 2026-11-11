// Harmless marker used by the PathGuard tests (tests/vm/samples/marked.c).
rule PathGuard_Test_Marker
{
    meta:
        description = "PathGuard test marker string"
        author = "PathGuard"

    strings:
        $marker = "PATHGUARD-TEST-MARKER-7f3a9c"

    condition:
        $marker
}
