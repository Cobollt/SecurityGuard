namespace SecurityGuard.ArchiveGuard.Enums;

public enum AuthenticodeSignatureStatus
{
    Unsigned = 0,
    Valid = 1,
    Untrusted = 2,
    Revoked = 3,
    Invalid = 4,
    Error = 5,
    Unavailable = 6
}