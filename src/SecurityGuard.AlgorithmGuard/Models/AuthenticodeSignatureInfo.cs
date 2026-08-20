namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AuthenticodeSignatureInfo(
    string FilePath,
    bool IsSigned,
    bool IsValid,
    string Status,
    string? Publisher,
    string? Thumbprint);