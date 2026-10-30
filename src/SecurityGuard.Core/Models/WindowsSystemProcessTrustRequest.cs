namespace SecurityGuard.Core.Models;

public sealed record WindowsSystemProcessTrustRequest(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath,
    string? Publisher = null,
    string? SignatureStatus = null);