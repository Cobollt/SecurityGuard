namespace SecurityGuard.Core.Models;

public sealed record WindowsSystemProcessTrustResult(
    bool IsTrusted,
    string Reason);