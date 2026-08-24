namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record ProcessAncestryEntry(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string? ExecutablePath,
    DateTimeOffset? CreatedAtUtc);