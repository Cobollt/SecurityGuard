namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record ProcessMetadata(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string? ExecutablePath,
    string? CommandLine);