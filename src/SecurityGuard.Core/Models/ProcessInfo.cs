namespace SecurityGuard.Core.Models;

public sealed record ProcessInfo(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string ExecutablePath,
    string? CommandLine,
    string? UserName,
    string? Publisher);