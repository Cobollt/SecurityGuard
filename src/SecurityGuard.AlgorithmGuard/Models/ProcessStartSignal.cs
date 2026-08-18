namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record ProcessStartSignal(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    DateTimeOffset DetectedAtUtc);