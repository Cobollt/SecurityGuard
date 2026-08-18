using SecurityGuard.AlgorithmGuard.Enums;

namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AlgorithmExecutionAttempt(
    Guid Id,
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string? ExecutablePath,
    string? CommandLine,
    InterpreterKind Interpreter,
    AlgorithmInvocationType InvocationType,
    string? ScriptPath,
    string? ScriptSha256,
    DateTimeOffset DetectedAtUtc);