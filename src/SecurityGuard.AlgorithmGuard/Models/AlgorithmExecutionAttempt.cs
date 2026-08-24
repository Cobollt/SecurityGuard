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
    DateTimeOffset DetectedAtUtc,
    string? UserName = null,
    string? ParentProcessName = null,
    string? ParentExecutablePath = null,
    string? ProcessPublisher = null,
    string? ProcessSignatureStatus = null,
    string? ScriptPublisher = null,
    string? ScriptSignatureStatus = null,
    IReadOnlyList<ProcessAncestryEntry>? ExecutionChain = null,
    Guid? CorrelationId = null);