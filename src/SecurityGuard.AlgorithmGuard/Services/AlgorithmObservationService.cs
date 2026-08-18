using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmObservationService
{
    private readonly IFileHashService _hashService;
    private readonly IProtectedObjectRepository _protectedObjectRepository;
    private readonly IAuditService _auditService;

    public AlgorithmObservationService(
        IFileHashService hashService,
        IProtectedObjectRepository protectedObjectRepository,
        IAuditService auditService)
    {
        _hashService = hashService;
        _protectedObjectRepository =
            protectedObjectRepository;

        _auditService = auditService;
    }

    public async Task HandleAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken = default)
    {
        var finalAttempt =
            attempt;

        if (!string.IsNullOrWhiteSpace(
                attempt.ScriptPath) &&
            Path.IsPathRooted(
                attempt.ScriptPath) &&
            File.Exists(
                attempt.ScriptPath))
        {
            var hash =
                await _hashService.ComputeSha256Async(
                    attempt.ScriptPath,
                    cancellationToken);

            finalAttempt =
                attempt with
                {
                    ScriptSha256 = hash
                };

            var file =
                new FileInfo(
                    attempt.ScriptPath);

            var now =
                DateTimeOffset.UtcNow;

            var protectedObject =
                new ProtectedObject(
                    Guid.NewGuid(),
                    file.FullName,
                    file.Name,
                    file.Extension,
                    hash,
                    file.Length,
                    ObjectTrustStatus.Unknown,
                    now,
                    now);

            await _protectedObjectRepository.UpsertAsync(
                protectedObject,
                cancellationToken);
        }

        await _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.AlgorithmExecution,
            SecuritySeverity.Info,
            "Algorithm execution detected",
            BuildDetails(finalAttempt),
            SecurityAction.None,
            cancellationToken: cancellationToken);
    }

    private static string BuildDetails(
        AlgorithmExecutionAttempt attempt)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"PID: {attempt.ProcessId}",
                $"Parent PID: {attempt.ParentProcessId?.ToString() ?? "Unknown"}",
                $"Process: {attempt.ProcessName}",
                $"Executable: {attempt.ExecutablePath ?? "Unknown"}",
                $"Interpreter: {attempt.Interpreter}",
                $"Invocation: {attempt.InvocationType}",
                $"Script: {attempt.ScriptPath ?? "None"}",
                $"SHA256: {attempt.ScriptSha256 ?? "Unknown"}",
                $"CommandLine: {attempt.CommandLine ?? "Unknown"}"
            });
    }
}