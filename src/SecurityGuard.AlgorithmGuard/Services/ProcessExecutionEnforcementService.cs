using System.Collections.Concurrent;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class ProcessExecutionEnforcementService
    : IAlgorithmEnforcementService,
      IAlgorithmRuntimeEnforcer
{
    private readonly IFileHashService _hashService;

    private readonly IProcessTerminationService _processTerminationService;

    private readonly ConcurrentDictionary<Guid, ManagedRule> _rules =
        new();

    public ProcessExecutionEnforcementService(
        IFileHashService hashService,
        IProcessTerminationService processTerminationService)
    {
        _hashService =
            hashService;

        _processTerminationService =
            processTerminationService;
    }

    public AlgorithmEnforcementLevel GetLevel(
        string? filePath)
    {
        return AlgorithmEnforcementClassifier.GetLevel(
            filePath);
    }

    public async Task<AlgorithmEnforcementResult> AddBlockAsync(
        Guid securityRuleId,
        string filePath,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            expectedSha256);

        var fullPath =
            Path.GetFullPath(
                filePath);

        if (!File.Exists(
                fullPath))
        {
            throw new FileNotFoundException(
                "Script file was not found.",
                fullPath);
        }

        var level =
            GetLevel(
                fullPath);

        if (level ==
            AlgorithmEnforcementLevel.Unsupported)
        {
            return new AlgorithmEnforcementResult(
                false,
                level,
                "This script type cannot currently be enforced by the process fallback.");
        }

        var currentHash =
            await _hashService.ComputeSha256Async(
                fullPath,
                cancellationToken);

        var normalizedExpectedHash =
            NormalizeHash(
                expectedSha256);

        var normalizedCurrentHash =
            NormalizeHash(
                currentHash);

        if (!string.Equals(
                normalizedExpectedHash,
                normalizedCurrentHash,
                StringComparison.OrdinalIgnoreCase))
        {
            return new AlgorithmEnforcementResult(
                false,
                level,
                "Script hash no longer matches the persisted block rule.");
        }

        _rules[securityRuleId] =
            new ManagedRule(
                fullPath,
                normalizedExpectedHash);

        return new AlgorithmEnforcementResult(
            true,
            level,
            "Process runtime fallback rule registered.");
    }

    public Task RemoveBlockAsync(
        Guid securityRuleId,
        CancellationToken cancellationToken = default)
    {
        _rules.TryRemove(
            securityRuleId,
            out _);

        return Task.CompletedTask;
    }

    public Task<AlgorithmEnforcementSnapshot> InspectAsync(
        CancellationToken cancellationToken = default)
    {
        var local =
            _rules.Keys.ToHashSet();

        var effective =
            _rules.Keys.ToHashSet();

        return Task.FromResult(
            new AlgorithmEnforcementSnapshot(
                local,
                effective,
                false,
                false));
    }

    public bool ContainsHash(
        string? hash)
    {
        if (string.IsNullOrWhiteSpace(
                hash))
        {
            return false;
        }

        var normalized =
            NormalizeHash(
                hash);

        return _rules.Values.Any(
            rule =>
                string.Equals(
                    rule.Sha256,
                    normalized,
                    StringComparison.OrdinalIgnoreCase));
    }

    public async Task<AlgorithmRuntimeEnforcementResult> EnforceAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken = default)
    {

        ArgumentNullException.ThrowIfNull(
            attempt);

        if (string.IsNullOrWhiteSpace(
                attempt.ScriptSha256))
        {
            return new AlgorithmRuntimeEnforcementResult(
                false,
                false,
                "The execution has no script hash.");
        }

        if (!ContainsHash(
                attempt.ScriptSha256))
        {
            return new AlgorithmRuntimeEnforcementResult(
                false,
                false,
                "No runtime block rule matches this script.");
        }

        var result =
            await _processTerminationService.TerminateAsync(
                attempt.ProcessId,
                attempt.ProcessName,
                cancellationToken);

        return new AlgorithmRuntimeEnforcementResult(
            true,
            result.Terminated,
            result.Message);
    }

    private static string NormalizeHash(
        string hash)
    {
        return hash
            .Trim()
            .ToUpperInvariant();
    }

    private sealed record ManagedRule(
        string FilePath,
        string Sha256);
}