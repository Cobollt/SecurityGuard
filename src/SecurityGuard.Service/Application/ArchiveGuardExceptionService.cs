using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Application;

public sealed class ArchiveGuardExceptionService
    : IArchiveGuardExceptionService
{
    private const int Priority =
        300;

    private readonly IRuleRepository _ruleRepository;
    private readonly SemaphoreSlim _mutationGate = new(1, 1);

    public ArchiveGuardExceptionService(
        IRuleRepository ruleRepository)
    {
        _ruleRepository =
            ruleRepository;
    }

    public async Task AddSha256ExceptionAsync(
        string sha256,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        await ExecuteWithSha256ExceptionAsync(
            sha256, fileName, _ => Task.FromResult(true), cancellationToken);
    }

    public async Task<T> ExecuteWithSha256ExceptionAsync<T>(
        string sha256,
        string fileName,
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await _mutationGate.WaitAsync(cancellationToken);
        try
        {
            var rule = await CreateExceptionRuleAsync(sha256, fileName, cancellationToken);
            try
            {
                if (rule is not null)
                {
                    await _ruleRepository.UpsertAsync(rule, cancellationToken);
                }
                return await operation(cancellationToken);
            }
            catch (Exception operationError)
            {
                if (rule is not null)
                {
                    try
                    {
                        // Cleanup must also run when the caller cancelled restoration.
                        await _ruleRepository.DeleteAsync(rule.Id, CancellationToken.None);
                    }
                    catch (Exception rollbackError)
                    {
                        throw new AggregateException(
                            "Operation failed and its SHA-256 exception could not be removed.",
                            operationError, rollbackError);
                    }
                }
                throw;
            }
        }
        finally
        {
            _mutationGate.Release();
        }
    }

    private async Task<SecurityRule?> CreateExceptionRuleAsync(
        string sha256,
        string fileName,
        CancellationToken cancellationToken)
    {
        sha256 =
            NormalizeSha256(
                sha256);

        fileName =
            string.IsNullOrWhiteSpace(
                fileName)
                ? sha256
                : fileName.Trim();

        var rules =
            await _ruleRepository.GetAllAsync(
                cancellationToken);

        var alreadyExists =
            rules.Any(
                rule =>
                    rule.Module ==
                        SecurityModuleKind.ArchiveGuard &&
                    rule.Decision ==
                        RuleDecision.Allow &&
                    rule.Scope ==
                        RuleScope.FileHash &&
                    string.Equals(
                        rule.Value,
                        sha256,
                        StringComparison.OrdinalIgnoreCase) &&
                    rule.Enabled &&
                    (rule.ExpiresAtUtc is null || rule.ExpiresAtUtc > DateTimeOffset.UtcNow) &&
                    (rule.Conditions is null || rule.Conditions.Count == 0));

        if (alreadyExists)
        {
            return null;
        }

        var now =
            DateTimeOffset.UtcNow;

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                $"ArchiveGuard SHA-256 exception: {fileName}",
                SecurityModuleKind.ArchiveGuard,
                RuleDecision.Allow,
                RuleScope.FileHash,
                sha256,
                true,
                Priority,
                now,
                null);

        return rule;
    }

    private static string NormalizeSha256(
        string sha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            sha256);

        sha256 =
            sha256.Trim()
                .ToUpperInvariant();

        if (sha256.Length !=
                64 ||
            sha256.Any(
                character =>
                    !Uri.IsHexDigit(
                        character)))
        {
            throw new ArgumentException(
                "SHA-256 must contain exactly 64 hexadecimal characters.",
                nameof(sha256));
        }

        return sha256;
    }
}