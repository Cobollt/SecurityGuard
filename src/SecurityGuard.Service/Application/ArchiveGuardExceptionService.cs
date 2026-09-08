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
                    rule.Enabled);

        if (alreadyExists)
        {
            return;
        }

        var now =
            DateTimeOffset.UtcNow;

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                $"ArchiveGuard SHA-256 exception: {fileName}",
                SecurityModuleKind.ArchiveGuard,
                RuleScope.FileHash,
                sha256,
                RuleDecision.Allow,
                Priority,
                true,
                now,
                null);

        await _ruleRepository.UpsertAsync(
            rule,
            cancellationToken);
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