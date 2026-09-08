using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardRuleService
    : IArchiveGuardRuleService
{
    private readonly IRuleEngine _ruleEngine;

    public ArchiveGuardRuleService(
        IRuleEngine ruleEngine)
    {
        _ruleEngine =
            ruleEngine;
    }

    public async Task<bool> IsAllowedAsync(
        ArchiveGuardScanResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            result);

        var filePath =
            Path.GetFullPath(
                result.FilePath);

        var context =
            new RuleMatchContext(
                FileHash:
                    result.Sha256,
                FilePath:
                    filePath,
                FileName:
                    Path.GetFileName(
                        filePath),
                FileExtension:
                    Path.GetExtension(
                        filePath));

        var evaluation =
            await _ruleEngine.EvaluateAsync(
                SecurityModuleKind.ArchiveGuard,
                context,
                cancellationToken);

        return evaluation.Matched &&
               evaluation.Decision ==
               RuleDecision.Allow;
    }
}