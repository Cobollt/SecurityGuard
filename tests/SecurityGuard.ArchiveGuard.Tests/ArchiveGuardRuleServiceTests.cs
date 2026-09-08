using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardRuleServiceTests
{
    [Fact]
    public async Task Matching_allow_rule_suppresses_decision()
    {
        var service =
            new ArchiveGuardRuleService(
                new AllowRuleEngine());

        var result =
            new ArchiveGuardScanResult(
                Guid.NewGuid(),
                @"C:\Test\sample.exe",
                new string(
                    'A',
                    64),
                100,
                ScanVerdict.Malicious,
                [],
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                DetectedFileType.Pe);

        Assert.True(
            await service.IsAllowedAsync(
                result));
    }

    private sealed class AllowRuleEngine
        : IRuleEngine
    {
        public Task<RuleEvaluationResult> EvaluateAsync(
            SecurityModuleKind module,
            RuleMatchContext context,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new RuleEvaluationResult(
                    true,
                    RuleDecision.Allow,
                    Guid.NewGuid()));
        }
    }
}