using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Hashing;
using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmDecisionHandlerTests
{
    [Fact]
    public async Task Allow_creates_hash_rule_for_script()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.AlgorithmGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(root);

        try
        {
            var databasePath =
                Path.Combine(
                    root,
                    "test.db");

            var factory =
                new SqliteConnectionFactory(
                    new StorageOptions(
                        databasePath));

            await new DatabaseInitializer(
                factory).InitializeAsync();

            var ruleRepository =
                new SqliteRuleRepository(
                    factory);

            var script =
                Path.Combine(
                    root,
                    "test.ps1");

            await File.WriteAllTextAsync(
                script,
                "Write-Host test");

            var hashService =
                new Sha256FileHashService();

            var handler =
                new AlgorithmDecisionHandler(
                    hashService,
                    ruleRepository,
                    new FakeQuarantineService(),
                    new AlgorithmTemporaryDecisionStore());

            var request =
                new SecurityDecisionRequest(
                    Guid.NewGuid(),
                    SecurityModuleKind.AlgorithmGuard,
                    SecurityEventType.AlgorithmExecution,
                    "Unknown",
                    $"powershell.exe -File \"{script}\"",
                    script,
                    "powershell.exe",
                    [
                        SecurityAction.Allow
                    ],
                    DateTimeOffset.UtcNow);

            await handler.HandleAsync(
                request,
                new SecurityDecision(
                    request.Id,
                    SecurityAction.Allow,
                    true,
                    DateTimeOffset.UtcNow));

            var rules =
                await ruleRepository.GetEnabledAsync();

            var rule =
                Assert.Single(rules);

            Assert.Equal(
                RuleScope.FileHash,
                rule.Scope);

            Assert.Equal(
                RuleDecision.Allow,
                rule.Decision);

            Assert.Equal(
                64,
                rule.Value.Length);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    private sealed class FakeQuarantineService
        : SecurityGuard.Core.Contracts.IQuarantineService
    {
        public Task<QuarantineRecord> QuarantineAsync(
            string filePath,
            SecurityModuleKind sourceModule,
            string reason,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<string> RestoreAsync(
            Guid quarantineId,
            string? destinationPath = null,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task DeleteAsync(
            Guid quarantineId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}