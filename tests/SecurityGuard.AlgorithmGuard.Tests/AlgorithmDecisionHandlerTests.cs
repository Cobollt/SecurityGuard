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

            var runtime =
                new FakeRuntimeController();

            var handler =
                new AlgorithmDecisionHandler(
                    hashService,
                    ruleRepository,
                    new FakeQuarantineService(),
                    new AlgorithmTemporaryDecisionStore(),
                    new FakeEnforcementService(),
                    new AlgorithmGuardOptions(),
                    runtime);

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
                    DateTimeOffset.UtcNow,
                    new RuleMatchContext(
                        Process:
                            "powershell.exe",
                        ParentProcess:
                            "explorer.exe",
                        ParentProcessPath:
                            @"C:\Windows\explorer.exe",
                        UserName:
                            @"DESKTOP\User",
                        ProcessPublisher:
                            "Microsoft"));

            var rules =
                await ruleRepository.GetEnabledAsync();

            var rule =
                Assert.Single(rules);
                
                Assert.NotNull(
                    rule.Conditions);

                Assert.Contains(
                    rule.Conditions,
                    condition =>
                        condition.Scope ==
                        RuleScope.UserName);

                Assert.Contains(
                    rule.Conditions,
                    condition =>
                        condition.Scope ==
                        RuleScope.ParentProcessPath);

                Assert.Contains(
                    rule.Conditions,
                    condition =>
                        condition.Scope ==
                        RuleScope.ProcessPublisher);

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

    [Fact]
    public async Task Block_applies_enforcement_and_creates_rule()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.AlgorithmGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(root);

        try
        {
            var factory =
                new SqliteConnectionFactory(
                    new StorageOptions(
                        Path.Combine(
                            root,
                            "test.db")));

            await new DatabaseInitializer(
                factory).InitializeAsync();

            var repository =
                new SqliteRuleRepository(
                    factory);

            var script =
                Path.Combine(
                    root,
                    "test.cmd");

            await File.WriteAllTextAsync(
                script,
                "echo test");

            var enforcement =
                new RecordingEnforcementService();

            var runtime =
                new FakeRuntimeController
                {
                    CurrentSettings =
                        new AlgorithmGuardSettings(
                            true,
                            AlgorithmGuardMode.Enforce,
                            EnforcementFailurePolicy.FailClosed)
                };

            var handler =
                new AlgorithmDecisionHandler(
                    hashService,
                    ruleRepository,
                    new FakeQuarantineService(),
                    new AlgorithmTemporaryDecisionStore(),
                    new FakeEnforcementService(),
                    new AlgorithmGuardOptions(),
                    runtime);

            var request =
                new SecurityDecisionRequest(
                    Guid.NewGuid(),
                    SecurityModuleKind.AlgorithmGuard,
                    SecurityEventType.AlgorithmExecution,
                    "Unknown",
                    $"cmd.exe /c \"{script}\"",
                    script,
                    "cmd.exe",
                    [
                        SecurityAction.Block
                    ],
                    DateTimeOffset.UtcNow);

            await handler.HandleAsync(
                request,
                new SecurityDecision(
                    request.Id,
                    SecurityAction.Block,
                    true,
                    DateTimeOffset.UtcNow));

            Assert.True(
                enforcement.WasCalled);

            var rules =
                await repository.GetEnabledAsync();

            var rule =
                Assert.Single(rules);

            Assert.Equal(
                RuleDecision.Block,
                rule.Decision);

            Assert.Equal(
                RuleScope.FileHash,
                rule.Scope);
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

    private sealed class FakeEnforcementService
    : SecurityGuard.AlgorithmGuard.Contracts.IAlgorithmEnforcementService
        {
        public SecurityGuard.AlgorithmGuard.Enums.AlgorithmEnforcementLevel GetLevel(
            string? filePath)
            {
            return SecurityGuard.AlgorithmGuard.Enums.AlgorithmEnforcementLevel.AppLockerBlocked;
            }

        public Task<SecurityGuard.AlgorithmGuard.Models.AlgorithmEnforcementResult>
            AddBlockAsync(
                Guid securityRuleId,
                string filePath,
                CancellationToken cancellationToken = default)
            {
            return Task.FromResult(
                new SecurityGuard.AlgorithmGuard.Models.AlgorithmEnforcementResult(
                    true,
                    SecurityGuard.AlgorithmGuard.Enums.AlgorithmEnforcementLevel.AppLockerBlocked,
                    "Applied"));
            }
        }

        private sealed class RecordingEnforcementService
        : SecurityGuard.AlgorithmGuard.Contracts.IAlgorithmEnforcementService
    {
        public bool WasCalled { get; private set; }

        public SecurityGuard.AlgorithmGuard.Enums.AlgorithmEnforcementLevel GetLevel(
            string? filePath)
        {
            return SecurityGuard.AlgorithmGuard.Enums.AlgorithmEnforcementLevel.AppLockerBlocked;
        }

        public Task<SecurityGuard.AlgorithmGuard.Models.AlgorithmEnforcementResult>
            AddBlockAsync(
                Guid securityRuleId,
                string filePath,
                CancellationToken cancellationToken = default)
        {
            WasCalled = true;

            return Task.FromResult(
                new SecurityGuard.AlgorithmGuard.Models.AlgorithmEnforcementResult(
                    true,
                    SecurityGuard.AlgorithmGuard.Enums.AlgorithmEnforcementLevel.AppLockerBlocked,
                    "Applied"));
        }
    }

    private sealed class FakeRuntimeController
        : SecurityGuard.AlgorithmGuard.Contracts.IAlgorithmGuardRuntimeController
    {
        public AlgorithmGuardSettings CurrentSettings { get; set; } =
            new(
                true,
                SecurityGuard.AlgorithmGuard.Enums.AlgorithmGuardMode.Monitor,
                SecurityGuard.AlgorithmGuard.Enums.EnforcementFailurePolicy.FailOpen);

        public string? EnforcementFailure { get; private set; }

        public Task ApplyAsync(
            AlgorithmGuardSettings settings,
            CancellationToken cancellationToken = default)
        {
            CurrentSettings =
                settings;

            return Task.CompletedTask;
        }

        public Task ReportEnforcementFailureAsync(
            string message,
            CancellationToken cancellationToken = default)
        {
            EnforcementFailure =
                message;

            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Block_in_monitor_mode_does_not_apply_os_enforcement()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.AlgorithmGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(
            root);

        try
        {
            var factory =
                new SqliteConnectionFactory(
                    new StorageOptions(
                        Path.Combine(
                            root,
                            "test.db")));

            await new DatabaseInitializer(
                factory).InitializeAsync();

            var repository =
                new SqliteRuleRepository(
                    factory);

            var script =
                Path.Combine(
                    root,
                    "monitor.cmd");

            await File.WriteAllTextAsync(
                script,
                "echo monitor");

            var enforcement =
                new RecordingEnforcementService();

            var runtime =
                new FakeRuntimeController
                {
                    CurrentSettings =
                        new AlgorithmGuardSettings(
                            true,
                            AlgorithmGuardMode.Monitor,
                            EnforcementFailurePolicy.FailOpen)
                };

            var handler =
                new AlgorithmDecisionHandler(
                    new Sha256FileHashService(),
                    repository,
                    new FakeQuarantineService(),
                    new AlgorithmTemporaryDecisionStore(),
                    enforcement,
                    new AlgorithmGuardOptions(),
                    runtime);

            var request =
                new SecurityDecisionRequest(
                    Guid.NewGuid(),
                    SecurityModuleKind.AlgorithmGuard,
                    SecurityEventType.AlgorithmExecution,
                    "Unknown",
                    $"cmd.exe /c \"{script}\"",
                    script,
                    "cmd.exe",
                    [
                        SecurityAction.Block
                    ],
                    DateTimeOffset.UtcNow);

            await handler.HandleAsync(
                request,
                new SecurityDecision(
                    request.Id,
                    SecurityAction.Block,
                    true,
                    DateTimeOffset.UtcNow));

            Assert.False(
                enforcement.WasCalled);

            var rules =
                await repository.GetEnabledAsync();

            var rule =
                Assert.Single(
                    rules);

            Assert.Equal(
                RuleDecision.Block,
                rule.Decision);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}