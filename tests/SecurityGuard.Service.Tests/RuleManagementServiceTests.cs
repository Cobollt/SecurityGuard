using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Service.Application;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Service.Tests;

public sealed class RuleManagementServiceTests
{
    [Fact]
    public async Task Delete_calls_module_handler_before_repository_delete()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var ruleRepository =
            new SqliteRuleRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Blocked script",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                "ABC123",
                true,
                200,
                DateTimeOffset.UtcNow,
                null);

        await ruleRepository.UpsertAsync(
            rule);

        var handler =
            new RecordingLifecycleHandler();

        var service =
            new RuleManagementService(
                ruleRepository,
                [handler],
                new AuditService(
                    eventRepository));

        await service.DeleteAsync(
            rule.Id);

        Assert.Equal(
            rule.Id,
            handler.DeletedRuleId);

        var stored =
            await ruleRepository.GetByIdAsync(
                rule.Id);

        Assert.Null(stored);
    }

    private sealed class RecordingLifecycleHandler
        : ISecurityRuleLifecycleHandler
    {
        public Guid? DeletedRuleId { get; private set; }

        public SecurityModuleKind Module =>
            SecurityModuleKind.AlgorithmGuard;

        public Task BeforeDeleteAsync(
            SecurityRule rule,
            CancellationToken cancellationToken = default)
        {
            DeletedRuleId =
                rule.Id;

            return Task.CompletedTask;
        }
    }
}