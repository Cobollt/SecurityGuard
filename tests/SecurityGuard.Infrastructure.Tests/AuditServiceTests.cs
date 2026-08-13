using SecurityGuard.Core.Enums;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Infrastructure.Tests;

public sealed class AuditServiceTests
{
    [Fact]
    public async Task Audit_event_is_saved()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var repository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var auditService =
            new AuditService(repository);

        await auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.AlgorithmExecution,
            SecuritySeverity.High,
            "Script blocked",
            "test.ps1",
            SecurityAction.Block);

        var events =
            await repository.GetRecentAsync(10);

        var securityEvent =
            Assert.Single(events);

        Assert.Equal(
            "Script blocked",
            securityEvent.Title);

        Assert.Equal(
            SecurityAction.Block,
            securityEvent.Action);
    }
}