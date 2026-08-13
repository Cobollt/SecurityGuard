using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SecurityEventRepositoryTests
{
    [Fact]
    public async Task Event_can_be_saved_and_loaded()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteSecurityEventRepository(
                database.ConnectionFactory);

        var securityEvent =
            SecurityEvent.Create(
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                SecuritySeverity.High,
                "Script blocked",
                "test.ps1",
                SecurityAction.Block);

        await repository.AddAsync(
            securityEvent);

        var events =
            await repository.GetRecentAsync(10);

        var stored =
            Assert.Single(events);

        Assert.Equal(
            securityEvent.Id,
            stored.Id);

        Assert.Equal(
            SecurityAction.Block,
            stored.Action);
    }
}