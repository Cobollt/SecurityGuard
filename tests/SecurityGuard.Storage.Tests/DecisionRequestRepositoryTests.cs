using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class DecisionRequestRepositoryTests
{
    [Fact]
    public async Task Pending_request_can_be_saved_and_removed()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteDecisionRequestRepository(
                database.ConnectionFactory);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Unknown script",
                "Execution blocked",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.AllowOnce,
                    SecurityAction.Allow,
                    SecurityAction.Quarantine,
                    SecurityAction.Delete
                ],
                DateTimeOffset.UtcNow);

        await repository.AddAsync(request);

        var pending =
            await repository.GetPendingAsync();

        var stored =
            Assert.Single(pending);

        Assert.Equal(
            request.Id,
            stored.Id);

        Assert.Contains(
            SecurityAction.Quarantine,
            stored.AvailableActions);

        await repository.RemoveAsync(
            request.Id);

        pending =
            await repository.GetPendingAsync();

        Assert.Empty(pending);
    }
}