using SecurityGuard.AlgorithmGuard.Configuration;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmDecisionMaintenanceServiceTests
{
    [Fact]
    public async Task Cleanup_removes_expired_decisions()
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

            var decisionRepository =
                new SqliteDecisionRequestRepository(
                    factory);

            var eventRepository =
                new SqliteSecurityEventRepository(
                    factory);

            var request =
                new SecurityDecisionRequest(
                    Guid.NewGuid(),
                    SecurityModuleKind.AlgorithmGuard,
                    SecurityEventType.AlgorithmExecution,
                    "Expired",
                    "Expired",
                    null,
                    "powershell.exe",
                    [
                        SecurityAction.AllowOnce
                    ],
                    DateTimeOffset.UtcNow -
                    TimeSpan.FromHours(1),
                    null,
                    "ALG:OLD");

            await decisionRepository.AddAsync(
                request);

            var service =
                new AlgorithmDecisionMaintenanceService(
                    decisionRepository,
                    new AuditService(
                        eventRepository),
                    new AlgorithmGuardOptions
                    {
                        PendingDecisionLifetime =
                            TimeSpan.FromMinutes(10)
                    });

            var removed =
                await service.CleanupAsync();

            Assert.Equal(
                1,
                removed);

            var remaining =
                await decisionRepository.GetPendingAsync();

            Assert.Empty(
                remaining);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}