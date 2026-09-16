using System.IO.Compression;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Infrastructure.Hashing;
using SecurityGuard.Service.Application;
using SecurityGuard.Storage.Repositories;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.Service.Tests;

public sealed class SecurityListRoundTripTests
{
    [Fact]
    public async Task Export_import_export_preserves_security_lists()
    {
        await using var sourceDatabase =
            await TestDatabase.CreateAsync();

        await using var targetDatabase =
            await TestDatabase.CreateAsync();

        var sourceRoot =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.RoundTrip.Source",
                Guid.NewGuid().ToString(
                    "N"));

        var targetRoot =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.RoundTrip.Target",
                Guid.NewGuid().ToString(
                    "N"));

        try
        {
            var sourceRules =
                new SqliteRuleRepository(
                    sourceDatabase.ConnectionFactory);

            var sourceHashes =
                new SqliteThreatHashRepository(
                    sourceDatabase.ConnectionFactory);

            var rule =
                new SecurityRule(
                    Guid.NewGuid(),
                    "Round trip rule",
                    SecurityModuleKind.TransferGuard,
                    RuleDecision.Block,
                    RuleScope.ProcessPath,
                    @"C:\Apps\sender.exe",
                    true,
                    200,
                    DateTimeOffset.UtcNow,
                    null,
                    [
                        new SecurityRuleCondition(
                            RuleScope.RemotePort,
                            "443"),

                        new SecurityRuleCondition(
                            RuleScope.Protocol,
                            "TCP")
                    ]);

            var hash =
                new ThreatHashEntry(
                    new string(
                        'A',
                        64),
                    "RoundTrip",
                    "Test hash",
                    true,
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow);

            await sourceRules.UpsertAsync(
                rule);

            await sourceHashes.UpsertAsync(
                hash);

            var sourceService =
                CreateService(
                    sourceDatabase,
                    sourceRoot);

            var firstExport =
                await sourceService.ExportAsync();

            var targetService =
                CreateService(
                    targetDatabase,
                    targetRoot);

            var import =
                await targetService.ImportAsync(
                    firstExport.PackagePath);

            Assert.False(
                import.AlreadyImported);

            Assert.True(
                File.Exists(
                    import.ArchivedPackagePath));

            var secondExport =
                await targetService.ExportAsync();

            AssertEntryEqual(
                firstExport.PackagePath,
                secondExport.PackagePath,
                SecurityListPackageFormat.RulesEntryName);

            AssertEntryEqual(
                firstExport.PackagePath,
                secondExport.PackagePath,
                SecurityListPackageFormat.RuleConditionsEntryName);

            AssertEntryEqual(
                firstExport.PackagePath,
                secondExport.PackagePath,
                SecurityListPackageFormat.ThreatHashesEntryName);

            var secondImport =
                await targetService.ImportAsync(
                    firstExport.PackagePath);

            Assert.True(
                secondImport.AlreadyImported);
        }
        finally
        {
            if (Directory.Exists(
                    sourceRoot))
            {
                Directory.Delete(
                    sourceRoot,
                    true);
            }

            if (Directory.Exists(
                    targetRoot))
            {
                Directory.Delete(
                    targetRoot,
                    true);
            }
        }
    }

    private static SecurityListTransferService CreateService(
        TestDatabase database,
        string root)
    {
        var rules =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var hashes =
            new SqliteThreatHashRepository(
                database.ConnectionFactory);

        var importStore =
            new SqliteSecurityListImportStore(
                database.ConnectionFactory);

        var history =
            new SqliteSecurityListImportHistoryRepository(
                database.ConnectionFactory);

        return new SecurityListTransferService(
            rules,
            hashes,
            importStore,
            history,
            new FakeAlgorithmSynchronizer(),
            new FakeTransferSynchronizer(),
            new Sha256FileHashService(),
            new SecurityGuardPaths(
                root),
            new FakeAuditService());
    }

    private static void AssertEntryEqual(
        string firstPackage,
        string secondPackage,
        string entryName)
    {
        using var first =
            ZipFile.OpenRead(
                firstPackage);

        using var second =
            ZipFile.OpenRead(
                secondPackage);

        var firstEntry =
            first.GetEntry(
                entryName);

        var secondEntry =
            second.GetEntry(
                entryName);

        Assert.NotNull(
            firstEntry);

        Assert.NotNull(
            secondEntry);

        using var firstStream =
            firstEntry!.Open();

        using var secondStream =
            secondEntry!.Open();

        using var firstMemory =
            new MemoryStream();

        using var secondMemory =
            new MemoryStream();

        firstStream.CopyTo(
            firstMemory);

        secondStream.CopyTo(
            secondMemory);

        Assert.Equal(
            firstMemory.ToArray(),
            secondMemory.ToArray());
    }

    private sealed class FakeAlgorithmSynchronizer
        : IAlgorithmEnforcementSynchronizer
    {
        public Task<AlgorithmEnforcementSyncResult> SynchronizeAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new AlgorithmEnforcementSyncResult(
                    0,
                    0,
                    true,
                    []));
        }

        public Task<int> DisableManagedRulesAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }
    }

    private sealed class FakeTransferSynchronizer
        : ITransferEnforcementSynchronizer
    {
        public Task<TransferEnforcementSyncResult> SynchronizeAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TransferEnforcementSyncResult(
                    0,
                    0,
                    true,
                    []));
        }

        public Task<int> DisableManagedRulesAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }
    }

    private sealed class FakeAuditService
        : IAuditService
    {
        public Task WriteAsync(
            SecurityModuleKind module,
            SecurityEventType type,
            SecuritySeverity severity,
            string title,
            string details,
            SecurityAction action = SecurityAction.None,
            Guid? correlationId = null,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}