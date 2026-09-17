using System.IO.Compression;
using System.Text.Json;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Service.Application;
using SecurityGuard.Infrastructure.Hashing;

namespace SecurityGuard.Service.Tests;

public sealed class SecurityListTransferServiceTests
{
    [Fact]
    public async Task Export_creates_portable_package()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.ListExportTests",
                Guid.NewGuid().ToString(
                    "N"));

        try
        {
            var ruleId =
                Guid.NewGuid();

            var rules =
                new[]
                {
                    new SecurityRule(
                        ruleId,
                        "Blocked transfer",
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
                        ])
                };

            var hashes =
                new[]
                {
                    new ThreatHashEntry(
                        new string(
                            'A',
                            64),
                        "Test",
                        "Test malicious hash",
                        true,
                        DateTimeOffset.UtcNow,
                        DateTimeOffset.UtcNow)
                };

            var audit =
                new FakeAuditService();

            var service =
                new SecurityListTransferService(
                    new FakeRuleRepository(
                        rules),
                    new FakeThreatHashRepository(
                        hashes),
                    null!,
                    null!,
                    null!,
                    null!,
                    new Sha256FileHashService(),
                    new SecurityGuardPaths(
                        root),
                    audit);

            var result =
                await service.ExportAsync();

            Assert.True(
                File.Exists(
                    result.PackagePath));

            Assert.Equal(
                1,
                result.RuleCount);

            Assert.Equal(
                2,
                result.RuleConditionCount);

            Assert.Equal(
                1,
                result.ThreatHashCount);

            using var archive =
                ZipFile.OpenRead(
                    result.PackagePath);

            Assert.NotNull(
                archive.GetEntry(
                    SecurityListPackageFormat.ManifestEntryName));

            Assert.NotNull(
                archive.GetEntry(
                    SecurityListPackageFormat.RulesEntryName));

            Assert.NotNull(
                archive.GetEntry(
                    SecurityListPackageFormat.RuleConditionsEntryName));

            Assert.NotNull(
                archive.GetEntry(
                    SecurityListPackageFormat.ThreatHashesEntryName));

            var manifestEntry =
                archive.GetEntry(
                    SecurityListPackageFormat.ManifestEntryName);

            Assert.NotNull(
                manifestEntry);

            using var reader =
                new StreamReader(
                    manifestEntry!.Open());

            var manifestJson =
                await reader.ReadToEndAsync();

            var manifest =
                JsonSerializer.Deserialize<
                    SecurityListPackageManifest>(
                        manifestJson,
                        new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive =
                                true
                        });

            Assert.NotNull(
                manifest);

            Assert.Equal(
                SecurityListPackageFormat.PackageType,
                manifest!.PackageType);

            Assert.Equal(
                SecurityListPackageFormat.CurrentVersion,
                manifest.FormatVersion);

            Assert.Equal(
                1,
                manifest.RuleCount);

            Assert.Equal(
                2,
                manifest.RuleConditionCount);

            Assert.Equal(
                1,
                manifest.ThreatHashCount);

            Assert.True(
                audit.Written);
        }
        finally
        {
            if (Directory.Exists(
                    root))
            {
                Directory.Delete(
                    root,
                    true);
            }
        }
    }

    private sealed class FakeRuleRepository
        : IRuleRepository
    {
        private readonly IReadOnlyList<SecurityRule> _rules;

        public FakeRuleRepository(
            IReadOnlyList<SecurityRule> rules)
        {
            _rules =
                rules;
        }

        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _rules);
        }

        public Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<SecurityRule>>(
                _rules
                    .Where(
                        rule =>
                            rule.Enabled)
                    .ToArray());
        }

        public Task<SecurityRule?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _rules.FirstOrDefault(
                    rule =>
                        rule.Id ==
                        id));
        }

        public Task UpsertAsync(
            SecurityRule rule,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class FakeThreatHashRepository
        : IThreatHashRepository
    {
        private readonly IReadOnlyList<ThreatHashEntry> _entries;

        public FakeThreatHashRepository(
            IReadOnlyList<ThreatHashEntry> entries)
        {
            _entries =
                entries;
        }

        public Task<ThreatHashEntry?> GetBySha256Async(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _entries.FirstOrDefault(
                    entry =>
                        string.Equals(
                            entry.Sha256,
                            sha256,
                            StringComparison.OrdinalIgnoreCase)));
        }

        public Task<IReadOnlyList<ThreatHashEntry>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _entries);
        }

        public Task UpsertAsync(
            ThreatHashEntry entry,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task DeleteAsync(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class FakeAuditService
        : IAuditService
    {
        public bool Written { get; private set; }

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
            Written =
                true;

            return Task.CompletedTask;
        }
    }
}