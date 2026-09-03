using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class KnownThreatHashStoreTests
{
    [Fact]
    public async Task Enabled_hash_is_malicious()
    {
        var hash =
            new string(
                'A',
                64);

        var store =
            new KnownThreatHashStore(
                new FakeRepository(
                    new ThreatHashEntry(
                        hash,
                        "Test",
                        null,
                        true,
                        DateTimeOffset.UtcNow,
                        DateTimeOffset.UtcNow)));

        Assert.True(
            await store.IsMaliciousAsync(
                hash));
    }

    [Fact]
    public async Task Disabled_hash_is_not_malicious()
    {
        var hash =
            new string(
                'B',
                64);

        var store =
            new KnownThreatHashStore(
                new FakeRepository(
                    new ThreatHashEntry(
                        hash,
                        "Test",
                        null,
                        false,
                        DateTimeOffset.UtcNow,
                        DateTimeOffset.UtcNow)));

        Assert.False(
            await store.IsMaliciousAsync(
                hash));
    }

    private sealed class FakeRepository
        : IThreatHashRepository
    {
        private readonly ThreatHashEntry? _entry;

        public FakeRepository(
            ThreatHashEntry? entry)
        {
            _entry =
                entry;
        }

        public Task<ThreatHashEntry?> GetBySha256Async(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _entry);
        }

        public Task<IReadOnlyList<ThreatHashEntry>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<ThreatHashEntry> result =
                _entry is null
                    ? []
                    : [_entry];

            return Task.FromResult(
                result);
        }

        public Task UpsertAsync(
            ThreatHashEntry entry,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}