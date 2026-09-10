using System.Collections.Concurrent;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardScanCache
    : IArchiveGuardScanCache
{
    private readonly ArchiveGuardOptions _options;

    private readonly ConcurrentDictionary<
        string,
        CacheEntry> _entries =
            new(
                StringComparer.OrdinalIgnoreCase);

    public ArchiveGuardScanCache(
        ArchiveGuardOptions options)
    {
        _options =
            options;
    }

    public bool TryGet(
        ArchiveFileMetadata metadata,
        out ArchiveGuardScanResult result)
    {
        ArgumentNullException.ThrowIfNull(
            metadata);

        result =
            null!;

        if (_options.ScanCacheTtlSeconds <=
            0)
        {
            return false;
        }

        var key =
            BuildKey(
                metadata);

        if (!_entries.TryGetValue(
                key,
                out var entry))
        {
            return false;
        }

        if (entry.ExpiresAtUtc <=
            DateTimeOffset.UtcNow)
        {
            _entries.TryRemove(
                key,
                out _);

            return false;
        }

        result =
            entry.Result;

        return true;
    }

    public void Store(
        ArchiveFileMetadata metadata,
        ArchiveGuardScanResult result)
    {
        ArgumentNullException.ThrowIfNull(
            metadata);

        ArgumentNullException.ThrowIfNull(
            result);

        if (_options.ScanCacheTtlSeconds <=
            0)
        {
            return;
        }

        if (result.Verdict is
            ScanVerdict.Error or
            ScanVerdict.Unknown)
        {
            return;
        }

        CleanupExpired();

        if (_entries.Count >=
            _options.MaxScanCacheEntries)
        {
            TrimOldest();
        }

        var now =
            DateTimeOffset.UtcNow;

        var snapshot =
            result with
            {
                Findings =
                    result.Findings.ToArray()
            };

        _entries[
            BuildKey(
                metadata)] =
            new CacheEntry(
                snapshot,
                now,
                now.AddSeconds(
                    _options.ScanCacheTtlSeconds));
    }

    public void Clear()
    {
        _entries.Clear();
    }

    private void CleanupExpired()
    {
        var now =
            DateTimeOffset.UtcNow;

        foreach (var pair in
                 _entries)
        {
            if (pair.Value.ExpiresAtUtc <=
                now)
            {
                _entries.TryRemove(
                    pair.Key,
                    out _);
            }
        }
    }

    private void TrimOldest()
    {
        var removeCount =
            Math.Max(
                1,
                _entries.Count -
                _options.MaxScanCacheEntries +
                1);

        var keys =
            _entries
                .OrderBy(
                    pair =>
                        pair.Value.StoredAtUtc)
                .Take(
                    removeCount)
                .Select(
                    pair =>
                        pair.Key)
                .ToArray();

        foreach (var key in
                 keys)
        {
            _entries.TryRemove(
                key,
                out _);
        }
    }

    private static string BuildKey(
        ArchiveFileMetadata metadata)
    {
        return string.Join(
            "|",
            metadata.Sha256.ToUpperInvariant(),
            metadata.FileName.ToUpperInvariant());
    }

    private sealed record CacheEntry(
        ArchiveGuardScanResult Result,
        DateTimeOffset StoredAtUtc,
        DateTimeOffset ExpiresAtUtc);
}