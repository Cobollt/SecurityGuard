using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteThreatHashRepository(
    SqliteDatabase database)
    : IThreatHashRepository
{
    public async Task<ThreatHashEntry?> GetBySha256Async(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        sha256 =
            Normalize(
                sha256);

        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                sha256,
                source,
                description,
                enabled,
                created_at_utc,
                updated_at_utc
            FROM threat_hashes
            WHERE sha256 = $sha256
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$sha256",
            sha256);

        await using var reader =
            await command.ExecuteReaderAsync(
                cancellationToken);

        if (!await reader.ReadAsync(
                cancellationToken))
        {
            return null;
        }

        return Read(
            reader);
    }

    public async Task<IReadOnlyList<ThreatHashEntry>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                sha256,
                source,
                description,
                enabled,
                created_at_utc,
                updated_at_utc
            FROM threat_hashes
            ORDER BY updated_at_utc DESC;
            """;

        var result =
            new List<ThreatHashEntry>();

        await using var reader =
            await command.ExecuteReaderAsync(
                cancellationToken);

        while (await reader.ReadAsync(
                   cancellationToken))
        {
            result.Add(
                Read(
                    reader));
        }

        return result;
    }

    public async Task UpsertAsync(
        ThreatHashEntry entry,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            entry);

        var sha256 =
            Normalize(
                entry.Sha256);

        if (string.IsNullOrWhiteSpace(
                entry.Source))
        {
            throw new ArgumentException(
                "Threat hash source is required.",
                nameof(entry));
        }

        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO threat_hashes (
                sha256,
                source,
                description,
                enabled,
                created_at_utc,
                updated_at_utc
            )
            VALUES (
                $sha256,
                $source,
                $description,
                $enabled,
                $createdAtUtc,
                $updatedAtUtc
            )
            ON CONFLICT(sha256) DO UPDATE SET
                source = excluded.source,
                description = excluded.description,
                enabled = excluded.enabled,
                updated_at_utc = excluded.updated_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$sha256",
            sha256);

        command.Parameters.AddWithValue(
            "$source",
            entry.Source.Trim());

        command.Parameters.AddWithValue(
            "$description",
            (object?)entry.Description ??
            DBNull.Value);

        command.Parameters.AddWithValue(
            "$enabled",
            entry.Enabled
                ? 1
                : 0);

        command.Parameters.AddWithValue(
            "$createdAtUtc",
            entry.CreatedAtUtc.ToUniversalTime()
                .ToString("O"));

        command.Parameters.AddWithValue(
            "$updatedAtUtc",
            entry.UpdatedAtUtc.ToUniversalTime()
                .ToString("O"));

        await command.ExecuteNonQueryAsync(
            cancellationToken);
    }

    public async Task DeleteAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        sha256 =
            Normalize(
                sha256);

        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            DELETE FROM threat_hashes
            WHERE sha256 = $sha256;
            """;

        command.Parameters.AddWithValue(
            "$sha256",
            sha256);

        await command.ExecuteNonQueryAsync(
            cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(
        CancellationToken cancellationToken)
    {
        var connection =
            new SqliteConnection(
                database.ConnectionString);

        await connection.OpenAsync(
            cancellationToken);

        var pragma =
            connection.CreateCommand();

        pragma.CommandText =
            "PRAGMA foreign_keys=ON;";

        await pragma.ExecuteNonQueryAsync(
            cancellationToken);

        return connection;
    }

    private static ThreatHashEntry Read(
        SqliteDataReader reader)
    {
        return new ThreatHashEntry(
            reader.GetString(0),
            reader.GetString(1),
            reader.IsDBNull(2)
                ? null
                : reader.GetString(2),
            reader.GetInt32(3) ==
                1,
            DateTimeOffset.Parse(
                reader.GetString(4)),
            DateTimeOffset.Parse(
                reader.GetString(5)));
    }

    private static string Normalize(
        string sha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            sha256);

        sha256 =
            sha256
                .Trim()
                .ToUpperInvariant();

        if (sha256.Length !=
                64 ||
            sha256.Any(
                value =>
                    !Uri.IsHexDigit(
                        value)))
        {
            throw new ArgumentException(
                "SHA-256 must contain exactly 64 hexadecimal characters.",
                nameof(sha256));
        }

        return sha256;
    }
}