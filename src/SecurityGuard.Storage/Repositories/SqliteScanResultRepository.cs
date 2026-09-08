using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteScanResultRepository
    : IScanResultRepository
{
    private readonly DatabaseInitializer _database;

    public SqliteScanResultRepository(
        DatabaseInitializer database)
    {
        _database =
            database;
    }

    public async Task UpsertAsync(
        ScanResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            result);

        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO scan_results (
                id,
                module,
                file_path,
                sha256,
                file_size,
                verdict,
                summary,
                started_at_utc,
                completed_at_utc
            )
            VALUES (
                $id,
                $module,
                $filePath,
                $sha256,
                $fileSize,
                $verdict,
                $summary,
                $startedAtUtc,
                $completedAtUtc
            )
            ON CONFLICT(id) DO UPDATE SET
                module = excluded.module,
                file_path = excluded.file_path,
                sha256 = excluded.sha256,
                file_size = excluded.file_size,
                verdict = excluded.verdict,
                summary = excluded.summary,
                started_at_utc = excluded.started_at_utc,
                completed_at_utc = excluded.completed_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$id",
            result.Id.ToString());

        command.Parameters.AddWithValue(
            "$module",
            (int)result.Module);

        command.Parameters.AddWithValue(
            "$filePath",
            result.FilePath);

        command.Parameters.AddWithValue(
            "$sha256",
            (object?)result.Sha256 ??
            DBNull.Value);

        command.Parameters.AddWithValue(
            "$fileSize",
            result.FileSize is null
                ? DBNull.Value
                : result.FileSize.Value);

        command.Parameters.AddWithValue(
            "$verdict",
            (int)result.Verdict);

        command.Parameters.AddWithValue(
            "$summary",
            result.Summary);

        command.Parameters.AddWithValue(
            "$startedAtUtc",
            result.StartedAtUtc
                .ToUniversalTime()
                .ToString("O"));

        command.Parameters.AddWithValue(
            "$completedAtUtc",
            result.CompletedAtUtc
                .ToUniversalTime()
                .ToString("O"));

        await command.ExecuteNonQueryAsync(
            cancellationToken);
    }

    public async Task<ScanResult?> GetByIdAsync(
        Guid id,
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
                id,
                module,
                file_path,
                sha256,
                file_size,
                verdict,
                summary,
                started_at_utc,
                completed_at_utc
            FROM scan_results
            WHERE id = $id
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

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

    public async Task<ScanResult?> GetLatestBySha256Async(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        sha256 =
            NormalizeSha256(
                sha256);

        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                module,
                file_path,
                sha256,
                file_size,
                verdict,
                summary,
                started_at_utc,
                completed_at_utc
            FROM scan_results
            WHERE sha256 = $sha256
            ORDER BY completed_at_utc DESC
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

    public async Task<IReadOnlyList<ScanResult>> GetRecentAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(limit));
        }

        await using var connection =
            await OpenAsync(
                cancellationToken);

        var command =
            connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                module,
                file_path,
                sha256,
                file_size,
                verdict,
                summary,
                started_at_utc,
                completed_at_utc
            FROM scan_results
            ORDER BY completed_at_utc DESC
            LIMIT $limit;
            """;

        command.Parameters.AddWithValue(
            "$limit",
            limit);

        var results =
            new List<ScanResult>();

        await using var reader =
            await command.ExecuteReaderAsync(
                cancellationToken);

        while (await reader.ReadAsync(
                   cancellationToken))
        {
            results.Add(
                Read(
                    reader));
        }

        return results;
    }

    private async Task<SqliteConnection> OpenAsync(
        CancellationToken cancellationToken)
    {
        var connection =
            new SqliteConnection(
                _database.ConnectionString);

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

    private static ScanResult Read(
        SqliteDataReader reader)
    {
        return new ScanResult(
            Guid.Parse(
                reader.GetString(0)),
            (SecurityModuleKind)reader.GetInt32(1),
            reader.GetString(2),
            reader.IsDBNull(3)
                ? null
                : reader.GetString(3),
            reader.IsDBNull(4)
                ? null
                : reader.GetInt64(4),
            (ScanVerdict)reader.GetInt32(5),
            reader.GetString(6),
            DateTimeOffset.Parse(
                reader.GetString(7)),
            DateTimeOffset.Parse(
                reader.GetString(8)));
    }

    private static string NormalizeSha256(
        string sha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            sha256);

        sha256 =
            sha256.Trim()
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