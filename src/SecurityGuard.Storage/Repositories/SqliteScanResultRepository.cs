using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteScanResultRepository
    : IScanResultRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteScanResultRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory =
            connectionFactory;
    }

    public async Task UpsertAsync(
        ScanResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            result);

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
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
                risk_score,
                findings_json,
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
                $riskScore,
                $findingsJson,
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
                risk_score = excluded.risk_score,
                findings_json = excluded.findings_json,
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
            "$riskScore",
            result.RiskScore);

        command.Parameters.AddWithValue(
            "$findingsJson",
            JsonSerializer.Serialize(
                result.Findings));

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
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
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
                risk_score,
                findings_json,
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
        ArgumentException.ThrowIfNullOrWhiteSpace(
            sha256);

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
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
                risk_score,
                findings_json,
                started_at_utc,
                completed_at_utc
            FROM scan_results
            WHERE UPPER(sha256) = UPPER($sha256)
            ORDER BY completed_at_utc DESC
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$sha256",
            sha256.Trim());

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
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
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
                risk_score,
                findings_json,
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

    private static ScanResult Read(
        SqliteDataReader reader)
    {
        var findings =
            JsonSerializer.Deserialize<List<string>>(
                reader.GetString(8))
            ??
            [];

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
            reader.GetInt32(7),
            findings,
            DateTimeOffset.Parse(
                reader.GetString(9)),
            DateTimeOffset.Parse(
                reader.GetString(10)));
    }
}