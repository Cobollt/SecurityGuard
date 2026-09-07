using System.Globalization;
using System.Text.Json;
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
            INSERT INTO scan_results
            (
                id,
                file_path,
                sha256,
                verdict,
                risk_score,
                findings_json,
                started_at_utc,
                completed_at_utc
            )
            VALUES
            (
                $id,
                $filePath,
                $sha256,
                $verdict,
                $riskScore,
                $findings,
                $started,
                $completed
            )
            ON CONFLICT(id)
            DO UPDATE SET
                file_path = excluded.file_path,
                sha256 = excluded.sha256,
                verdict = excluded.verdict,
                risk_score = excluded.risk_score,
                findings_json = excluded.findings_json,
                started_at_utc = excluded.started_at_utc,
                completed_at_utc = excluded.completed_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$id",
            result.Id.ToString());

        command.Parameters.AddWithValue(
            "$filePath",
            result.FilePath);

        command.Parameters.AddWithValue(
            "$sha256",
            result.Sha256);

        command.Parameters.AddWithValue(
            "$verdict",
            (int)result.Verdict);

        command.Parameters.AddWithValue(
            "$riskScore",
            result.RiskScore);

        command.Parameters.AddWithValue(
            "$findings",
            JsonSerializer.Serialize(
                result.Findings));

        command.Parameters.AddWithValue(
            "$started",
            result.StartedAtUtc
                .ToUniversalTime()
                .ToString(
                    "O",
                    CultureInfo.InvariantCulture));

        command.Parameters.AddWithValue(
            "$completed",
            result.CompletedAtUtc
                .ToUniversalTime()
                .ToString(
                    "O",
                    CultureInfo.InvariantCulture));

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
                file_path,
                sha256,
                verdict,
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
                file_path,
                sha256,
                verdict,
                risk_score,
                findings_json,
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
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                file_path,
                sha256,
                verdict,
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
        Microsoft.Data.Sqlite.SqliteDataReader reader)
    {
        var findings =
            JsonSerializer.Deserialize<List<string>>(
                reader.GetString(
                    5)) ??
            [];

        return new ScanResult(
            Guid.Parse(
                reader.GetString(
                    0)),
            reader.GetString(
                1),
            reader.GetString(
                2),
            (ScanVerdict)reader.GetInt32(
                3),
            reader.GetInt32(
                4),
            findings,
            DateTimeOffset.Parse(
                reader.GetString(
                    6),
                CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(
                reader.GetString(
                    7),
                CultureInfo.InvariantCulture));
    }
}