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
        _connectionFactory = connectionFactory;
    }

    public async Task AddAsync(
        ScanResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

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
            );
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
            JsonSerializer.Serialize(result.Findings));

        command.Parameters.AddWithValue(
            "$started",
            result.StartedAtUtc.ToString("O"));

        command.Parameters.AddWithValue(
            "$completed",
            result.CompletedAtUtc.ToString("O"));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<ScanResult?> GetLatestByHashAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

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
            await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var findings =
            JsonSerializer.Deserialize<List<string>>(
                reader.GetString(5)) ?? [];

        return new ScanResult(
            Guid.Parse(reader.GetString(0)),
            reader.GetString(1),
            reader.GetString(2),
            (ScanVerdict)reader.GetInt32(3),
            reader.GetInt32(4),
            findings,
            DateTimeOffset.Parse(reader.GetString(6)),
            DateTimeOffset.Parse(reader.GetString(7)));
    }
}