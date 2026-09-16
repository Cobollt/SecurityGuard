using System.Globalization;
using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Lists;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteSecurityListImportHistoryRepository
    : ISecurityListImportHistoryRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteSecurityListImportHistoryRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory =
            connectionFactory;
    }

    public async Task<SecurityListImportRecord?> GetByPackageSha256Async(
        string packageSha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            packageSha256);

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                package_sha256,
                original_file_name,
                archived_package_path,
                package_type,
                format_version,
                exported_at_utc,
                imported_at_utc,
                mode,
                rule_count,
                rule_condition_count,
                threat_hash_count
            FROM security_list_imports
            WHERE package_sha256 = $sha256
            LIMIT 1;
            """;

        command.Parameters.AddWithValue(
            "$sha256",
            NormalizeSha256(
                packageSha256));

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

    public async Task<IReadOnlyList<SecurityListImportRecord>> GetRecentAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <=
            0)
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
                package_sha256,
                original_file_name,
                archived_package_path,
                package_type,
                format_version,
                exported_at_utc,
                imported_at_utc,
                mode,
                rule_count,
                rule_condition_count,
                threat_hash_count
            FROM security_list_imports
            ORDER BY imported_at_utc DESC
            LIMIT $limit;
            """;

        command.Parameters.AddWithValue(
            "$limit",
            limit);

        var result =
            new List<SecurityListImportRecord>();

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

    private static SecurityListImportRecord Read(
        SqliteDataReader reader)
    {
        return new SecurityListImportRecord(
            Guid.Parse(
                reader.GetString(
                    0)),
            reader.GetString(
                1),
            reader.GetString(
                2),
            reader.GetString(
                3),
            reader.GetString(
                4),
            reader.GetInt32(
                5),
            DateTimeOffset.Parse(
                reader.GetString(
                    6),
                CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(
                reader.GetString(
                    7),
                CultureInfo.InvariantCulture),
            (SecurityListImportMode)reader.GetInt32(
                8),
            reader.GetInt32(
                9),
            reader.GetInt32(
                10),
            reader.GetInt32(
                11));
    }

    private static string NormalizeSha256(
        string value)
    {
        return value
            .Trim()
            .ToUpperInvariant();
    }
}