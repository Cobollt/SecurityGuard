using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteRuleRepository : IRuleRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteRuleRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            SELECT
                id,
                name,
                module,
                decision,
                scope,
                value,
                enabled,
                priority,
                created_at_utc,
                expires_at_utc
            FROM rules
            WHERE enabled = 1;
            """;

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);

        var results = new List<SecurityRule>();

        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ReadRule(reader));
        }

        return results;
    }

    public async Task UpsertAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);

        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            """
            INSERT INTO rules
            (
                id,
                name,
                module,
                decision,
                scope,
                value,
                enabled,
                priority,
                created_at_utc,
                expires_at_utc
            )
            VALUES
            (
                $id,
                $name,
                $module,
                $decision,
                $scope,
                $value,
                $enabled,
                $priority,
                $created,
                $expires
            )
            ON CONFLICT(id)
            DO UPDATE SET
                name = excluded.name,
                module = excluded.module,
                decision = excluded.decision,
                scope = excluded.scope,
                value = excluded.value,
                enabled = excluded.enabled,
                priority = excluded.priority,
                expires_at_utc = excluded.expires_at_utc;
            """;

        command.Parameters.AddWithValue(
            "$id",
            rule.Id.ToString());

        command.Parameters.AddWithValue(
            "$name",
            rule.Name);

        command.Parameters.AddWithValue(
            "$module",
            (int)rule.Module);

        command.Parameters.AddWithValue(
            "$decision",
            (int)rule.Decision);

        command.Parameters.AddWithValue(
            "$scope",
            (int)rule.Scope);

        command.Parameters.AddWithValue(
            "$value",
            rule.Value);

        command.Parameters.AddWithValue(
            "$enabled",
            rule.Enabled ? 1 : 0);

        command.Parameters.AddWithValue(
            "$priority",
            rule.Priority);

        command.Parameters.AddWithValue(
            "$created",
            rule.CreatedAtUtc.ToString("O"));

        command.Parameters.AddWithValue(
            "$expires",
            rule.ExpiresAtUtc?.ToString("O") ??
            (object)DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task DeleteAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();

        command.CommandText =
            "DELETE FROM rules WHERE id = $id;";

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static SecurityRule ReadRule(
        SqliteDataReader reader)
    {
        DateTimeOffset? expiresValue =
            reader.IsDBNull(9)
                ? null
                : DateTimeOffset.Parse(reader.GetString(9));

        return new SecurityRule(
            Guid.Parse(reader.GetString(0)),
            reader.GetString(1),
            (SecurityModuleKind)reader.GetInt32(2),
            (RuleDecision)reader.GetInt32(3),
            (RuleScope)reader.GetInt32(4),
            reader.GetString(5),
            reader.GetInt32(6) == 1,
            reader.GetInt32(7),
            DateTimeOffset.Parse(reader.GetString(8)),
            expiresValue);
    }
}