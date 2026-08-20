using System.Globalization;
using Microsoft.Data.Sqlite;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Repositories;

public sealed class SqliteRuleRepository
    : IRuleRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteRuleRepository(
        SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory =
            connectionFactory;
    }

    public async Task<IReadOnlyList<SecurityRule>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            BuildSelectSql(
                null);

        return await ReadRulesAsync(
            command,
            cancellationToken);
    }

    public async Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            BuildSelectSql(
                "r.enabled = 1");

        return await ReadRulesAsync(
            command,
            cancellationToken);
    }

    public async Task<SecurityRule?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var command =
            connection.CreateCommand();

        command.CommandText =
            BuildSelectSql(
                "r.id = $id");

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        var rules =
            await ReadRulesAsync(
                command,
                cancellationToken);

        return rules.FirstOrDefault();
    }

    public async Task UpsertAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            rule);

        await using var connection =
            await _connectionFactory.OpenAsync(
                cancellationToken);

        await using var transaction =
            await connection.BeginTransactionAsync(
                cancellationToken);

        try
        {
            await using (var command =
                         connection.CreateCommand())
            {
                command.Transaction =
                    (SqliteTransaction)transaction;

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
                        created_at_utc = excluded.created_at_utc,
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

                await command.ExecuteNonQueryAsync(
                    cancellationToken);
            }

            await using (var deleteConditions =
                         connection.CreateCommand())
            {
                deleteConditions.Transaction =
                    (SqliteTransaction)transaction;

                deleteConditions.CommandText =
                    """
                    DELETE FROM rule_conditions
                    WHERE rule_id = $ruleId;
                    """;

                deleteConditions.Parameters.AddWithValue(
                    "$ruleId",
                    rule.Id.ToString());

                await deleteConditions.ExecuteNonQueryAsync(
                    cancellationToken);
            }

            var conditions =
                rule.Conditions ??
                [];

            for (var index = 0;
                 index < conditions.Count;
                 index++)
            {
                var condition =
                    conditions[index];

                await using var insertCondition =
                    connection.CreateCommand();

                insertCondition.Transaction =
                    (SqliteTransaction)transaction;

                insertCondition.CommandText =
                    """
                    INSERT INTO rule_conditions
                    (
                        rule_id,
                        position,
                        scope,
                        value
                    )
                    VALUES
                    (
                        $ruleId,
                        $position,
                        $scope,
                        $value
                    );
                    """;

                insertCondition.Parameters.AddWithValue(
                    "$ruleId",
                    rule.Id.ToString());

                insertCondition.Parameters.AddWithValue(
                    "$position",
                    index);

                insertCondition.Parameters.AddWithValue(
                    "$scope",
                    (int)condition.Scope);

                insertCondition.Parameters.AddWithValue(
                    "$value",
                    condition.Value);

                await insertCondition.ExecuteNonQueryAsync(
                    cancellationToken);
            }

            await transaction.CommitAsync(
                cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(
                cancellationToken);

            throw;
        }
    }

    public async Task DeleteAsync(
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
            DELETE FROM rules
            WHERE id = $id;
            """;

        command.Parameters.AddWithValue(
            "$id",
            id.ToString());

        await command.ExecuteNonQueryAsync(
            cancellationToken);
    }

    private static string BuildSelectSql(
        string? where)
    {
        var filter =
            string.IsNullOrWhiteSpace(where)
                ? string.Empty
                : $"WHERE {where}";

        return
            $"""
            SELECT
                r.id,
                r.name,
                r.module,
                r.decision,
                r.scope,
                r.value,
                r.enabled,
                r.priority,
                r.created_at_utc,
                r.expires_at_utc,
                c.position,
                c.scope,
                c.value
            FROM rules r
            LEFT JOIN rule_conditions c
                ON c.rule_id = r.id
            {filter}
            ORDER BY
                r.priority DESC,
                r.created_at_utc DESC,
                c.position ASC;
            """;
    }

    private static async Task<IReadOnlyList<SecurityRule>> ReadRulesAsync(
        SqliteCommand command,
        CancellationToken cancellationToken)
    {
        await using var reader =
            await command.ExecuteReaderAsync(
                cancellationToken);

        var builders =
            new Dictionary<Guid, RuleBuilder>();

        var order =
            new List<Guid>();

        while (await reader.ReadAsync(
                   cancellationToken))
        {
            var id =
                Guid.Parse(
                    reader.GetString(0));

            if (!builders.TryGetValue(
                    id,
                    out var builder))
            {
                builder =
                    new RuleBuilder(
                        id,
                        reader.GetString(1),
                        (SecurityModuleKind)reader.GetInt32(2),
                        (RuleDecision)reader.GetInt32(3),
                        (RuleScope)reader.GetInt32(4),
                        reader.GetString(5),
                        reader.GetInt32(6) != 0,
                        reader.GetInt32(7),
                        ParseDateTimeOffset(
                            reader.GetString(8)),
                        reader.IsDBNull(9)
                            ? null
                            : ParseDateTimeOffset(
                                reader.GetString(9)));

                builders[id] =
                    builder;

                order.Add(id);
            }

            if (!reader.IsDBNull(11) &&
                !reader.IsDBNull(12))
            {
                builder.Conditions.Add(
                    new SecurityRuleCondition(
                        (RuleScope)reader.GetInt32(11),
                        reader.GetString(12)));
            }
        }

        return order
            .Select(
                id =>
                    builders[id].Build())
            .ToArray();
    }

    private static DateTimeOffset ParseDateTimeOffset(
        string value)
    {
        return DateTimeOffset.Parse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind);
    }

    private sealed class RuleBuilder
    {
        public Guid Id { get; }

        public string Name { get; }

        public SecurityModuleKind Module { get; }

        public RuleDecision Decision { get; }

        public RuleScope Scope { get; }

        public string Value { get; }

        public bool Enabled { get; }

        public int Priority { get; }

        public DateTimeOffset CreatedAtUtc { get; }

        public DateTimeOffset? ExpiresAtUtc { get; }

        public List<SecurityRuleCondition> Conditions { get; } =
            [];

        public RuleBuilder(
            Guid id,
            string name,
            SecurityModuleKind module,
            RuleDecision decision,
            RuleScope scope,
            string value,
            bool enabled,
            int priority,
            DateTimeOffset createdAtUtc,
            DateTimeOffset? expiresAtUtc)
        {
            Id = id;
            Name = name;
            Module = module;
            Decision = decision;
            Scope = scope;
            Value = value;
            Enabled = enabled;
            Priority = priority;
            CreatedAtUtc = createdAtUtc;
            ExpiresAtUtc = expiresAtUtc;
        }

        public SecurityRule Build()
        {
            return new SecurityRule(
                Id,
                Name,
                Module,
                Decision,
                Scope,
                Value,
                Enabled,
                Priority,
                CreatedAtUtc,
                ExpiresAtUtc,
                Conditions.ToArray());
        }
    }
}