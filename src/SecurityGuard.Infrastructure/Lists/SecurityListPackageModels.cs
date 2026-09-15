using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Lists;

public static class SecurityListPackageFormat
{
    public const string PackageType =
        "SecurityGuard.Lists";

    public const int CurrentVersion =
        1;

    public const string ManifestEntryName =
        "manifest.json";

    public const string RulesEntryName =
        "rules.json";

    public const string RuleConditionsEntryName =
        "rule_conditions.json";

    public const string ThreatHashesEntryName =
        "threat_hashes.json";
}

public sealed record SecurityListPackageManifest(
    string PackageType,
    int FormatVersion,
    DateTimeOffset ExportedAtUtc,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount,
    string RulesSha256,
    string RuleConditionsSha256,
    string ThreatHashesSha256);

public sealed record SecurityListRuleEntry(
    Guid Id,
    string Name,
    SecurityModuleKind Module,
    RuleDecision Decision,
    RuleScope Scope,
    string Value,
    bool Enabled,
    int Priority,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc);

public sealed record SecurityListRuleConditionEntry(
    Guid RuleId,
    int Position,
    RuleScope Scope,
    string Value);

public sealed record SecurityListThreatHashEntry(
    string Sha256,
    string Source,
    string? Description,
    bool Enabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record SecurityListExportResult(
    string PackagePath,
    DateTimeOffset ExportedAtUtc,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount);