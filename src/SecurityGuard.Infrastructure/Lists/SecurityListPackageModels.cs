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

    public const long MaxPackageBytes =
        64L * 1024L * 1024L;

    public const long MaxManifestBytes =
        1024L * 1024L;

    public const long MaxRulesBytes =
        32L * 1024L * 1024L;

    public const long MaxRuleConditionsBytes =
        32L * 1024L * 1024L;

    public const long MaxThreatHashesBytes =
        32L * 1024L * 1024L;

    public const int MaxRuleCount =
        50_000;

    public const int MaxRuleConditionCount =
        250_000;

    public const int MaxThreatHashCount =
        250_000;
}

public enum SecurityListImportMode
{
    Merge = 0
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
    string PackageSha256,
    DateTimeOffset ExportedAtUtc,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount);

public sealed record SecurityListPackageValidationResult(
    bool IsValid,
    string? Error,
    string? PackageSha256,
    SecurityListPackageManifest? Manifest);

public sealed record SecurityListStoreImportResult(
    int RulesUpserted,
    int ThreatHashesUpserted);

public sealed record SecurityListImportRecord(
    Guid Id,
    string PackageSha256,
    string OriginalFileName,
    string ArchivedPackagePath,
    string PackageType,
    int FormatVersion,
    DateTimeOffset ExportedAtUtc,
    DateTimeOffset ImportedAtUtc,
    SecurityListImportMode Mode,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount);

public sealed record SecurityListImportResult(
    string PackagePath,
    string PackageSha256,
    string ArchivedPackagePath,
    SecurityListImportMode Mode,
    DateTimeOffset ImportedAtUtc,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount,
    bool AlreadyImported,
    bool AlgorithmEnforcementSynchronized,
    bool TransferEnforcementSynchronized,
    IReadOnlyList<string> Warnings);