using SecurityGuard.Core.Lists;

namespace SecurityGuard.Core.Ipc.SecurityLists;

public sealed record SecurityListExportIpcDto(
    string PackagePath,
    DateTimeOffset ExportedAtUtc,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount);

public sealed record SecurityListValidateIpcRequest(
    string PackagePath);

public sealed record SecurityListValidationIpcDto(
    bool IsValid,
    string? Error,
    int? FormatVersion,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount);

public sealed record SecurityListImportIpcRequest(
    string PackagePath,
    SecurityListImportMode Mode);

public sealed record SecurityListImportIpcDto(
    string PackagePath,
    SecurityListImportMode Mode,
    DateTimeOffset ImportedAtUtc,
    int RuleCount,
    int RuleConditionCount,
    int ThreatHashCount,
    bool AlgorithmEnforcementSynchronized,
    bool TransferEnforcementSynchronized,
    string[] Warnings);

public sealed record SecurityListFoldersIpcDto(
    string ListsDirectory,
    string ExportsDirectory,
    string ImportsDirectory);