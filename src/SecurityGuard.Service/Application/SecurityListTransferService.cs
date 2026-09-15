using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Lists;
using SecurityGuard.Infrastructure.Configuration;

namespace SecurityGuard.Service.Application;

public sealed class SecurityListTransferService
    : ISecurityListTransferService
{
    private static readonly JsonSerializerOptions JsonOptions =
        CreateJsonOptions();

    private readonly IRuleRepository _ruleRepository;
    private readonly IThreatHashRepository _threatHashRepository;
    private readonly SecurityGuardPaths _paths;
    private readonly IAuditService _auditService;

    public SecurityListTransferService(
        IRuleRepository ruleRepository,
        IThreatHashRepository threatHashRepository,
        SecurityGuardPaths paths,
        IAuditService auditService)
    {
        _ruleRepository =
            ruleRepository;

        _threatHashRepository =
            threatHashRepository;

        _paths =
            paths;

        _auditService =
            auditService;
    }

    public string ListsDirectory =>
        _paths.ListsDirectory;

    public string ExportsDirectory =>
        _paths.ListExportsDirectory;

    public string ImportsDirectory =>
        _paths.ListImportsDirectory;

    public async Task<SecurityListExportResult> ExportAsync(
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(
            _paths.ListsDirectory);

        Directory.CreateDirectory(
            _paths.ListExportsDirectory);

        Directory.CreateDirectory(
            _paths.ListImportsDirectory);

        Directory.CreateDirectory(
            _paths.TempDirectory);

        var rules =
            (await _ruleRepository.GetAllAsync(
                cancellationToken))
            .OrderBy(
                rule =>
                    rule.Module)
            .ThenByDescending(
                rule =>
                    rule.Priority)
            .ThenBy(
                rule =>
                    rule.Id)
            .ToArray();

        var threatHashes =
            (await _threatHashRepository.GetAllAsync(
                cancellationToken))
            .OrderBy(
                entry =>
                    entry.Sha256,
                StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var ruleEntries =
            rules
                .Select(
                    rule =>
                        new SecurityListRuleEntry(
                            rule.Id,
                            rule.Name,
                            rule.Module,
                            rule.Decision,
                            rule.Scope,
                            rule.Value,
                            rule.Enabled,
                            rule.Priority,
                            rule.CreatedAtUtc,
                            rule.ExpiresAtUtc))
                .ToArray();

        var conditionEntries =
            rules
                .SelectMany(
                    rule =>
                        (rule.Conditions ?? [])
                            .Select(
                                (condition, position) =>
                                    new SecurityListRuleConditionEntry(
                                        rule.Id,
                                        position,
                                        condition.Scope,
                                        condition.Value)))
                .ToArray();

        var threatHashEntries =
            threatHashes
                .Select(
                    entry =>
                        new SecurityListThreatHashEntry(
                            entry.Sha256,
                            entry.Source,
                            entry.Description,
                            entry.Enabled,
                            entry.CreatedAtUtc,
                            entry.UpdatedAtUtc))
                .ToArray();

        var rulesBytes =
            Serialize(
                ruleEntries);

        var conditionsBytes =
            Serialize(
                conditionEntries);

        var threatHashesBytes =
            Serialize(
                threatHashEntries);

        var exportedAtUtc =
            DateTimeOffset.UtcNow;

        var manifest =
            new SecurityListPackageManifest(
                SecurityListPackageFormat.PackageType,
                SecurityListPackageFormat.CurrentVersion,
                exportedAtUtc,
                ruleEntries.Length,
                conditionEntries.Length,
                threatHashEntries.Length,
                ComputeSha256(
                    rulesBytes),
                ComputeSha256(
                    conditionsBytes),
                ComputeSha256(
                    threatHashesBytes));

        var manifestBytes =
            Serialize(
                manifest);

        var suffix =
            Guid.NewGuid()
                .ToString(
                    "N")[..8];

        var fileName =
            $"SecurityGuardLists_{exportedAtUtc:yyyyMMdd_HHmmss_fff}_{suffix}.zip";

        var destinationPath =
            Path.Combine(
                _paths.ListExportsDirectory,
                fileName);

        var temporaryPath =
            Path.Combine(
                _paths.TempDirectory,
                $"SecurityGuardLists_{Guid.NewGuid():N}.tmp");

        try
        {
            await CreatePackageAsync(
                temporaryPath,
                manifestBytes,
                rulesBytes,
                conditionsBytes,
                threatHashesBytes,
                cancellationToken);

            File.Move(
                temporaryPath,
                destinationPath,
                false);
        }
        catch
        {
            TryDelete(
                temporaryPath);

            throw;
        }

        try
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.Core,
                SecurityEventType.Audit,
                SecuritySeverity.Info,
                "Security lists exported",
                $"Package={fileName}; Rules={ruleEntries.Length}; Conditions={conditionEntries.Length}; ThreatHashes={threatHashEntries.Length}",
                cancellationToken:
                    cancellationToken);
        }
        catch
        {
        }

        return new SecurityListExportResult(
            destinationPath,
            exportedAtUtc,
            ruleEntries.Length,
            conditionEntries.Length,
            threatHashEntries.Length);
    }

    private static async Task CreatePackageAsync(
        string filePath,
        byte[] manifest,
        byte[] rules,
        byte[] conditions,
        byte[] threatHashes,
        CancellationToken cancellationToken)
    {
        await using var fileStream =
            new FileStream(
                filePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize:
                    64 * 1024,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        using var archive =
            new ZipArchive(
                fileStream,
                ZipArchiveMode.Create,
                true);

        await WriteEntryAsync(
            archive,
            SecurityListPackageFormat.ManifestEntryName,
            manifest,
            cancellationToken);

        await WriteEntryAsync(
            archive,
            SecurityListPackageFormat.RulesEntryName,
            rules,
            cancellationToken);

        await WriteEntryAsync(
            archive,
            SecurityListPackageFormat.RuleConditionsEntryName,
            conditions,
            cancellationToken);

        await WriteEntryAsync(
            archive,
            SecurityListPackageFormat.ThreatHashesEntryName,
            threatHashes,
            cancellationToken);
    }

    private static async Task WriteEntryAsync(
        ZipArchive archive,
        string entryName,
        byte[] content,
        CancellationToken cancellationToken)
    {
        var entry =
            archive.CreateEntry(
                entryName,
                CompressionLevel.Optimal);

        await using var stream =
            entry.Open();

        await stream.WriteAsync(
            content,
            cancellationToken);
    }

    private static byte[] Serialize<T>(
        T value)
    {
        return JsonSerializer.SerializeToUtf8Bytes(
            value,
            JsonOptions);
    }

    private static string ComputeSha256(
        byte[] value)
    {
        return Convert.ToHexString(
            SHA256.HashData(
                value));
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options =
            new JsonSerializerOptions
            {
                PropertyNamingPolicy =
                    JsonNamingPolicy.CamelCase,

                WriteIndented =
                    true
            };

        options.Converters.Add(
            new JsonStringEnumConverter());

        return options;
    }

    private static void TryDelete(
        string filePath)
    {
        try
        {
            if (File.Exists(
                    filePath))
            {
                File.Delete(
                    filePath);
            }
        }
        catch
        {
        }
    }
}