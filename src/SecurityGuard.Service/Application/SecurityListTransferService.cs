using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.Service.Application;

public sealed class SecurityListTransferService
    : ISecurityListTransferService
{
    private static readonly JsonSerializerOptions JsonOptions =
        CreateJsonOptions();

    private readonly IRuleRepository _ruleRepository;
    private readonly IThreatHashRepository _threatHashRepository;
    private readonly ISecurityListImportStore _importStore;
    private readonly IAlgorithmEnforcementSynchronizer _algorithmSynchronizer;
    private readonly ITransferEnforcementSynchronizer _transferSynchronizer;
    private readonly SecurityGuardPaths _paths;
    private readonly IAuditService _auditService;
    private readonly ISecurityListImportHistoryRepository _importHistoryRepository;
    private readonly IFileHashService _fileHashService;
    private readonly SemaphoreSlim _importGate =
        new(
            1,
            1);

    public SecurityListTransferService(
        IRuleRepository ruleRepository,
        IThreatHashRepository threatHashRepository,
        ISecurityListImportStore importStore,
        ISecurityListImportHistoryRepository importHistoryRepository,
        IAlgorithmEnforcementSynchronizer algorithmSynchronizer,
        ITransferEnforcementSynchronizer transferSynchronizer,
        IFileHashService fileHashService,
        SecurityGuardPaths paths,
        IAuditService auditService)
    {
        _ruleRepository =
            ruleRepository;

        _threatHashRepository =
            threatHashRepository;

        _importStore =
            importStore;

        _importHistoryRepository =
            importHistoryRepository;

        _algorithmSynchronizer =
            algorithmSynchronizer;

        _transferSynchronizer =
            transferSynchronizer;

        _fileHashService =
            fileHashService;

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
        EnsureDirectories();

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

        if (rules.Length >
            SecurityListPackageFormat.MaxRuleCount)
        {
            throw new InvalidOperationException(
                "Too many security rules to export.");
        }

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

        if (conditionEntries.Length >
            SecurityListPackageFormat.MaxRuleConditionCount)
        {
            throw new InvalidOperationException(
                "Too many security rule conditions to export.");
        }

        if (threatHashes.Length >
            SecurityListPackageFormat.MaxThreatHashCount)
        {
            throw new InvalidOperationException(
                "Too many threat hashes to export.");
        }

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

        EnsureEntrySize(
            rulesBytes,
            SecurityListPackageFormat.MaxRulesBytes,
            SecurityListPackageFormat.RulesEntryName);

        EnsureEntrySize(
            conditionsBytes,
            SecurityListPackageFormat.MaxRuleConditionsBytes,
            SecurityListPackageFormat.RuleConditionsEntryName);

        EnsureEntrySize(
            threatHashesBytes,
            SecurityListPackageFormat.MaxThreatHashesBytes,
            SecurityListPackageFormat.ThreatHashesEntryName);

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
                .ToString("N")[..8];

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

        var packageSha256 =
            await _fileHashService.ComputeSha256Async(
                destinationPath,
                cancellationToken);

        return new SecurityListExportResult(
            destinationPath,
            packageSha256,
            exportedAtUtc,
            ruleEntries.Length,
            conditionEntries.Length,
            threatHashEntries.Length);
    }

    public async Task<SecurityListPackageValidationResult> ValidateAsync(
        string packagePath,
        CancellationToken cancellationToken = default)
    {
        string? stagedPath =
            null;

        try
        {
            EnsureDirectories();

            stagedPath =
                await StagePackageAsync(
                    packagePath,
                    cancellationToken);

            var packageSha256 =
                NormalizeSha256(
                    await _fileHashService.ComputeSha256Async(
                        stagedPath,
                        cancellationToken));

            var package =
                await ReadPackageAsync(
                    stagedPath,
                    cancellationToken);

            return new SecurityListPackageValidationResult(
                true,
                null,
                packageSha256,
                package.Manifest);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new SecurityListPackageValidationResult(
                false,
                exception.Message,
                null,
                null);
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(
                    stagedPath))
            {
                TryDelete(
                    stagedPath);
            }
        }
    }

    public async Task<SecurityListImportResult> ImportAsync(
        string packagePath,
        SecurityListImportMode mode = SecurityListImportMode.Merge,
        CancellationToken cancellationToken = default)
    {
        if (mode !=
            SecurityListImportMode.Merge)
        {
            throw new NotSupportedException(
                $"Import mode is not supported: {mode}");
        }

        await _importGate.WaitAsync(
            cancellationToken);

        string? stagedPath =
            null;

        ArchivedPackageResult? archived =
            null;

        try
        {
            EnsureDirectories();

            var originalPath =
                Path.GetFullPath(
                    packagePath);

            stagedPath =
                await StagePackageAsync(
                    originalPath,
                    cancellationToken);

            var packageSha256 =
                NormalizeSha256(
                    await _fileHashService.ComputeSha256Async(
                        stagedPath,
                        cancellationToken));

            var existing =
                await _importHistoryRepository.GetByPackageSha256Async(
                    packageSha256,
                    cancellationToken);

            if (existing is not null)
            {
                var duplicateWarnings =
                    new List<string>
                    {
            "Этот пакет уже был импортирован ранее."
                    };

                if (!File.Exists(
                        existing.ArchivedPackagePath))
                {
                    duplicateWarnings.Add(
                        "Архивированная копия ранее импортированного пакета отсутствует.");
                }

                return new SecurityListImportResult(
                    originalPath,
                    packageSha256,
                    existing.ArchivedPackagePath,
                    existing.Mode,
                    existing.ImportedAtUtc,
                    existing.RuleCount,
                    existing.RuleConditionCount,
                    existing.ThreatHashCount,
                    true,
                    false,
                    false,
                    duplicateWarnings);
            }
            var package =
                await ReadPackageAsync(
                    stagedPath,
                    cancellationToken);

            var rules =
                BuildRules(
                    package);

            var threatHashes =
                BuildThreatHashes(
                    package);

            archived =
                await ArchiveStagedPackageAsync(
                    stagedPath,
                    packageSha256,
                    cancellationToken);

            stagedPath =
                null;

            var importedAtUtc =
                DateTimeOffset.UtcNow;

            var importRecord =
                new SecurityListImportRecord(
                    Guid.NewGuid(),
                    packageSha256,
                    Path.GetFileName(
                        originalPath),
                    archived.Path,
                    package.Manifest.PackageType,
                    package.Manifest.FormatVersion,
                    package.Manifest.ExportedAtUtc,
                    importedAtUtc,
                    mode,
                    rules.Length,
                    package.Conditions.Length,
                    threatHashes.Length);

            try
            {
                await _importStore.ImportAsync(
                    rules,
                    threatHashes,
                    mode,
                    importRecord,
                    cancellationToken);
            }
            catch
            {
                if (archived.Created)
                {
                    TryDelete(
                        archived.Path);
                }

                throw;
            }

            var warnings =
                new List<string>();

            var algorithmHealthy =
                await SynchronizeAlgorithmGuardAsync(
                    warnings,
                    cancellationToken);

            var transferHealthy =
                await SynchronizeTransferGuardAsync(
                    warnings,
                    cancellationToken);

            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.Core,
                    SecurityEventType.Audit,
                    warnings.Count ==
                    0
                        ? SecuritySeverity.Info
                        : SecuritySeverity.Medium,
                    "Security lists imported",
                    $"Package={Path.GetFileName(originalPath)}; PackageSha256={packageSha256}; Rules={rules.Length}; Conditions={package.Conditions.Length}; ThreatHashes={threatHashes.Length}; AlgorithmSync={algorithmHealthy}; TransferSync={transferHealthy}",
                    cancellationToken:
                        cancellationToken);
            }
            catch
            {
            }

            return new SecurityListImportResult(
                originalPath,
                packageSha256,
                archived.Path,
                mode,
                importedAtUtc,
                rules.Length,
                package.Conditions.Length,
                threatHashes.Length,
                false,
                algorithmHealthy,
                transferHealthy,
                warnings);
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(
                    stagedPath))
            {
                TryDelete(
                    stagedPath);
            }

            _importGate.Release();
        }
    }

    private async Task<bool> SynchronizeAlgorithmGuardAsync(
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        try
        {
            var result =
                await _algorithmSynchronizer.SynchronizeAsync(
                    cancellationToken);

            foreach (var warning in
                     result.Warnings)
            {
                warnings.Add(
                    $"AlgorithmGuard: {warning}");
            }

            return result.Healthy;
        }
        catch (Exception exception)
        {
            warnings.Add(
                $"AlgorithmGuard synchronization failed: {exception.Message}");

            return false;
        }
    }

    private async Task<bool> SynchronizeTransferGuardAsync(
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        try
        {
            var result =
                await _transferSynchronizer.SynchronizeAsync(
                    cancellationToken);

            foreach (var warning in
                     result.Warnings)
            {
                warnings.Add(
                    $"TransferGuard: {warning}");
            }

            return result.Healthy;
        }
        catch (Exception exception)
        {
            warnings.Add(
                $"TransferGuard synchronization failed: {exception.Message}");

            return false;
        }
    }

    private async Task<ParsedPackage> ReadPackageAsync(
        string packagePath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            packagePath);

        var fullPath =
            Path.GetFullPath(
                packagePath);

        if (!File.Exists(
                fullPath))
        {
            throw new FileNotFoundException(
                "Security list package was not found.",
                fullPath);
        }

        var fileInfo =
            new FileInfo(
                fullPath);

        if (fileInfo.Length <=
                0 ||
            fileInfo.Length >
                SecurityListPackageFormat.MaxPackageBytes)
        {
            throw new InvalidDataException(
                "Security list package size is invalid.");
        }

        await using var fileStream =
            new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize:
                    64 * 1024,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        using var archive =
            new ZipArchive(
                fileStream,
                ZipArchiveMode.Read,
                false);

        var entries =
            new Dictionary<string, ZipArchiveEntry>(
                StringComparer.Ordinal);

        foreach (var entry in
                 archive.Entries)
        {
            if (string.IsNullOrWhiteSpace(
                    entry.Name) ||
                !string.Equals(
                    entry.Name,
                    entry.FullName,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Package contains an invalid entry path.");
            }

            if (!entries.TryAdd(
                    entry.FullName,
                    entry))
            {
                throw new InvalidDataException(
                    $"Package contains duplicate entry: {entry.FullName}");
            }
        }

        var expectedNames =
            new[]
            {
                SecurityListPackageFormat.ManifestEntryName,
                SecurityListPackageFormat.RulesEntryName,
                SecurityListPackageFormat.RuleConditionsEntryName,
                SecurityListPackageFormat.ThreatHashesEntryName
            };

        if (entries.Count !=
                expectedNames.Length ||
            expectedNames.Any(
                name =>
                    !entries.ContainsKey(
                        name)))
        {
            throw new InvalidDataException(
                "Security list package has an unexpected structure.");
        }

        var manifestBytes =
            await ReadEntryAsync(
                entries[
                    SecurityListPackageFormat.ManifestEntryName],
                SecurityListPackageFormat.MaxManifestBytes,
                cancellationToken);

        var rulesBytes =
            await ReadEntryAsync(
                entries[
                    SecurityListPackageFormat.RulesEntryName],
                SecurityListPackageFormat.MaxRulesBytes,
                cancellationToken);

        var conditionsBytes =
            await ReadEntryAsync(
                entries[
                    SecurityListPackageFormat.RuleConditionsEntryName],
                SecurityListPackageFormat.MaxRuleConditionsBytes,
                cancellationToken);

        var threatHashesBytes =
            await ReadEntryAsync(
                entries[
                    SecurityListPackageFormat.ThreatHashesEntryName],
                SecurityListPackageFormat.MaxThreatHashesBytes,
                cancellationToken);

        var manifest =
            Deserialize<SecurityListPackageManifest>(
                manifestBytes);

        ValidateManifest(
            manifest,
            rulesBytes,
            conditionsBytes,
            threatHashesBytes);

        var rules =
            Deserialize<SecurityListRuleEntry[]>(
                rulesBytes);

        var conditions =
            Deserialize<SecurityListRuleConditionEntry[]>(
                conditionsBytes);

        var threatHashes =
            Deserialize<SecurityListThreatHashEntry[]>(
                threatHashesBytes);

        ValidateContents(
            manifest,
            rules,
            conditions,
            threatHashes);

        return new ParsedPackage(
            manifest,
            rules,
            conditions,
            threatHashes);
    }

    private static void ValidateManifest(
        SecurityListPackageManifest manifest,
        byte[] rules,
        byte[] conditions,
        byte[] threatHashes)
    {
        if (!string.Equals(
                manifest.PackageType,
                SecurityListPackageFormat.PackageType,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Package type is not supported.");
        }

        if (manifest.FormatVersion <
            SecurityListPackageFormat.CurrentVersion)
        {
            throw new InvalidDataException(
                $"Older package format is not accepted: {manifest.FormatVersion}");
        }

        if (manifest.FormatVersion >
            SecurityListPackageFormat.CurrentVersion)
        {
            throw new InvalidDataException(
                $"Newer package format is not supported: {manifest.FormatVersion}");
        }

        if (manifest.RuleCount <
                0 ||
            manifest.RuleCount >
                SecurityListPackageFormat.MaxRuleCount)
        {
            throw new InvalidDataException(
                "Manifest rule count is invalid.");
        }

        if (manifest.RuleConditionCount <
                0 ||
            manifest.RuleConditionCount >
                SecurityListPackageFormat.MaxRuleConditionCount)
        {
            throw new InvalidDataException(
                "Manifest rule condition count is invalid.");
        }

        if (manifest.ThreatHashCount <
                0 ||
            manifest.ThreatHashCount >
                SecurityListPackageFormat.MaxThreatHashCount)
        {
            throw new InvalidDataException(
                "Manifest threat hash count is invalid.");
        }

        VerifySha256(
            manifest.RulesSha256,
            rules,
            SecurityListPackageFormat.RulesEntryName);

        VerifySha256(
            manifest.RuleConditionsSha256,
            conditions,
            SecurityListPackageFormat.RuleConditionsEntryName);

        VerifySha256(
            manifest.ThreatHashesSha256,
            threatHashes,
            SecurityListPackageFormat.ThreatHashesEntryName);
    }

    private static void ValidateContents(
        SecurityListPackageManifest manifest,
        SecurityListRuleEntry[] rules,
        SecurityListRuleConditionEntry[] conditions,
        SecurityListThreatHashEntry[] threatHashes)
    {
        if (rules.Length !=
            manifest.RuleCount)
        {
            throw new InvalidDataException(
                "Rule count does not match manifest.");
        }

        if (conditions.Length !=
            manifest.RuleConditionCount)
        {
            throw new InvalidDataException(
                "Rule condition count does not match manifest.");
        }

        if (threatHashes.Length !=
            manifest.ThreatHashCount)
        {
            throw new InvalidDataException(
                "Threat hash count does not match manifest.");
        }

        var ruleIds =
            new HashSet<Guid>();

        foreach (var rule in
                 rules)
        {
            if (rule.Id ==
                Guid.Empty)
            {
                throw new InvalidDataException(
                    "Rule ID cannot be empty.");
            }

            if (!ruleIds.Add(
                    rule.Id))
            {
                throw new InvalidDataException(
                    $"Duplicate rule ID: {rule.Id}");
            }

            if (string.IsNullOrWhiteSpace(
                    rule.Name))
            {
                throw new InvalidDataException(
                    $"Rule name is missing: {rule.Id}");
            }

            if (string.IsNullOrWhiteSpace(
                    rule.Value))
            {
                throw new InvalidDataException(
                    $"Rule value is missing: {rule.Id}");
            }

            if (!Enum.IsDefined(
                    rule.Module) ||
                !Enum.IsDefined(
                    rule.Decision) ||
                !Enum.IsDefined(
                    rule.Scope))
            {
                throw new InvalidDataException(
                    $"Rule contains an unsupported enum value: {rule.Id}");
            }
        }

        foreach (var group in
                 conditions.GroupBy(
                     condition =>
                         condition.RuleId))
        {
            if (!ruleIds.Contains(
                    group.Key))
            {
                throw new InvalidDataException(
                    $"Condition references unknown rule: {group.Key}");
            }

            var ordered =
                group
                    .OrderBy(
                        condition =>
                            condition.Position)
                    .ToArray();

            for (var index = 0;
                 index < ordered.Length;
                 index++)
            {
                var condition =
                    ordered[index];

                if (condition.Position !=
                    index)
                {
                    throw new InvalidDataException(
                        $"Rule condition positions are invalid: {group.Key}");
                }

                if (!Enum.IsDefined(
                        condition.Scope))
                {
                    throw new InvalidDataException(
                        $"Rule condition scope is invalid: {group.Key}");
                }

                if (string.IsNullOrWhiteSpace(
                        condition.Value))
                {
                    throw new InvalidDataException(
                        $"Rule condition value is missing: {group.Key}");
                }
            }
        }

        var hashes =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        foreach (var threatHash in
                 threatHashes)
        {
            var sha256 =
                NormalizeSha256(
                    threatHash.Sha256);

            if (!hashes.Add(
                    sha256))
            {
                throw new InvalidDataException(
                    $"Duplicate threat hash: {sha256}");
            }

            if (string.IsNullOrWhiteSpace(
                    threatHash.Source))
            {
                throw new InvalidDataException(
                    $"Threat hash source is missing: {sha256}");
            }
        }
    }

    private static async Task<byte[]> ReadEntryAsync(
        ZipArchiveEntry entry,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        if (entry.Length <
                0 ||
            entry.Length >
                maxBytes)
        {
            throw new InvalidDataException(
                $"Package entry is too large: {entry.FullName}");
        }

        await using var stream =
            entry.Open();

        using var memory =
            new MemoryStream();

        var buffer =
            new byte[64 * 1024];

        long total =
            0;

        while (true)
        {
            var read =
                await stream.ReadAsync(
                    buffer,
                    cancellationToken);

            if (read ==
                0)
            {
                break;
            }

            total +=
                read;

            if (total >
                maxBytes)
            {
                throw new InvalidDataException(
                    $"Package entry exceeds size limit: {entry.FullName}");
            }

            await memory.WriteAsync(
                buffer.AsMemory(
                    0,
                    read),
                cancellationToken);
        }

        return memory.ToArray();
    }

    private static void VerifySha256(
        string expected,
        byte[] content,
        string entryName)
    {
        var actual =
            ComputeSha256(
                content);

        if (!string.Equals(
                NormalizeSha256(
                    expected),
                actual,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Package checksum mismatch: {entryName}");
        }
    }

    private static string NormalizeSha256(
        string sha256)
    {
        if (string.IsNullOrWhiteSpace(
                sha256))
        {
            throw new InvalidDataException(
                "SHA-256 value is missing.");
        }

        var normalized =
            sha256
                .Trim()
                .ToUpperInvariant();

        if (normalized.Length !=
                64 ||
            normalized.Any(
                character =>
                    !Uri.IsHexDigit(
                        character)))
        {
            throw new InvalidDataException(
                "SHA-256 value is invalid.");
        }

        return normalized;
    }

    private static byte[] Serialize<T>(
        T value)
    {
        return JsonSerializer.SerializeToUtf8Bytes(
            value,
            JsonOptions);
    }

    private static T Deserialize<T>(
        byte[] content)
    {
        return JsonSerializer.Deserialize<T>(
                   content,
                   JsonOptions)
               ??
               throw new InvalidDataException(
                   "Package contains invalid JSON.");
    }

    private static string ComputeSha256(
        byte[] value)
    {
        return Convert.ToHexString(
            SHA256.HashData(
                value));
    }

    private static void EnsureEntrySize(
        byte[] content,
        long maximum,
        string entryName)
    {
        if (content.LongLength >
            maximum)
        {
            throw new InvalidOperationException(
                $"Export entry exceeds size limit: {entryName}");
        }
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

    private void EnsureDirectories()
    {
        Directory.CreateDirectory(
            _paths.ListsDirectory);

        Directory.CreateDirectory(
            _paths.ListExportsDirectory);

        Directory.CreateDirectory(
            _paths.ListImportsDirectory);

        Directory.CreateDirectory(
            _paths.TempDirectory);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options =
            new JsonSerializerOptions
            {
                PropertyNamingPolicy =
                    JsonNamingPolicy.CamelCase,

                PropertyNameCaseInsensitive =
                    true,

                WriteIndented =
                    true
            };

        options.Converters.Add(
            new JsonStringEnumConverter(
                namingPolicy:
                    null,
                allowIntegerValues:
                    false));

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

    private sealed record ParsedPackage(
        SecurityListPackageManifest Manifest,
        SecurityListRuleEntry[] Rules,
        SecurityListRuleConditionEntry[] Conditions,
        SecurityListThreatHashEntry[] ThreatHashes);

    private async Task<string> StagePackageAsync(
        string packagePath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            packagePath);

        var sourcePath =
            Path.GetFullPath(
                packagePath);

        if (!File.Exists(
                sourcePath))
        {
            throw new FileNotFoundException(
                "Security list package was not found.",
                sourcePath);
        }

        var info =
            new FileInfo(
                sourcePath);

        if (info.Length <=
                0 ||
            info.Length >
                SecurityListPackageFormat.MaxPackageBytes)
        {
            throw new InvalidDataException(
                "Security list package size is invalid.");
        }

        var stagedPath =
            Path.Combine(
                _paths.TempDirectory,
                $"SecurityGuardLists_Import_{Guid.NewGuid():N}.tmp");

        await using var source =
            new FileStream(
                sourcePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize:
                    64 * 1024,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        await using var destination =
            new FileStream(
                stagedPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize:
                    64 * 1024,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        var buffer =
            new byte[
                64 * 1024];

        long total =
            0;

        while (true)
        {
            var read =
                await source.ReadAsync(
                    buffer,
                    cancellationToken);

            if (read ==
                0)
            {
                break;
            }

            total +=
                read;

            if (total >
                SecurityListPackageFormat.MaxPackageBytes)
            {
                throw new InvalidDataException(
                    "Security list package exceeds the allowed size.");
            }

            await destination.WriteAsync(
                buffer.AsMemory(
                    0,
                    read),
                cancellationToken);
        }

        await destination.FlushAsync(
            cancellationToken);

        return stagedPath;
    }

    private async Task<ArchivedPackageResult> ArchiveStagedPackageAsync(
        string stagedPath,
        string packageSha256,
        CancellationToken cancellationToken)
    {
        packageSha256 =
            NormalizeSha256(
                packageSha256);

        var archivedPath =
            Path.Combine(
                _paths.ListImportsDirectory,
                $"SecurityGuardLists_Imported_{packageSha256}.zip");

        if (File.Exists(
                archivedPath))
        {
            var existingHash =
                NormalizeSha256(
                    await _fileHashService.ComputeSha256Async(
                        archivedPath,
                        cancellationToken));

            if (!string.Equals(
                    existingHash,
                    packageSha256,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Existing archived package has an unexpected fingerprint.");
            }

            TryDelete(
                stagedPath);

            return new ArchivedPackageResult(
                archivedPath,
                false);
        }

        File.Move(
            stagedPath,
            archivedPath,
            false);

        return new ArchivedPackageResult(
            archivedPath,
            true);
    }

    private sealed record ArchivedPackageResult(
        string Path,
        bool Created);
    
    private static SecurityRule[] BuildRules(
        ParsedPackage package)
    {
        var conditionsByRule =
            package.Conditions
                .GroupBy(
                    condition =>
                        condition.RuleId)
                .ToDictionary(
                    group =>
                        group.Key,
                    group =>
                        (IReadOnlyList<SecurityRuleCondition>)group
                            .OrderBy(
                                condition =>
                                    condition.Position)
                            .Select(
                                condition =>
                                    new SecurityRuleCondition(
                                        condition.Scope,
                                        condition.Value))
                            .ToArray());

        return package.Rules
            .Select(
                rule =>
                    new SecurityRule(
                        rule.Id,
                        rule.Name,
                        rule.Module,
                        rule.Decision,
                        rule.Scope,
                        rule.Value,
                        rule.Enabled,
                        rule.Priority,
                        rule.CreatedAtUtc,
                        rule.ExpiresAtUtc,
                        conditionsByRule.TryGetValue(
                            rule.Id,
                            out var conditions)
                            ? conditions
                            : []))
            .ToArray();
    }

    private static ThreatHashEntry[] BuildThreatHashes(
        ParsedPackage package)
    {
        return package.ThreatHashes
            .Select(
                entry =>
                    new ThreatHashEntry(
                        NormalizeSha256(
                            entry.Sha256),
                        entry.Source,
                        entry.Description,
                        entry.Enabled,
                        entry.CreatedAtUtc,
                        entry.UpdatedAtUtc))
            .ToArray();
    }
}