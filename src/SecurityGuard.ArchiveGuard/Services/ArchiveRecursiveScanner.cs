using System.Buffers;
using System.Security.Cryptography;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveRecursiveScanner
    : IArchiveRecursiveScanner
{
    private readonly ArchiveGuardOptions _options;
    private readonly IReadOnlyDictionary<
        DetectedFileType,
        IArchiveFormatHandler> _handlers;
    private readonly ZipEntryPathInspector _pathInspector;
    private readonly IFileTypeDetector _fileTypeDetector;
    private readonly IReadOnlyList<IArchiveFileAnalyzer> _analyzers;
    private readonly IArchiveTemporarySpoolService _spoolService;

    public ArchiveRecursiveScanner(
        ArchiveGuardOptions options,
        IEnumerable<IArchiveFormatHandler> handlers,
        ZipEntryPathInspector pathInspector,
        IFileTypeDetector fileTypeDetector,
        IEnumerable<IArchiveFileAnalyzer> analyzers,
        IArchiveTemporarySpoolService spoolService)
    {
        _options =
            options;

        _handlers =
            handlers.ToDictionary(
                handler =>
                    handler.FileType);

        _pathInspector =
            pathInspector;

        _fileTypeDetector =
            fileTypeDetector;

        _analyzers =
            analyzers.ToArray();

        _spoolService =
            spoolService;
    }

    public bool Supports(
        DetectedFileType fileType)
    {
        return _handlers.ContainsKey(
            fileType);
    }

    public async Task<ArchiveRecursiveScanResult> ScanAsync(
        string filePath,
        DetectedFileType fileType,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        var context =
            new RecursiveContext(
                new ArchiveScanBudget(
                    _options.MaxRecursiveExpandedBytes,
                    _options.MaxRecursiveEntryCount));

        await using var stream =
            new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize:
                    64 * 1024,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        await ScanArchiveAsync(
            stream,
            fileType,
            Path.GetFileName(
                filePath),
            0,
            context,
            cancellationToken);

        return new ArchiveRecursiveScanResult(
            context.Verdict,
            context.Findings,
            context.Budget.ExpandedBytesRead,
            context.Budget.EntriesInspected,
            context.ArchivesInspected,
            context.BudgetExhausted);
    }

    private async Task ScanArchiveAsync(
        Stream stream,
        DetectedFileType fileType,
        string logicalPath,
        int depth,
        RecursiveContext context,
        CancellationToken cancellationToken)
    {
        if (depth >
            _options.MaxArchiveDepth)
        {
            AddFinding(
                context,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ArchiveDepthExceeded,
                    ScanVerdict.Unknown,
                    SecuritySeverity.High,
                    "Archive recursion depth exceeded",
                    $"Depth={depth}; Limit={_options.MaxArchiveDepth}",
                    logicalPath));

            return;
        }

        if (!_handlers.TryGetValue(
                fileType,
                out var handler))
        {
            AddFinding(
                context,
                new ArchiveScanFinding(
                    ArchiveFindingKind.UnsupportedArchiveFormat,
                    ScanVerdict.Unknown,
                    SecuritySeverity.Medium,
                    "Unsupported archive format",
                    $"DetectedType={fileType}",
                    logicalPath));

            return;
        }

        if (handler.RequiresSeekableInput &&
            !stream.CanSeek)
        {
            AddFinding(
                context,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ArchiveInvalidStructure,
                    ScanVerdict.Error,
                    SecuritySeverity.High,
                    "Archive handler requires a seekable stream",
                    $"DetectedType={fileType}",
                    logicalPath));

            return;
        }

        context.ArchivesInspected++;

        if (stream.CanSeek)
        {
            stream.Position =
                0;
        }

        var seenPaths =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        var localEntryCount =
            0;

        long localExpandedBytes =
            0;

        try
        {
            await foreach (
                var entry in
                handler.ReadEntriesAsync(
                    stream,
                    logicalPath,
                    cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();

                localEntryCount++;

                if (localEntryCount >
                    GetEntryCountLimit(
                        fileType))
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetEntryCountFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.High,
                            "Archive entry count limit exceeded",
                            $"Entries={localEntryCount}; Limit={GetEntryCountLimit(fileType)}",
                            logicalPath));

                    return;
                }

                if (!context.Budget.TryRegisterEntry())
                {
                    context.BudgetExhausted =
                        true;

                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            ArchiveFindingKind.RecursiveEntryCountExceeded,
                            ScanVerdict.Unknown,
                            SecuritySeverity.High,
                            "Recursive archive entry limit exceeded",
                            $"Limit={context.Budget.MaxEntries}",
                            logicalPath));

                    return;
                }

                if (entry.ExpandedLength is > 0)
                {
                    localExpandedBytes =
                        SaturatingAdd(
                            localExpandedBytes,
                            entry.ExpandedLength.Value);

                    if (localExpandedBytes >
                        GetExpandedSizeLimit(
                            fileType))
                    {
                        AddFinding(
                            context,
                            new ArchiveScanFinding(
                                GetExpandedSizeFinding(
                                    fileType),
                                ScanVerdict.Suspicious,
                                SecuritySeverity.Critical,
                                "Archive expanded size limit exceeded",
                                $"ExpandedBytes={localExpandedBytes}; Limit={GetExpandedSizeLimit(fileType)}",
                                logicalPath));

                        return;
                    }
                }

                var path =
                    _pathInspector.Inspect(
                        entry.FullName);

                var unsafePath =
                    false;

                if (path.IsAbsolute)
                {
                    unsafePath =
                        true;

                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetAbsolutePathFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.High,
                            "Archive entry contains an absolute path",
                            $"Entry={entry.FullName}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));
                }

                if (path.HasTraversal)
                {
                    unsafePath =
                        true;

                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetTraversalFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.Critical,
                            "Archive entry contains path traversal",
                            $"Entry={entry.FullName}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));
                }

                if (path.HasAlternateDataStream)
                {
                    unsafePath =
                        true;

                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetAdsFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.High,
                            "Archive entry contains a Windows alternate data stream path",
                            $"Entry={entry.FullName}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));
                }

                if (!string.IsNullOrWhiteSpace(
                        path.NormalizedPath) &&
                    !seenPaths.Add(
                        path.NormalizedPath))
                {
                    unsafePath =
                        true;

                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetDuplicateFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.Medium,
                            "Archive contains duplicate normalized paths",
                            $"Entry={entry.FullName}; Normalized={path.NormalizedPath}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));
                }

                if (entry.IsEncrypted)
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetEncryptedFinding(
                                fileType),
                            ScanVerdict.Unknown,
                            SecuritySeverity.Medium,
                            "Archive entry is encrypted",
                            $"Entry={entry.FullName}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));

                    continue;
                }

                if (entry.IsLink)
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            ArchiveFindingKind.ArchiveLinkEntry,
                            ScanVerdict.Unknown,
                            SecuritySeverity.Medium,
                            "Archive entry is a filesystem link",
                            $"Entry={entry.FullName}; Target={entry.LinkTarget ?? "Unknown"}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));

                    continue;
                }

                if (entry.IsDirectory ||
                    unsafePath)
                {
                    continue;
                }

                if (entry.ExpandedLength >
                    GetEntrySizeLimit(
                        fileType))
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetEntrySizeFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.High,
                            "Archive entry size limit exceeded",
                            $"Entry={entry.FullName}; Size={entry.ExpandedLength}; Limit={GetEntrySizeLimit(fileType)}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));

                    continue;
                }

                var ratio =
                    CalculateCompressionRatio(
                        entry.ExpandedLength,
                        entry.CompressedLength);

                if (ratio is not null &&
                    ratio >
                    GetCompressionRatioLimit(
                        fileType))
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            GetCompressionRatioFinding(
                                fileType),
                            ScanVerdict.Suspicious,
                            SecuritySeverity.Critical,
                            "Suspicious archive compression ratio",
                            $"Entry={entry.FullName}; Ratio={ratio:F2}; Limit={GetCompressionRatioLimit(fileType):F2}",
                            BuildLogicalPath(
                                logicalPath,
                                entry.FullName)));

                    continue;
                }

                await InspectEntryAsync(
                    entry,
                    logicalPath,
                    depth,
                    context,
                    cancellationToken);

                if (context.BudgetExhausted)
                {
                    return;
                }
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            AddFinding(
                context,
                new ArchiveScanFinding(
                    GetInvalidStructureFinding(
                        fileType),
                    ScanVerdict.Error,
                    SecuritySeverity.High,
                    "Archive structure could not be read",
                    $"{exception.GetType().Name}: {exception.Message}",
                    logicalPath));
        }
    }

    private async Task InspectEntryAsync(
        ArchiveFormatEntry entry,
        string parentPath,
        int depth,
        RecursiveContext context,
        CancellationToken cancellationToken)
    {
        var logicalPath =
            BuildLogicalPath(
                parentPath,
                entry.FullName);

        ArchiveTemporarySpool? spool =
            null;

        var buffer =
            ArrayPool<byte>.Shared.Rent(
                _options.EntryReadBufferBytes);

        var header =
            new byte[
                _options.HeaderBytesToRead];

        var headerLength =
            0;

        long actualBytes =
            0;

        var detectedType =
            DetectedFileType.Unknown;

        var typeResolved =
            false;

        var spoolStarted =
            false;

        try
        {
            await using var entryStream =
                await entry.OpenAsync(
                    cancellationToken);

            using var hash =
                IncrementalHash.CreateHash(
                    HashAlgorithmName.SHA256);

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var requestSize =
                    buffer.Length;

                if (!typeResolved &&
                    headerLength <
                    header.Length)
                {
                    requestSize =
                        Math.Min(
                            requestSize,
                            header.Length -
                            headerLength);
                }

                var remainingEntry =
                    Math.Max(
                        0,
                        _options.MaxArchiveEntryBytes -
                        actualBytes);

                var remainingBudget =
                    context.Budget.RemainingBytes;

                requestSize =
                    (int)Math.Min(
                        requestSize,
                        Math.Min(
                            remainingEntry + 1,
                            remainingBudget + 1));

                if (requestSize <= 0)
                {
                    requestSize =
                        1;
                }

                var read =
                    await entryStream.ReadAsync(
                        buffer.AsMemory(
                            0,
                            requestSize),
                        cancellationToken);

                if (read == 0)
                {
                    break;
                }

                if (!context.Budget.TryConsume(
                        read))
                {
                    context.BudgetExhausted =
                        true;

                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            ArchiveFindingKind.ArchiveReadBudgetExceeded,
                            ScanVerdict.Unknown,
                            SecuritySeverity.High,
                            "Recursive archive read budget exceeded",
                            $"Limit={context.Budget.MaxExpandedBytes}",
                            logicalPath));

                    return;
                }

                actualBytes +=
                    read;

                if (actualBytes >
                    _options.MaxArchiveEntryBytes)
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            ArchiveFindingKind.ArchiveEntryActualSizeExceeded,
                            ScanVerdict.Suspicious,
                            SecuritySeverity.Critical,
                            "Archive entry exceeded actual read-size limit",
                            $"ReadBytes={actualBytes}; Limit={_options.MaxArchiveEntryBytes}",
                            logicalPath));

                    return;
                }

                hash.AppendData(
                    buffer.AsSpan(
                        0,
                        read));

                if (headerLength <
                    header.Length)
                {
                    var copy =
                        Math.Min(
                            read,
                            header.Length -
                            headerLength);

                    buffer.AsSpan(
                            0,
                            copy)
                        .CopyTo(
                            header.AsSpan(
                                headerLength));

                    headerLength +=
                        copy;
                }

                if (!typeResolved)
                {
                    detectedType =
                        _fileTypeDetector.Detect(
                            header.AsSpan(
                                0,
                                headerLength));

                    if (detectedType !=
                            DetectedFileType.Unknown ||
                        headerLength ==
                            header.Length)
                    {
                        typeResolved =
                            true;
                    }

                    if (detectedType !=
                            DetectedFileType.Unknown &&
                        Supports(
                            detectedType))
                    {
                        if (depth >=
                            _options.MaxArchiveDepth)
                        {
                            AddFinding(
                                context,
                                new ArchiveScanFinding(
                                    ArchiveFindingKind.ArchiveDepthExceeded,
                                    ScanVerdict.Unknown,
                                    SecuritySeverity.High,
                                    "Nested archive recursion depth limit reached",
                                    $"Depth={depth + 1}; Limit={_options.MaxArchiveDepth}",
                                    logicalPath));
                        }
                        else if (entry.ExpandedLength >
                                 _options.MaxNestedArchiveBytes)
                        {
                            AddFinding(
                                context,
                                new ArchiveScanFinding(
                                    ArchiveFindingKind.NestedArchiveSizeExceeded,
                                    ScanVerdict.Unknown,
                                    SecuritySeverity.High,
                                    "Nested archive exceeds spool size limit",
                                    $"Size={entry.ExpandedLength}; Limit={_options.MaxNestedArchiveBytes}",
                                    logicalPath));
                        }
                        else
                        {
                            spool =
                                await _spoolService.CreateAsync(
                                    cancellationToken);

                            await spool.Stream.WriteAsync(
                                header.AsMemory(
                                    0,
                                    headerLength),
                                cancellationToken);

                            spoolStarted =
                                true;
                        }
                    }
                }
                else if (spool is not null &&
                         spoolStarted)
                {
                    if (actualBytes >
                        _options.MaxNestedArchiveBytes)
                    {
                        await spool.DisposeAsync();

                        spool =
                            null;

                        AddFinding(
                            context,
                            new ArchiveScanFinding(
                                ArchiveFindingKind.NestedArchiveSizeExceeded,
                                ScanVerdict.Unknown,
                                SecuritySeverity.High,
                                "Nested archive exceeded actual spool size limit",
                                $"ReadBytes={actualBytes}; Limit={_options.MaxNestedArchiveBytes}",
                                logicalPath));
                    }
                    else
                    {
                        await spool.Stream.WriteAsync(
                            buffer.AsMemory(
                                0,
                                read),
                            cancellationToken);
                    }
                }
            }

            var digest =
                Convert.ToHexString(
                    hash.GetHashAndReset());

            var fileName =
                GetEntryFileName(
                    entry.FullName);

            var metadata =
                new ArchiveFileMetadata(
                    logicalPath,
                    fileName,
                    Path.GetExtension(
                        fileName),
                    actualBytes,
                    entry.LastWriteAtUtc ??
                    DateTimeOffset.UnixEpoch,
                    digest,
                    header[..headerLength],
                    detectedType);

            await AnalyzeEntryMetadataAsync(
                metadata,
                logicalPath,
                context,
                cancellationToken);

            if (!Supports(
                    detectedType) ||
                spool is null ||
                depth >=
                    _options.MaxArchiveDepth)
            {
                return;
            }

            await spool.Stream.FlushAsync(
                cancellationToken);

            spool.Stream.Position =
                0;

            await ScanArchiveAsync(
                spool.Stream,
                detectedType,
                logicalPath,
                depth + 1,
                context,
                cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            AddFinding(
                context,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ArchiveEntryReadFailure,
                    ScanVerdict.Error,
                    SecuritySeverity.High,
                    "Unable to inspect archive entry",
                    $"{exception.GetType().Name}: {exception.Message}",
                    logicalPath));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(
                buffer);

            if (spool is not null)
            {
                await spool.DisposeAsync();
            }
        }
    }

    private async Task AnalyzeEntryMetadataAsync(
        ArchiveFileMetadata metadata,
        string logicalPath,
        RecursiveContext context,
        CancellationToken cancellationToken)
    {
        foreach (var analyzer in
                 _analyzers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var findings =
                    await analyzer.AnalyzeAsync(
                        metadata,
                        cancellationToken);

                foreach (var finding in
                         findings)
                {
                    AddFinding(
                        context,
                        finding with
                        {
                            EntryPath =
                                logicalPath
                        });
                }
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                AddFinding(
                    context,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.AnalyzerFailure,
                        ScanVerdict.Error,
                        SecuritySeverity.High,
                        $"Analyzer failed: {analyzer.GetType().Name}",
                        exception.Message,
                        logicalPath));
            }
        }
    }

    private int GetEntryCountLimit(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? _options.MaxZipEntryCount
            : _options.MaxArchiveEntryCount;
    }

    private long GetExpandedSizeLimit(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? _options.MaxZipExpandedBytes
            : _options.MaxArchiveExpandedBytes;
    }

    private long GetEntrySizeLimit(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? _options.MaxZipEntryBytes
            : _options.MaxArchiveEntryBytes;
    }

    private double GetCompressionRatioLimit(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? _options.MaxZipCompressionRatio
            : _options.MaxArchiveCompressionRatio;
    }

    private static ArchiveFindingKind GetEntryCountFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipEntryCountExceeded
            : ArchiveFindingKind.ArchiveEntryCountExceeded;
    }

    private static ArchiveFindingKind GetExpandedSizeFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipExpandedSizeExceeded
            : ArchiveFindingKind.ArchiveExpandedSizeExceeded;
    }

    private static ArchiveFindingKind GetEntrySizeFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipEntrySizeExceeded
            : ArchiveFindingKind.ArchiveEntrySizeExceeded;
    }

    private static ArchiveFindingKind GetCompressionRatioFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipCompressionRatioExceeded
            : ArchiveFindingKind.ArchiveCompressionRatioExceeded;
    }

    private static ArchiveFindingKind GetTraversalFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipPathTraversal
            : ArchiveFindingKind.ArchivePathTraversal;
    }

    private static ArchiveFindingKind GetAbsolutePathFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipAbsolutePath
            : ArchiveFindingKind.ArchiveAbsolutePath;
    }

    private static ArchiveFindingKind GetDuplicateFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipDuplicatePath
            : ArchiveFindingKind.ArchiveDuplicatePath;
    }

    private static ArchiveFindingKind GetEncryptedFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipEncryptedEntry
            : ArchiveFindingKind.ArchiveEncryptedEntry;
    }

    private static ArchiveFindingKind GetAdsFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipAlternateDataStreamPath
            : ArchiveFindingKind.ArchiveAlternateDataStreamPath;
    }

    private static ArchiveFindingKind GetInvalidStructureFinding(
        DetectedFileType type)
    {
        return type ==
               DetectedFileType.Zip
            ? ArchiveFindingKind.ZipInvalidStructure
            : ArchiveFindingKind.ArchiveInvalidStructure;
    }

    private void AddFinding(
        RecursiveContext context,
        ArchiveScanFinding finding)
    {
        context.Verdict =
            SelectHigherVerdict(
                context.Verdict,
                finding.Verdict);

        if (context.Findings.Count >=
            _options.MaxArchiveFindings)
        {
            return;
        }

        context.Findings.Add(
            finding);
    }

    private static ScanVerdict SelectHigherVerdict(
        ScanVerdict current,
        ScanVerdict candidate)
    {
        return GetVerdictRank(
                   candidate) >
               GetVerdictRank(
                   current)
            ? candidate
            : current;
    }

    private static int GetVerdictRank(
        ScanVerdict verdict)
    {
        return verdict switch
        {
            ScanVerdict.Malicious =>
                4,

            ScanVerdict.Error =>
                3,

            ScanVerdict.Suspicious =>
                2,

            ScanVerdict.Unknown =>
                1,

            _ =>
                0
        };
    }

    private static double? CalculateCompressionRatio(
        long? expanded,
        long? compressed)
    {
        if (expanded is null ||
            compressed is null)
        {
            return null;
        }

        if (expanded <= 0)
        {
            return 1.0;
        }

        if (compressed <= 0)
        {
            return double.PositiveInfinity;
        }

        return (double)expanded /
               compressed;
    }

    private static long SaturatingAdd(
        long current,
        long value)
    {
        if (value <= 0)
        {
            return current;
        }

        if (current >
            long.MaxValue -
            value)
        {
            return long.MaxValue;
        }

        return current +
               value;
    }

    private static string BuildLogicalPath(
        string parent,
        string entry)
    {
        return
            $"{parent}!/{entry.Replace('\\', '/')}";
    }

    private static string GetEntryFileName(
        string fullName)
    {
        var normalized =
            fullName.Replace(
                '\\',
                '/');

        var index =
            normalized.LastIndexOf(
                '/');

        return index >= 0
            ? normalized[(index + 1)..]
            : normalized;
    }

    private sealed class RecursiveContext
    {
        public RecursiveContext(
            ArchiveScanBudget budget)
        {
            Budget =
                budget;
        }

        public ArchiveScanBudget Budget { get; }

        public List<ArchiveScanFinding> Findings { get; } =
            [];

        public ScanVerdict Verdict { get; set; } =
            ScanVerdict.Clean;

        public int ArchivesInspected { get; set; }

        public bool BudgetExhausted { get; set; }
    }
}