using System.Buffers;
using System.IO.Compression;
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
    private readonly IZipSafetyAnalyzer _zipSafetyAnalyzer;
    private readonly ZipEntryPathInspector _pathInspector;
    private readonly IFileTypeDetector _fileTypeDetector;
    private readonly IReadOnlyList<IArchiveFileAnalyzer> _analyzers;
    private readonly IArchiveTemporarySpoolService _spoolService;

    public ArchiveRecursiveScanner(
        ArchiveGuardOptions options,
        IZipSafetyAnalyzer zipSafetyAnalyzer,
        ZipEntryPathInspector pathInspector,
        IFileTypeDetector fileTypeDetector,
        IEnumerable<IArchiveFileAnalyzer> analyzers,
        IArchiveTemporarySpoolService spoolService)
    {
        _options =
            options;

        _zipSafetyAnalyzer =
            zipSafetyAnalyzer;

        _pathInspector =
            pathInspector;

        _fileTypeDetector =
            fileTypeDetector;

        _analyzers =
            analyzers.ToArray();

        _spoolService =
            spoolService;
    }

    public async Task<ArchiveRecursiveScanResult> ScanZipAsync(
        string filePath,
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

        await ScanZipStreamAsync(
            stream,
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

    private async Task ScanZipStreamAsync(
        Stream stream,
        string logicalPath,
        int depth,
        RecursiveContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

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

        context.ArchivesInspected++;

        stream.Position =
            0;

        var safety =
            await _zipSafetyAnalyzer.AnalyzeAsync(
                stream,
                cancellationToken);

        AddFindings(
            context,
            safety.Findings,
            logicalPath);

        if (!safety.IsValidStructure)
        {
            return;
        }

        if (safety.EntryCount >
                _options.MaxZipEntryCount ||
            safety.TotalExpandedBytes >
                _options.MaxZipExpandedBytes)
        {
            return;
        }

        stream.Position =
            0;

        using var archive =
            new ZipArchive(
                stream,
                ZipArchiveMode.Read,
                leaveOpen:
                    true);

        var seenPaths =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        foreach (var entry in
                 archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (context.BudgetExhausted)
            {
                return;
            }

            if (string.IsNullOrEmpty(
                    entry.Name))
            {
                continue;
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
                        $"Limit={_options.MaxRecursiveEntryCount}",
                        logicalPath));

                return;
            }

            var path =
                _pathInspector.Inspect(
                    entry.FullName);

            if (path.IsAbsolute ||
                path.HasTraversal ||
                path.HasAlternateDataStream)
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(
                    path.NormalizedPath) &&
                !seenPaths.Add(
                    path.NormalizedPath))
            {
                continue;
            }

            if (entry.IsEncrypted)
            {
                continue;
            }

            if (entry.Length >
                _options.MaxZipEntryBytes)
            {
                continue;
            }

            var ratio =
                CalculateCompressionRatio(
                    entry.Length,
                    entry.CompressedLength);

            if (ratio >
                _options.MaxZipCompressionRatio)
            {
                continue;
            }

            var entryPath =
                BuildLogicalPath(
                    logicalPath,
                    entry.FullName);

            await InspectEntryAsync(
                entry,
                entryPath,
                depth,
                context,
                cancellationToken);
        }
    }

    private async Task InspectEntryAsync(
        ZipArchiveEntry entry,
        string logicalPath,
        int depth,
        RecursiveContext context,
        CancellationToken cancellationToken)
    {
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

        var nestedSizeFindingAdded =
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

                var budgetRemaining =
                    context.Budget.RemainingBytes;

                var entryRemaining =
                    Math.Max(
                        0,
                        _options.MaxZipEntryBytes -
                        actualBytes);

                var requested =
                    (int)Math.Min(
                        buffer.Length,
                        Math.Min(
                            budgetRemaining + 1,
                            entryRemaining + 1));

                if (requested <= 0)
                {
                    requested =
                        1;
                }

                var read =
                    await entryStream.ReadAsync(
                        buffer.AsMemory(
                            0,
                            requested),
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
                            $"ReadBytes={context.Budget.ExpandedBytesRead}; Limit={context.Budget.MaxExpandedBytes}",
                            logicalPath));

                    return;
                }

                actualBytes +=
                    read;

                if (actualBytes >
                    _options.MaxZipEntryBytes)
                {
                    AddFinding(
                        context,
                        new ArchiveScanFinding(
                            ArchiveFindingKind.ArchiveEntryActualSizeExceeded,
                            ScanVerdict.Suspicious,
                            SecuritySeverity.Critical,
                            "Archive entry exceeded actual read-size limit",
                            $"Entry={entry.FullName}; Limit={_options.MaxZipEntryBytes}",
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
                    var copyLength =
                        Math.Min(
                            read,
                            header.Length -
                            headerLength);

                    buffer.AsSpan(
                            0,
                            copyLength)
                        .CopyTo(
                            header.AsSpan(
                                headerLength));

                    headerLength +=
                        copyLength;
                }

                if (detectedType ==
                    DetectedFileType.Unknown)
                {
                    detectedType =
                        _fileTypeDetector.Detect(
                            header.AsSpan(
                                0,
                                headerLength));

                    if (detectedType ==
                        DetectedFileType.Zip)
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
                        else if (entry.Length >
                                 _options.MaxNestedArchiveBytes)
                        {
                            nestedSizeFindingAdded =
                                true;

                            AddFinding(
                                context,
                                new ArchiveScanFinding(
                                    ArchiveFindingKind.NestedArchiveSizeExceeded,
                                    ScanVerdict.Unknown,
                                    SecuritySeverity.High,
                                    "Nested ZIP exceeds spool size limit",
                                    $"ExpandedBytes={entry.Length}; Limit={_options.MaxNestedArchiveBytes}",
                                    logicalPath));
                        }
                        else
                        {
                            spool =
                                await _spoolService.CreateAsync(
                                    cancellationToken);

                            await spool.Stream.WriteAsync(
                                buffer.AsMemory(
                                    0,
                                    read),
                                cancellationToken);
                        }
                    }
                }
                else if (spool is not null)
                {
                    if (actualBytes >
                        _options.MaxNestedArchiveBytes)
                    {
                        await spool.DisposeAsync();

                        spool =
                            null;

                        if (!nestedSizeFindingAdded)
                        {
                            nestedSizeFindingAdded =
                                true;

                            AddFinding(
                                context,
                                new ArchiveScanFinding(
                                    ArchiveFindingKind.NestedArchiveSizeExceeded,
                                    ScanVerdict.Unknown,
                                    SecuritySeverity.High,
                                    "Nested ZIP exceeded actual spool size limit",
                                    $"ReadBytes={actualBytes}; Limit={_options.MaxNestedArchiveBytes}",
                                    logicalPath));
                        }
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
                    entry.LastWriteTime.ToUniversalTime(),
                    digest,
                    header[..headerLength],
                    detectedType);

            await AnalyzeEntryMetadataAsync(
                metadata,
                logicalPath,
                context,
                cancellationToken);

            if (detectedType !=
                DetectedFileType.Zip)
            {
                return;
            }

            if (depth >=
                _options.MaxArchiveDepth)
            {
                return;
            }

            if (spool is null)
            {
                return;
            }

            await spool.Stream.FlushAsync(
                cancellationToken);

            spool.Stream.Position =
                0;

            await ScanZipStreamAsync(
                spool.Stream,
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

    private void AddFindings(
        RecursiveContext context,
        IEnumerable<ArchiveScanFinding> findings,
        string logicalPath)
    {
        foreach (var finding in
                 findings)
        {
            AddFinding(
                context,
                finding.EntryPath is null
                    ? finding with
                    {
                        EntryPath =
                            logicalPath
                    }
                    : finding);
        }
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

    private static double CalculateCompressionRatio(
        long expanded,
        long compressed)
    {
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

    private static string BuildLogicalPath(
        string parent,
        string entryName)
    {
        var normalized =
            entryName.Replace(
                '\\',
                '/');

        return $"{parent}!/{normalized}";
    }

    private static string GetEntryFileName(
        string fullName)
    {
        var normalized =
            fullName.Replace(
                '\\',
                '/');

        var separator =
            normalized.LastIndexOf(
                '/');

        return separator >= 0
            ? normalized[(separator + 1)..]
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