namespace SecurityGuard.ArchiveGuard.Configuration;

public sealed class ArchiveGuardOptions
{
    public int HeaderBytesToRead { get; init; } =
        64 * 1024;

    public int MaxZipEntryCount { get; init; } =
        10_000;

    public long MaxZipExpandedBytes { get; init; } =
        1L * 1024L * 1024L * 1024L;

    public long MaxZipEntryBytes { get; init; } =
        512L * 1024L * 1024L;

    public double MaxZipCompressionRatio { get; init; } =
        200.0;

    public int MaxRecordedZipEntries { get; init; } =
        2048;

    public int MaxArchiveFindings { get; init; } =
        256;

    public int MaxArchiveDepth { get; init; } =
        5;
    public int MaxArchiveEntryCount { get; init; } =
    10_000;

    public long MaxArchiveExpandedBytes { get; init; } =
        1L * 1024L * 1024L * 1024L;

    public long MaxArchiveEntryBytes { get; init; } =
        512L * 1024L * 1024L;

    public double MaxArchiveCompressionRatio { get; init; } =
        200.0;
    
    public long MaxPeAnalysisBytes { get; init; } =
        128L * 1024L * 1024L;

    public int MaxPeSections { get; init; } =
        96;

    public int MaxPeImportDescriptors { get; init; } =
        256;

    public int MaxPeImports { get; init; } =
        2048;

    public int MaxPeImportNameBytes { get; init; } =
        260;

    public int MaxPeSectionEntropySampleBytes { get; init; } =
        4 * 1024 * 1024;

    public double PeHighEntropyThreshold { get; init; } =
        7.20;

    public int MaxScriptFindingsPerFile { get; init; } =
        8;

    public bool AuthenticodeOnlineRevocationCheck { get; init; } =
        false;
}