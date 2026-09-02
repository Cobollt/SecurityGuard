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
}