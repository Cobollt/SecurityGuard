namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveScanBudget
{
    public ArchiveScanBudget(
        long maxExpandedBytes,
        int maxEntries)
    {
        if (maxExpandedBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxExpandedBytes));
        }

        if (maxEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxEntries));
        }

        MaxExpandedBytes =
            maxExpandedBytes;

        MaxEntries =
            maxEntries;
    }

    public long MaxExpandedBytes { get; }

    public int MaxEntries { get; }

    public long ExpandedBytesRead { get; private set; }

    public int EntriesInspected { get; private set; }

    public long RemainingBytes =>
        Math.Max(
            0,
            MaxExpandedBytes -
            ExpandedBytesRead);

    public bool TryRegisterEntry()
    {
        if (EntriesInspected >=
            MaxEntries)
        {
            return false;
        }

        EntriesInspected++;

        return true;
    }

    public bool TryConsume(
        int bytes)
    {
        if (bytes < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes));
        }

        if (bytes >
            RemainingBytes)
        {
            return false;
        }

        ExpandedBytesRead +=
            bytes;

        return true;
    }
}