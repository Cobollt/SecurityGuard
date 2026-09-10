namespace SecurityGuard.ArchiveGuard.Exceptions;

public sealed class ArchiveFileChangedException
    : IOException
{
    public ArchiveFileChangedException(
        string filePath)
        : base(
            $"File changed while ArchiveGuard was reading it: {filePath}")
    {
        FilePath =
            filePath;
    }

    public string FilePath { get; }
}