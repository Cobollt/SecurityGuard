namespace SecurityGuard.ArchiveGuard.Models;

public sealed class ArchiveTemporarySpool
    : IAsyncDisposable
{
    private FileStream? _stream;

    public ArchiveTemporarySpool(
        string filePath,
        FileStream stream)
    {
        FilePath =
            filePath;

        _stream =
            stream;
    }

    public string FilePath { get; }

    public FileStream Stream =>
        _stream ??
        throw new ObjectDisposedException(
            nameof(ArchiveTemporarySpool));

    public async ValueTask DisposeAsync()
    {
        var stream =
            _stream;

        _stream =
            null;

        if (stream is not null)
        {
            await stream.DisposeAsync();
        }

        try
        {
            if (File.Exists(
                    FilePath))
            {
                File.Delete(
                    FilePath);
            }
        }
        catch
        {
        }
    }
}