namespace SecurityGuard.ArchiveGuard.Configuration;

public sealed class ArchiveGuardOptions
{
    public int HeaderBytesToRead { get; init; } =
        64 * 1024;
}