namespace SecurityGuard.ArchiveGuard.Models;

public sealed record PeImportModule(
    string Name,
    IReadOnlyList<string> Functions);