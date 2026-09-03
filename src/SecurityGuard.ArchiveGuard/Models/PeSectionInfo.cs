namespace SecurityGuard.ArchiveGuard.Models;

public sealed record PeSectionInfo(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawOffset,
    uint RawSize,
    uint Characteristics,
    bool Executable,
    bool Writable,
    double? Entropy);