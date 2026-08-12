namespace SecurityGuard.Core.Models;

public sealed record FileTransferInfo(
    Guid Id,
    string FilePath,
    string FileName,
    string? Sha256,
    long? SizeBytes,
    ProcessInfo SourceProcess,
    string? RemoteAddress,
    int? RemotePort,
    string? Protocol,
    DateTimeOffset DetectedAtUtc);