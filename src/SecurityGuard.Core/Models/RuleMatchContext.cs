namespace SecurityGuard.Core.Models;

public sealed record RuleMatchContext(
    string? FileHash = null,
    string? FilePath = null,
    string? Publisher = null,
    string? Process = null,
    string? ParentProcess = null,
    string? RemoteAddress = null,
    int? RemotePort = null,
    string? Protocol = null);