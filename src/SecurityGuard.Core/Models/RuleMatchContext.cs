namespace SecurityGuard.Core.Models;

public sealed record RuleMatchContext(
    string? FileHash = null,
    string? FilePath = null,
    string? FileName = null,
    string? FileExtension = null,
    string? Publisher = null,
    string? Process = null,
    string? ParentProcess = null,
    string? Interpreter = null,
    string? RemoteAddress = null,
    int? RemotePort = null,
    string? Protocol = null,
    string? DestinationProcess = null,
    string? CommandLine = null,
    string? UserName = null,
    string? ProcessPublisher = null,
    string? ParentProcessPath = null);