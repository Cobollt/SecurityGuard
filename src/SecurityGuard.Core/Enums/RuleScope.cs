namespace SecurityGuard.Core.Enums;

public enum RuleScope
{
    FileHash = 0,
    FilePath = 1,
    FileName = 2,
    FileExtension = 3,
    Publisher = 4,
    Process = 5,
    ParentProcess = 6,
    Interpreter = 7,
    RemoteAddress = 8,
    RemotePort = 9,
    Protocol = 10,
    DestinationProcess = 11,
    CommandLine = 12,
    UserName = 13,
    ProcessPublisher = 14,
    ParentProcessPath = 15,
    RootProcess = 16,
    RootProcessPath = 17,
    ExecutionChain = 18,
    ProcessPath = 19,
    FileCategory = 20,
    TransferActivityKind = 21
}