namespace SecurityGuard.Core.Enums;

public enum RuleScope
{
    FileHash = 0,
    FilePath = 1,
    Publisher = 2,
    Process = 3,
    ParentProcess = 4,
    RemoteAddress = 5,
    RemotePort = 6,
    Protocol = 7
}