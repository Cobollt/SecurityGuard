namespace SecurityGuard.Core.Enums;

public enum SecurityEventType
{
    System = 0,
    AlgorithmExecution = 1,
    FileTransfer = 2,
    FileScan = 3,
    ArchiveScan = 4,
    Quarantine = 5,
    Rule = 6,
    Audit = 7
}