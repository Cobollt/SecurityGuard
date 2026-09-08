namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardFileCandidatePolicy
{
    bool ShouldScan(
        string filePath);
}