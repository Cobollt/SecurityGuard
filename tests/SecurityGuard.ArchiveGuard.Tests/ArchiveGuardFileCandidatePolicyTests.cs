using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardFileCandidatePolicyTests
{
    private readonly ArchiveGuardFileCandidatePolicy _policy =
        new();

    [Theory]
    [InlineData("file.crdownload")]
    [InlineData("file.part")]
    [InlineData("file.partial")]
    [InlineData("file.tmp")]
    [InlineData("file.download")]
    public void Temporary_download_is_ignored(
        string fileName)
    {
        Assert.False(
            _policy.ShouldScan(
                fileName));
    }

    [Theory]
    [InlineData("archive.zip")]
    [InlineData("document.pdf")]
    [InlineData("program.exe")]
    [InlineData("script.ps1")]
    [InlineData("file")]
    public void Completed_file_is_candidate(
        string fileName)
    {
        Assert.True(
            _policy.ShouldScan(
                fileName));
    }
}