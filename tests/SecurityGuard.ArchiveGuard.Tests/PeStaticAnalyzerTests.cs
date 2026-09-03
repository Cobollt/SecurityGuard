using SecurityGuard.ArchiveGuard.Analyzers;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class PeStaticAnalyzerTests
{
    [Fact]
    public async Task Normal_pe_is_parsed()
    {
        var analyzer =
            new PeStaticAnalyzer(
                new ArchiveGuardOptions());

        await using var stream =
            new MemoryStream(
                PeTestFileFactory.Create());

        var result =
            await analyzer.AnalyzeAsync(
                stream,
                "test.exe");

        Assert.True(
            result.IsValid);

        Assert.Equal(
            "x64",
            result.MachineName);

        Assert.Single(
            result.Sections);

        Assert.DoesNotContain(
            result.Findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.PeInvalidStructure);
    }

    [Fact]
    public async Task Writable_executable_section_is_suspicious()
    {
        var analyzer =
            new PeStaticAnalyzer(
                new ArchiveGuardOptions());

        await using var stream =
            new MemoryStream(
                PeTestFileFactory.Create(
                    writableExecutable:
                        true));

        var result =
            await analyzer.AnalyzeAsync(
                stream,
                "test.exe");

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.PeWritableExecutableSection);
    }

    [Fact]
    public async Task High_entropy_executable_section_is_suspicious()
    {
        var random =
            new byte[
                1024 * 1024];

        new Random(
            12345)
            .NextBytes(
                random);

        var analyzer =
            new PeStaticAnalyzer(
                new ArchiveGuardOptions
                {
                    PeHighEntropyThreshold =
                        7.0
                });

        await using var stream =
            new MemoryStream(
                PeTestFileFactory.Create(
                    sectionData:
                        random));

        var result =
            await analyzer.AnalyzeAsync(
                stream,
                "packed.exe");

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.PeHighEntropySection);
    }
}