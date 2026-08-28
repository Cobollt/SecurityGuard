using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferFileClassifierTests
{
    private readonly TransferFileClassifier _classifier =
        new();

    [Fact]
    public void Document_in_user_folder_is_high_priority()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\Documents\Report.pdf");

        Assert.Equal(
            TransferFileCategory.Document,
            result.Category);

        Assert.Equal(
            TransferFilePriority.High,
            result.Priority);
    }

    [Fact]
    public void Archive_in_downloads_is_high_priority()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\Downloads\backup.zip");

        Assert.Equal(
            TransferFileCategory.Archive,
            result.Category);

        Assert.Equal(
            TransferFilePriority.High,
            result.Priority);
    }

    [Fact]
    public void Source_code_is_high_priority()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\Documents\Project\Program.cs");

        Assert.Equal(
            TransferFileCategory.SourceCode,
            result.Category);

        Assert.Equal(
            TransferFilePriority.High,
            result.Priority);
    }

    [Fact]
    public void Windows_system_library_is_ignored()
    {
        var result =
            _classifier.Classify(
                @"C:\Windows\System32\kernel32.dll");

        Assert.Equal(
            TransferFileCategory.System,
            result.Category);

        Assert.Equal(
            TransferFilePriority.Ignore,
            result.Priority);
    }

    [Fact]
    public void Browser_cache_is_ignored()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\data_1");

        Assert.Equal(
            TransferFileCategory.Cache,
            result.Category);

        Assert.Equal(
            TransferFilePriority.Ignore,
            result.Priority);
    }

    [Fact]
    public void Temporary_file_is_ignored()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\AppData\Local\Temp\upload.tmp");

        Assert.Equal(
            TransferFileCategory.Temporary,
            result.Category);

        Assert.Equal(
            TransferFilePriority.Ignore,
            result.Priority);
    }

    [Fact]
    public void Database_in_documents_is_high_priority()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\Documents\customers.sqlite");

        Assert.Equal(
            TransferFileCategory.Database,
            result.Category);

        Assert.Equal(
            TransferFilePriority.High,
            result.Priority);
    }

    [Fact]
    public void Executable_in_downloads_is_not_ignored()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\Downloads\tool.exe");

        Assert.Equal(
            TransferFileCategory.Executable,
            result.Category);

        Assert.Equal(
            TransferFilePriority.Medium,
            result.Priority);
    }

    [Fact]
    public void Unknown_file_in_documents_is_medium_priority()
    {
        var result =
            _classifier.Classify(
                @"C:\Users\Ivan\Documents\private.customformat");

        Assert.Equal(
            TransferFileCategory.Unknown,
            result.Category);

        Assert.Equal(
            TransferFilePriority.Medium,
            result.Priority);
    }
}