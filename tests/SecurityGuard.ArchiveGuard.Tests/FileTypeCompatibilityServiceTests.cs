using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class FileTypeCompatibilityServiceTests
{
    private readonly FileTypeCompatibilityService _service =
        new();

    [Theory]
    [InlineData(".zip")]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pptx")]
    [InlineData(".jar")]
    [InlineData(".epub")]
    public void Zip_container_extensions_are_valid(
        string extension)
    {
        Assert.True(
            _service.IsCompatible(
                DetectedFileType.Zip,
                extension));
    }

    [Fact]
    public void Zip_with_pdf_extension_is_not_valid()
    {
        Assert.False(
            _service.IsCompatible(
                DetectedFileType.Zip,
                ".pdf"));
    }

    [Fact]
    public void Pe_with_exe_extension_is_valid()
    {
        Assert.True(
            _service.IsCompatible(
                DetectedFileType.Pe,
                ".exe"));
    }

    [Fact]
    public void Pe_with_pdf_extension_is_not_valid()
    {
        Assert.False(
            _service.IsCompatible(
                DetectedFileType.Pe,
                ".pdf"));
    }

    [Fact]
    public void Tgz_can_contain_gzip()
    {
        Assert.True(
            _service.IsCompatible(
                DetectedFileType.Gzip,
                ".tgz"));
    }
}