using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmEnforcementClassifierTests
{
    [Fact]
    public void PowerShell_script_is_classified_as_PowerShellScript()
    {
        var result =
            AlgorithmEnforcementClassifier.GetLevel(
                @"C:\Temp\TEST.PS1");

        Assert.Equal(
            AlgorithmEnforcementLevel.PowerShellScript,
            result);
    }

    [Theory]
    [InlineData(@"C:\Temp\test.bat")]
    [InlineData(@"C:\Temp\test.CMD")]
    [InlineData(@"C:\Temp\test.vbs")]
    [InlineData(@"C:\Temp\test.js")]
    public void Supported_script_is_classified_as_Blocked(
        string filePath)
    {
        var result =
            AlgorithmEnforcementClassifier.GetLevel(
                filePath);

        Assert.Equal(
            AlgorithmEnforcementLevel.Blocked,
            result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"C:\Temp\test.py")]
    public void Unsupported_path_is_classified_as_Unsupported(
        string? filePath)
    {
        var result =
            AlgorithmEnforcementClassifier.GetLevel(
                filePath);

        Assert.Equal(
            AlgorithmEnforcementLevel.Unsupported,
            result);
    }
}