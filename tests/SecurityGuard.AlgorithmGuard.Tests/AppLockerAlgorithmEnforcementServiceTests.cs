using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AppLockerAlgorithmEnforcementServiceTests
{
    private readonly AppLockerAlgorithmEnforcementService _service =
        new(
            new PowerShellProcessRunner());

    [Theory]
    [InlineData(@"C:\Temp\test.bat")]
    [InlineData(@"C:\Temp\test.cmd")]
    [InlineData(@"C:\Temp\test.vbs")]
    [InlineData(@"C:\Temp\test.js")]
    public void Supported_script_has_applocker_block(
        string path)
    {
        var result =
            _service.GetLevel(path);

        Assert.Equal(
            AlgorithmEnforcementLevel.AppLockerBlocked,
            result);
    }

    [Fact]
    public void PowerShell_has_constrained_enforcement()
    {
        var result =
            _service.GetLevel(
                @"C:\Temp\test.ps1");

        Assert.Equal(
            AlgorithmEnforcementLevel.PowerShellConstrained,
            result);
    }

    [Theory]
    [InlineData(@"C:\Temp\test.py")]
    [InlineData(@"C:\Temp\test.pyw")]
    [InlineData(@"C:\Temp\test.txt")]
    public void Unsupported_script_is_reported(
        string path)
    {
        var result =
            _service.GetLevel(path);

        Assert.Equal(
            AlgorithmEnforcementLevel.Unsupported,
            result);
    }
}