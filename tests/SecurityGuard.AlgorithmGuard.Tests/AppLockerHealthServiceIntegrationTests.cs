using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AppLockerHealthServiceIntegrationTests
{
    [Fact]
    public async Task Current_machine_applocker_health_can_be_detected()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var service =
            new AppLockerHealthService();

        var result =
            await service.EnsureReadyAsync();

        Assert.True(
            result.IsWindows);

        Assert.True(
            result.EngineInstalled);

        Assert.True(
            result.EngineRunning);

        Assert.True(
            result.ApplicationIdentityInstalled);

        Assert.True(
            result.ApplicationIdentityRunning);

        Assert.True(
            result.PowerShellAvailable);
    }
}