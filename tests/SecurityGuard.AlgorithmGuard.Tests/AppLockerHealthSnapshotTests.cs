using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AppLockerHealthSnapshotTests
{
    [Fact]
    public void EngineReady_ReturnsTrue_WhenEngineAndServiceAreRunning()
    {
        var snapshot =
            new AppLockerHealthSnapshot(
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                null);

        Assert.True(
            snapshot.EngineReady);
    }

    [Fact]
    public void ManagementReady_ReturnsFalse_WhenCmdletsAreUnavailable()
    {
        var snapshot =
            new AppLockerHealthSnapshot(
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                null);

        Assert.False(
            snapshot.ManagementReady);
    }

    [Fact]
    public void EnforcementReady_ReturnsFalse_WhenManagementIsUnavailable()
    {
        var snapshot =
            new AppLockerHealthSnapshot(
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                null);

        Assert.True(
            snapshot.EngineReady);

        Assert.False(
            snapshot.EnforcementReady);
    }

    [Fact]
    public void EnforcementReady_ReturnsTrue_WhenAllRequirementsAreAvailable()
    {
        var snapshot =
            new AppLockerHealthSnapshot(
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                null);

        Assert.True(
            snapshot.EngineReady);

        Assert.True(
            snapshot.ManagementReady);

        Assert.True(
            snapshot.EnforcementReady);
    }

    [Fact]
    public void EngineReady_ReturnsFalse_WhenApplicationIdentityIsStopped()
    {
        var snapshot =
            new AppLockerHealthSnapshot(
                true,
                true,
                true,
                true,
                false,
                true,
                true,
                true,
                null);

        Assert.False(
            snapshot.EngineReady);

        Assert.False(
            snapshot.EnforcementReady);
    }

    [Fact]
    public void EngineReady_ReturnsFalse_WhenAppIdDriverIsStopped()
    {
        var snapshot =
            new AppLockerHealthSnapshot(
                true,
                true,
                false,
                true,
                true,
                true,
                true,
                true,
                null);

        Assert.False(
            snapshot.EngineReady);

        Assert.False(
            snapshot.EnforcementReady);
    }
}