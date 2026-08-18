using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Tests;

public sealed class PipeJsonSerializerTests
{
    [Fact]
    public void Snapshot_can_be_serialized()
    {
        var snapshot =
            new SecuritySnapshot(
                [
                    new ModuleStatus(
                        SecurityModuleKind.Core,
                        ModuleOperationalState.Active,
                        "Ready",
                        DateTimeOffset.UtcNow)
                ],
                [
                    SecurityEvent.Create(
                        SecurityModuleKind.Core,
                        SecurityEventType.System,
                        SecuritySeverity.Info,
                        "Started",
                        "SecurityGuard started")
                ],
                [],
                0,
                DateTimeOffset.UtcNow);

        var json =
            PipeJsonSerializer.Serialize(
                snapshot);

        var restored =
            PipeJsonSerializer.Deserialize<SecuritySnapshot>(
                json);

        Assert.Single(
            restored.Modules);

        Assert.Single(
            restored.RecentEvents);

        Assert.Equal(
            SecurityModuleKind.Core,
            restored.Modules[0].Module);
    }

    [Fact]
    public void Enums_are_serialized_as_names()
    {
        var status =
            new ModuleStatus(
                SecurityModuleKind.AlgorithmGuard,
                ModuleOperationalState.Active,
                "Ready",
                DateTimeOffset.UtcNow);

        var json =
            PipeJsonSerializer.Serialize(
                status);

        Assert.Contains(
            "AlgorithmGuard",
            json);

        Assert.Contains(
            "Active",
            json);
    }
}