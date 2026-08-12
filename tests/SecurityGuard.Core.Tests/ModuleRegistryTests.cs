using Xunit;

using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Services;

namespace SecurityGuard.Core.Tests;

public sealed class ModuleRegistryTests
{
    [Fact]
    public void Registry_contains_all_modules()
    {
        var registry = new ModuleRegistry();

        var modules = registry.GetAll();

        Assert.Equal(4, modules.Count);

        Assert.Contains(
            modules,
            item => item.Module == SecurityModuleKind.Core);

        Assert.Contains(
            modules,
            item => item.Module == SecurityModuleKind.AlgorithmGuard);

        Assert.Contains(
            modules,
            item => item.Module == SecurityModuleKind.TransferGuard);

        Assert.Contains(
            modules,
            item => item.Module == SecurityModuleKind.ArchiveGuard);
    }

    [Fact]
    public void Registry_updates_module_state()
    {
        var registry = new ModuleRegistry();

        registry.Set(
            SecurityModuleKind.Core,
            ModuleOperationalState.Active,
            "Ready");

        var status = registry.Get(
            SecurityModuleKind.Core);

        Assert.Equal(
            ModuleOperationalState.Active,
            status.State);

        Assert.Equal(
            "Ready",
            status.Message);
    }

    [Fact]
    public void Unknown_module_throws_exception()
    {
        var registry = new ModuleRegistry();

        Assert.Throws<KeyNotFoundException>(
            () => registry.Get(
                (SecurityModuleKind)999));
    }
}