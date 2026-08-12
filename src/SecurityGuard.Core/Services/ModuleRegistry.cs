using System.Collections.Concurrent;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Services;

public sealed class ModuleRegistry : IModuleRegistry
{
    private readonly ConcurrentDictionary<SecurityModuleKind, ModuleStatus> _statuses = new();

    public ModuleRegistry()
    {
        Set(
            SecurityModuleKind.Core,
            ModuleOperationalState.Starting,
            "Core is starting");

        Set(
            SecurityModuleKind.AlgorithmGuard,
            ModuleOperationalState.Disabled,
            "AlgorithmGuard is not implemented");

        Set(
            SecurityModuleKind.TransferGuard,
            ModuleOperationalState.Disabled,
            "TransferGuard is not implemented");

        Set(
            SecurityModuleKind.ArchiveGuard,
            ModuleOperationalState.Disabled,
            "ArchiveGuard is not implemented");
    }

    public IReadOnlyList<ModuleStatus> GetAll()
    {
        return _statuses
            .Values
            .OrderBy(status => status.Module)
            .ToArray();
    }

    public ModuleStatus Get(SecurityModuleKind module)
    {
        if (!_statuses.TryGetValue(module, out var status))
        {
            throw new KeyNotFoundException(
                $"Module '{module}' is not registered.");
        }

        return status;
    }

    public void Set(
        SecurityModuleKind module,
        ModuleOperationalState state,
        string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        _statuses[module] = new ModuleStatus(
            module,
            state,
            message,
            DateTimeOffset.UtcNow);
    }
}