using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IModuleRegistry
{
    IReadOnlyList<ModuleStatus> GetAll();

    ModuleStatus Get(SecurityModuleKind module);

    void Set(
        SecurityModuleKind module,
        ModuleOperationalState state,
        string message);
}