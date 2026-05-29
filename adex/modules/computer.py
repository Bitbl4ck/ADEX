from adex.findings import Finding
from adex.modules.base import ModuleBase, RunContext


class ComputerModule(ModuleBase):
    name = "computer"
    description = "LAPS coverage, outdated OS, infrastructure servers"
    opsec_safe = True
    implemented = False

    def run(self, ctx: RunContext) -> list[Finding]:
        ctx.log.info("[computer] stub — implemented in Phase 2")
        return []
