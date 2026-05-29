from adex.findings import Finding
from adex.modules.base import ModuleBase, RunContext


class ApplicationModule(ModuleBase):
    name = "application"
    description = "Exchange, SCCM, SCOM detection"
    opsec_safe = True
    implemented = False

    def run(self, ctx: RunContext) -> list[Finding]:
        ctx.log.info("[application] stub — implemented in Phase 2")
        return []
