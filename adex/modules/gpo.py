from adex.findings import Finding
from adex.modules.base import ModuleBase, RunContext


class GpoModule(ModuleBase):
    name = "gpo"
    description = "GPO write access, local group membership via GPO"
    opsec_safe = True
    implemented = False

    def run(self, ctx: RunContext) -> list[Finding]:
        ctx.log.info("[gpo] stub — implemented in Phase 2")
        return []
