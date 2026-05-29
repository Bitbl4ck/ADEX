from adex.findings import Finding
from adex.modules.base import ModuleBase, RunContext


class AccountsModule(ModuleBase):
    name = "accounts"
    description = "Privileged users, adminCount, SID history, stale accounts"
    opsec_safe = True
    implemented = False

    def run(self, ctx: RunContext) -> list[Finding]:
        ctx.log.info("[accounts] stub — implemented in Phase 2")
        return []
