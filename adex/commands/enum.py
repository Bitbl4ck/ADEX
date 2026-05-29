"""`adex enum` — orchestrates discovery modules + chain inference + risk scoring."""

from __future__ import annotations

import argparse
import logging

from rich.console import Console

from adex.auth import Auth, AuthError
from adex.chain import compute_chains, resolve_sinks
from adex.connection import BoundLDAP, connect_ldap
from adex.connection import ConnectionError as ADEXConnError
from adex.exit_codes import ExitCode, from_findings
from adex.filters import parse_min_severity, parse_module_list
from adex.findings import Edge, FindingCollector, Severity
from adex.modules import all_modules, select
from adex.modules.base import ME_NODE, RunContext
from adex.output import print_findings_console, print_summary, write_outputs
from adex.risk import compute_risk
from adex.trusts import enumerate_trusts, traverse_trusts
from adex.utils import get_principal_sids

log = logging.getLogger("adex.enum")


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser(
        "enum",
        parents=[common],
        help="Run enumeration modules against a target domain",
    )
    p.add_argument("-o", "--output", help="Output file base name (.json/.html/.txt)")
    p.add_argument("-f", "--format", default="all",
                   choices=["all", "html", "json", "txt"],
                   help="Output format (default: all)")
    p.add_argument("--min-severity", default=None,
                   choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("-L", "--list-modules", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Include INFO-level findings")
    p.add_argument("-M", "--modules", help="Comma-separated list of modules to run")
    p.add_argument("--opsec", action="store_true", help="Skip noisy checks")
    p.add_argument("--map-trusts", action="store_true",
                   help="Enumerate trusted domains and run modules across each one")
    p.add_argument("--no-chains", action="store_true",
                   help="Skip attack-chain inference")
    p.add_argument("--no-risk", action="store_true",
                   help="Skip risk scoring")
    p.set_defaults(handler=handle)


def _list_modules(console: Console) -> int:
    console.print("[bold]Available modules:[/bold]")
    for mod in all_modules():
        impl = "[green]impl[/green]" if mod.implemented else "[dim]stub[/dim]"
        opsec = "[blue]opsec[/blue]" if mod.opsec_safe else "[red]noisy[/red]"
        console.print(f"  {mod.name:<14} {impl}  {opsec}  {mod.description}")
    return int(ExitCode.SUCCESS)


def _run_modules(bound: BoundLDAP, auth: Auth, dc: str, mods,
                 collector: FindingCollector, console: Console,
                 domain_context: str) -> set[str]:
    sids = get_principal_sids(bound.conn, bound.base_dn,
                              auth.username if auth.primary_method != "schannel" else None)
    ctx = RunContext(
        conn=bound.conn,
        auth=auth,
        base_dn=bound.base_dn,
        dc=dc,
        use_ldaps=bound.use_ldaps,
        log=logging.getLogger("adex.module"),
        principal_sids=sids,
        me_node=ME_NODE,
        domain_context=domain_context,
    )
    domain_label = f"[cyan]{domain_context}[/cyan] " if domain_context else ""
    for cls in mods:
        instance = cls()
        label = f"{domain_label}[{instance.name}]"
        if not instance.implemented:
            console.print(f"[dim]{label} stub[/dim]")
            instance.run(ctx)
            continue
        console.print(f"{label} running...")
        try:
            findings = instance.run(ctx) or []
            for f in findings:
                if not f.domain_context:
                    f.domain_context = domain_context
            collector.extend(findings)
            console.print(f"  [dim]{len(findings)} finding(s)[/dim]")
        except Exception as e:
            log.exception("module %s failed", instance.name)
            console.print(f"  [red]error:[/red] {e}")
    return sids


def handle(args: argparse.Namespace) -> int:
    console = Console()

    if args.list_modules:
        return _list_modules(console)

    try:
        auth = Auth.from_args(args)
        auth.validate()
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        return int(ExitCode.AUTH_FAIL)

    try:
        bound = connect_ldap(auth, dc=args.dc, use_ldaps=args.ldaps,
                             timeout=args.timeout, dns_server=args.dns)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        return int(ExitCode.AUTH_FAIL)
    except ADEXConnError as e:
        console.print(f"[red]connection error:[/red] {e}")
        return int(ExitCode.NET_FAIL)
    except Exception as e:
        if "invalidCredentials" in str(e) or "AcceptSecurityContext" in str(e):
            console.print(f"[red]auth error:[/red] {e}")
            return int(ExitCode.AUTH_FAIL)
        console.print(f"[red]connection error:[/red] {e}")
        return int(ExitCode.NET_FAIL)

    console.print(f"[green]bound to[/green] {args.dc or auth.domain} "
                  f"as [bold]{auth.username or '<schannel>'}[/bold] "
                  f"({auth.primary_method}) base=[dim]{bound.base_dn}[/dim]")

    try:
        mods = select(parse_module_list(args.modules), opsec_only=args.opsec)
    except KeyError as e:
        console.print(f"[red]{e}[/red]")
        return int(ExitCode.SUCCESS)

    collector = FindingCollector()

    # ---- primary domain ----
    primary_sids = _run_modules(bound, auth, args.dc or auth.domain, mods,
                                collector, console, "")

    # Sinks for chain inference (resolved against primary domain only)
    sinks = resolve_sinks(bound.conn, bound.base_dn)

    # ---- trust traversal ----
    if args.map_trusts:
        trusts = enumerate_trusts(bound.conn, bound.base_dn)
        if not trusts:
            console.print("[dim]no trusts found to traverse[/dim]")
        else:
            console.print(f"[cyan]traversing {len(trusts)} trust(s)[/cyan]")

            def runner(other_bound, other_auth, partner_label):
                _run_modules(other_bound, other_auth,
                             other_bound.server.host or partner_label,
                             mods, collector, console, partner_label)

            traverse_trusts(bound, auth, trusts, args.ldaps, args.timeout,
                            args.dns, runner, log)

    bound.conn.unbind()

    # ---- chain inference ----
    if not args.no_chains:
        # Build edges: ME → each principal SID (cost 0), then all module-emitted edges
        edges = [Edge(src=ME_NODE, dst=sid, type="GenericAll",
                      dst_label="(self/group)", cost=0) for sid in primary_sids]
        edges.extend(collector.all_edges())
        sources = {ME_NODE}
        try:
            graph, chain_findings = compute_chains(edges, sources, sinks)
            collector.extend(chain_findings)
            console.print(f"[cyan][chain][/cyan] {len(chain_findings)} attack path(s) found")
        except Exception as e:
            log.exception("chain inference failed")
            console.print(f"[red]chain error:[/red] {e}")
            graph = None
    else:
        graph = None

    # ---- risk scoring ----
    if not args.no_risk and graph is not None:
        risk_finding = compute_risk(graph, sinks)
        if risk_finding:
            collector.add(risk_finding)

    min_sev = parse_min_severity(args.min_severity, args.verbose)
    console.print()
    print_summary(collector.all(), console)
    console.print()
    print_findings_console(collector.all(), min_sev, console)

    if args.output:
        formats = [args.format]
        written = write_outputs(args.output, collector.all(), formats)
        for p in written:
            console.print(f"[green]wrote[/green] {p}")

    return from_findings(collector.all(), Severity.HIGH)
