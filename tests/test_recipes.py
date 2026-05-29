from adex import recipes


def test_kerberoast_interpolates():
    out = recipes.kerberoast("corp.local", "1.2.3.4", "svc_user",
                             "jdoe", password="P@ss")
    full = "\n".join(out)
    assert "impacket-GetUserSPNs" in full
    assert "corp.local/jdoe:'P@ss'" in full
    assert "1.2.3.4" in full
    assert "svc_user" in full


def test_asrep_roast_no_creds():
    out = recipes.asrep_roast("corp.local", "1.2.3.4", "preauth.user")
    full = "\n".join(out)
    assert "impacket-GetNPUsers" in full
    assert "preauth.user" in full
    assert "-no-pass" in full


def test_dcsync():
    out = recipes.dcsync("corp.local", "1.2.3.4", "jdoe",
                        nt_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
    full = "\n".join(out)
    assert "impacket-secretsdump" in full
    assert "-just-dc" in full


def test_esc1_command():
    out = recipes.esc1("ESSOS-CA", "ESC1-Template",
                       "administrator@corp.local",
                       "corp.local", "1.2.3.4", "jdoe", password="x")
    full = "\n".join(out)
    assert "certipy req" in full
    assert "ESC1-Template" in full
    assert "administrator@corp.local" in full


def test_rbcd_write_chain():
    out = recipes.rbcd_write("corp.local", "1.2.3.4", "TARGET$", "PWNED$",
                             "jdoe", password="x")
    full = "\n".join(out)
    assert "impacket-addcomputer" in full
    assert "bloodyAD" in full
    assert "impacket-getST" in full


def test_unconstrained_includes_petitpotam():
    out = recipes.unconstrained_coerce("HOST$", "corp.local", "1.2.3.4", "tun0")
    full = "\n".join(out)
    assert "PetitPotam.py" in full or "printerbug.py" in full
