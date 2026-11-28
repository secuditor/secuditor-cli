# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform executive Summary Report generator for full Secuditor audits."""

from datetime import datetime
import platform
import socket
import sys

__all__ = ["build_summary_report", "format_summary_report", "MITRE_MAP"]

MITRE_MAP = {
    "Endpoint Protection": "T1562.001 (Impair Defenses)",
    "Host-based Firewall": "T1562.004 (Disable Firewall)",
    "Network Gateway": "T1046 (Network Service Discovery)",
    "Auto Screen Lock": "T1078.003 (Local Access)",
    "Elevation Prompt": "T1548.002 (Bypass UAC)",
    "Memory Integrity": "T1014 (Kernel / Rootkit)",
    "Boot Security Layer": "T1542.003 (Bootkit)",
    "System Restore": "T1490 (Inhibit Recovery)",
    "Disk Encryption": "T1005 (Offline Data Access)",
    "LAPS Protection": "T1078.003 (Local Admin)",
    "Domain Settings": "–",
    "Password Policy": "T1110 (Brute Force)",
    "Bluetooth Component": "T1011.001 (Bluetooth)",
    "PowerShell Remoting": "T1059.001 (PowerShell)",
    "RPC Print Spooler": "T1210 (Print Spooler RPC)",
    "SMBv1 Protocol": "T1210 (SMB Exploit)",
    "SMBv2 Protocol": "T1021.002 (SMB Shares)",
    "FTP Service": "T1071.002 (File Transfer Protocol)",
    "DCOM Service": "T1021.003 (DCOM Remote)",
    "WinRM Service": "T1021.006 (WinRM Remote)",
    "Remote Desktop": "T1021.001 (RDP Remote)",
    "SSH Service": "T1021.004 (SSH Remote)",
    "SMB / File Sharing": "T1021.002 (SMB Shares)",
    "NFS Server": "T1021.002 (Network Shares)",
    "Print Service (CUPS)": "T1210 (Print Service)",
    "Telnet Service": "T1021 (Unencrypted Remote)",
    "Shared Folders": "T1021.002 (SMB/Network Shares)",
    "Sensitive Paths": "T1552.001 (Credentials in Files)",
    "NTLM Configuration": "T1557.001 (NTLM Relay)",
    "Proxy Configuration": "T1090 (Traffic Proxy)",
    "SSL/TLS Interception": "T1557 (AiTM / TLS MITM)",
    "Suspicious Activity": "T1055 (Process Anomaly)",
}


def _row(element: str, status: str, reference: str, result: str, mitre: str | None = None) -> dict:
    mitre_val = (
        (mitre or MITRE_MAP.get(element, "–"))
        if result == "Fail"
        else "–"
    )
    return {
        "element": element,
        "status": status,
        "reference": reference,
        "result": result,
        "mitre": mitre_val,
    }


def _eval_remote_value(element: str, raw_val: str | None, reference: str = "Remote Access") -> dict:
    """Evaluate a remote_access check string into Pass / Fail / N/A."""
    if not raw_val:
        return _row(element, "Unknown", reference, "N/A")
    val = str(raw_val).strip()
    low = val.lower()

    if low in ("unknown", "unavailable", ""):
        return _row(element, "Unknown", reference, "N/A")
    if low.startswith("disabled") or low in ("not detected", "stopped", "remote disabled"):
        return _row(element, "Disabled", reference, "Pass")
    if any(
        bad in low
        for bad in (
            "high risk",
            "potentially dangerous",
            "potentially exposed",
            "exposure detected",
        )
    ):
        return _row(element, "Exposed", reference, "Fail")
    if "hardened" in low or "low risk" in low:
        return _row(element, "Hardened", reference, "Pass")
    if "moderate risk" in low or "default" in low:
        return _row(element, "Default", reference, "Pass")
    if low.startswith("running"):
        return _row(element, "Running", reference, "Fail")
    return _row(element, "Enabled", reference, "Pass")


def _extract_product_and_state(entry: str) -> tuple[str, str]:
    s = str(entry or "").strip()
    if "(" in s and s.endswith(")"):
        prod, rest = s.rsplit("(", 1)
        return prod.strip(), rest[:-1].strip()
    return s, ""


def _resolve_platform(results: dict) -> str:
    for key in (
        "endpoint_security",
        "remote_access",
        "domain_settings",
        "password_policy",
        "system_settings",
    ):
        sec = results.get(key)
        if isinstance(sec, dict):
            plat = sec.get("platform")
            if not plat and isinstance(sec.get("system"), dict):
                plat = sec["system"].get("platform")
            if plat:
                return str(plat)
    return platform.system()


def _resolve_hostname(results: dict) -> str:
    for key in (
        "system_settings",
        "endpoint_security",
        "domain_settings",
        "remote_access",
    ):
        sec = results.get(key)
        if isinstance(sec, dict):
            host = sec.get("hostname")
            if not host and isinstance(sec.get("system"), dict):
                host = sec["system"].get("hostname")
            if host:
                return str(host)
    return socket.gethostname() or "Unknown Host"


def build_summary_report(
    results: dict,
    hostname: str | None = None,
    timestamp: datetime | None = None,
) -> dict:
    """Build a structured Pass / Fail / N/A summary report from FullAudit results."""
    data = results if isinstance(results, dict) else {}
    os_name = _resolve_platform(data)
    is_win = os_name == "Windows"
    is_mac = os_name == "Darwin"
    resolved_host = hostname or _resolve_hostname(data)
    ts = (timestamp or datetime.now()).replace(microsecond=0)

    end_checks = (
        data.get("endpoint_security", {}).get("checks", {})
        if isinstance(data.get("endpoint_security"), dict)
        else {}
    )
    rem_checks = (
        data.get("remote_access", {}).get("checks", {})
        if isinstance(data.get("remote_access"), dict)
        else {}
    )
    dgm = data.get("gateway_discovery") if isinstance(data.get("gateway_discovery"), dict) else {}
    dsa = data.get("domain_settings") if isinstance(data.get("domain_settings"), dict) else {}
    pwd = data.get("password_policy") if isinstance(data.get("password_policy"), dict) else {}
    smb = data.get("shared_folders") if isinstance(data.get("shared_folders"), dict) else {}
    pth = data.get("sensitive_paths") if isinstance(data.get("sensitive_paths"), dict) else {}
    prx = data.get("suspicious_proxy") if isinstance(data.get("suspicious_proxy"), dict) else {}
    ssl_res = data.get("ssl_interception") if isinstance(data.get("ssl_interception"), dict) else {}
    prc = data.get("suspicious_processes") if isinstance(data.get("suspicious_processes"), dict) else {}

    rows: list[dict] = []

    # 1. Endpoint Protection
    if end_checks:
        ep_items = end_checks.get("Endpoint Protection") or []
        def_items = end_checks.get("Windows Defender") or []
        active_prod = None
        inactive_prod = None
        for entry in list(ep_items) + list(def_items):
            prod, st = _extract_product_and_state(entry)
            if st.lower() in ("active", "enabled", "running", "on"):
                active_prod = prod or entry
                break
            if st.lower() in ("inactive", "disabled", "off") and not inactive_prod:
                inactive_prod = prod or entry

        if active_prod:
            rows.append(_row("Endpoint Protection", "Operates", active_prod, "Pass"))
        elif inactive_prod:
            rows.append(_row("Endpoint Protection", "Inactive", inactive_prod, "Fail"))
        elif not is_win and end_checks.get("Mandatory Access Control"):
            mac_val = str(end_checks["Mandatory Access Control"])
            mac_ok = any(t in mac_val.lower() for t in ("enabled", "enforcing"))
            rows.append(
                _row(
                    "Endpoint Protection",
                    "Operates" if mac_ok else "Inactive",
                    mac_val,
                    "Pass" if mac_ok else "Fail",
                )
            )
        else:
            rows.append(_row("Endpoint Protection", "Unknown", "Not Verified", "N/A"))

    # 2. Host-based Firewall
    if end_checks and "Host-based Firewall" in end_checks:
        fw_raw = str(end_checks.get("Host-based Firewall") or "Unknown")
        fw_prod, fw_st = _extract_product_and_state(fw_raw)
        fw_low = fw_raw.lower()
        if fw_st.lower() in ("on", "enabled", "active") or "on" == fw_low:
            rows.append(_row("Host-based Firewall", "Operates", fw_prod or "Host Firewall", "Pass"))
        elif "partially" in fw_low:
            rows.append(_row("Host-based Firewall", "Partial", fw_prod or "Host Firewall", "Fail"))
        elif fw_st.lower() in ("off", "disabled", "inactive") or "off" in fw_low:
            rows.append(_row("Host-based Firewall", "Inactive", fw_prod or "Host Firewall", "Fail"))
        else:
            rows.append(_row("Host-based Firewall", "Unknown", fw_prod or "Host Firewall", "N/A"))

    # 3. Network Gateway
    if dgm and "error" not in dgm:
        gw = dgm.get("gateway") or {}
        exp = dgm.get("exposure") or {}
        gw_ip = str(gw.get("ip") or "")
        vendor = str(gw.get("vendor") or "Default Gateway")
        vendor_clean = vendor.split("(", 1)[0].strip() or vendor
        mgmt = str(exp.get("management_ports") or "").lower()
        if not gw_ip or gw_ip in ("Not Found", "Unavailable", "Unknown"):
            rows.append(_row("Network Gateway", "NotFound", "No Gateway", "N/A"))
        elif any(tok in mgmt for tok in ("telnet exposed", "http exposed", "api exposed")):
            rows.append(_row("Network Gateway", "Exposed", vendor_clean, "Fail"))
        else:
            rows.append(_row("Network Gateway", "Operates", vendor_clean, "Pass"))

    # 4. Auto Screen Lock
    if end_checks and "Auto Screen Lock" in end_checks:
        asl = str(end_checks.get("Auto Screen Lock") or "Unknown")
        asl_l = asl.lower()
        ref = asl.split("(", 1)[1].rstrip(")") if "(" in asl else asl
        if asl_l.startswith(("enforced", "enabled", "default")):
            rows.append(_row("Auto Screen Lock", "Operates", ref, "Pass"))
        elif asl_l.startswith("disabled"):
            rows.append(_row("Auto Screen Lock", "Inactive", ref, "Fail"))
        else:
            rows.append(_row("Auto Screen Lock", "Unknown", "Screen Lock", "N/A"))

    # 5. Elevation Prompt (UAC / MAC / Gatekeeper)
    if end_checks:
        if is_win and "UAC Elevation" in end_checks:
            uac = str(end_checks.get("UAC Elevation") or "Unknown")
            uac_l = uac.lower()
            if uac_l in ("disabled", "not found") or "without prompting" in uac_l:
                rows.append(_row("Elevation Prompt", "Inactive", "UAC Protection", "Fail"))
            elif uac_l == "unknown":
                rows.append(_row("Elevation Prompt", "Unknown", "UAC Protection", "N/A"))
            else:
                rows.append(_row("Elevation Prompt", "Enforced", "UAC Protection", "Pass"))
        elif is_mac and "Gatekeeper" in end_checks:
            gk = str(end_checks.get("Gatekeeper") or "Unknown").lower()
            if gk == "enabled":
                rows.append(_row("Elevation Prompt", "Enforced", "Gatekeeper", "Pass"))
            elif gk == "disabled":
                rows.append(_row("Elevation Prompt", "Inactive", "Gatekeeper", "Fail"))
            else:
                rows.append(_row("Elevation Prompt", "Unknown", "Gatekeeper", "N/A"))
        elif "Mandatory Access Control" in end_checks:
            mac_v = str(end_checks.get("Mandatory Access Control") or "Unknown")
            mac_l = mac_v.lower()
            if "enabled" in mac_l or "enforcing" in mac_l:
                rows.append(_row("Elevation Prompt", "Enforced", mac_v, "Pass"))
            elif "disabled" in mac_l or "permissive" in mac_l:
                rows.append(_row("Elevation Prompt", "Inactive", mac_v, "Fail"))
            else:
                rows.append(_row("Elevation Prompt", "Unknown", "AppArmor / SELinux", "N/A"))

    # 6. Memory Integrity (Core Isolation / ASLR / SIP)
    if end_checks:
        if is_win and "Core Isolation" in end_checks:
            ci = str(end_checks.get("Core Isolation") or "Unknown").lower()
            if ci == "enabled":
                rows.append(_row("Memory Integrity", "Enforced", "Core Isolation", "Pass"))
            elif ci.startswith("disabled"):
                rows.append(_row("Memory Integrity", "Inactive", "Core Isolation", "Fail"))
            else:
                rows.append(_row("Memory Integrity", "Unknown", "Core Isolation", "N/A"))
        elif is_mac and "System Integrity Protection" in end_checks:
            sip = str(end_checks.get("System Integrity Protection") or "Unknown").lower()
            if sip == "enabled":
                rows.append(_row("Memory Integrity", "Enforced", "SIP", "Pass"))
            elif sip == "disabled":
                rows.append(_row("Memory Integrity", "Inactive", "SIP", "Fail"))
            else:
                rows.append(_row("Memory Integrity", "Unknown", "SIP", "N/A"))
        elif "Kernel Hardening (ASLR)" in end_checks:
            aslr = str(end_checks.get("Kernel Hardening (ASLR)") or "Unknown").lower()
            if aslr.startswith("enabled"):
                rows.append(_row("Memory Integrity", "Enforced", "Kernel ASLR", "Pass"))
            elif aslr.startswith("disabled"):
                rows.append(_row("Memory Integrity", "Inactive", "Kernel ASLR", "Fail"))
            else:
                rows.append(_row("Memory Integrity", "Unknown", "Kernel ASLR", "N/A"))

    # 7. Boot Security Layer
    if end_checks and "UEFI Secure Boot" in end_checks:
        sb = str(end_checks.get("UEFI Secure Boot") or "Unknown").lower()
        if sb == "enabled":
            rows.append(_row("Boot Security Layer", "Enforced", "UEFI Secure Boot", "Pass"))
        elif sb == "disabled":
            rows.append(_row("Boot Security Layer", "Inactive", "UEFI Secure Boot", "Fail"))
        else:
            rows.append(_row("Boot Security Layer", "N/A", "UEFI Secure Boot", "N/A"))

    # 8. System Restore / Snapshots / Time Machine
    if end_checks:
        for key, ref_name in (
            ("System Restore", "Restore Point"),
            ("System Snapshots", "System Snapshots"),
            ("Time Machine Backups", "Time Machine"),
        ):
            if key in end_checks:
                sr = str(end_checks.get(key) or "Unknown").lower()
                if sr.startswith(("enabled", "available")):
                    rows.append(_row("System Restore", "Operates", ref_name, "Pass"))
                elif sr.startswith(("disabled", "not detected")):
                    rows.append(_row("System Restore", "Inactive", ref_name, "Fail"))
                else:
                    rows.append(_row("System Restore", "N/A", ref_name, "N/A"))
                break

    # 9. Disk Encryption (BitLocker / LUKS / FileVault)
    if end_checks:
        for key, ref_name in (
            ("BitLocker Drive Encryption", "Enterprise Related"),
            ("Disk Encryption", "LUKS / dm-crypt"),
            ("FileVault Disk Encryption", "FileVault"),
        ):
            if key in end_checks:
                de = str(end_checks.get(key) or "Unknown").lower()
                if de.startswith("enabled"):
                    rows.append(_row("Disk Encryption", "Enforced", ref_name, "Pass"))
                elif de.startswith(("disabled", "not detected")):
                    rows.append(_row("Disk Encryption", "Inactive", ref_name, "Fail"))
                else:
                    rows.append(_row("Disk Encryption", "Unknown", ref_name, "N/A"))
                break

    # 10. LAPS Protection (Windows)
    if dsa and "error" not in dsa and is_win:
        laps = dsa.get("laps") or {}
        laps_vals = laps.get("value") if isinstance(laps, dict) else None
        configured = isinstance(laps_vals, list) and any(
            isinstance(p, dict) and p.get("configured") is True for p in laps_vals
        )
        if configured:
            rows.append(_row("LAPS Protection", "Enforced", "Enterprise Related", "Pass"))
        else:
            rows.append(_row("LAPS Protection", "Inactive", "Enterprise Related", "Fail"))

    # 11. Domain Settings
    aff_label = "Workgroup (Local)" if is_win else "Local (Standalone)"
    if dsa and "error" not in dsa:
        aff = dsa.get("affiliation") or {}
        aff_val = aff.get("value") if isinstance(aff, dict) else None
        if isinstance(aff_val, dict):
            atype = str(aff_val.get("type") or "")
            aname = str(aff_val.get("name") or "")
            atype_l = atype.lower()
            if "hybrid" in atype_l:
                aff_label = f"Hybrid ({aname})" if aname else "Hybrid AD"
                rows.append(_row("Domain Settings", "Enforced", aff_label, "Pass"))
            elif "entra" in atype_l:
                aff_label = f"Entra ID ({aname})" if aname else "Entra ID"
                rows.append(_row("Domain Settings", "Enforced", aff_label, "Pass"))
            elif any(
                tok in atype_l
                for tok in (
                    "active directory",
                    "domain",
                    "realm",
                    "sssd",
                    "freeipa",
                    "directory",
                    "ldap",
                    "nis",
                )
            ):
                aff_label = f"Domain ({aname})" if aname else (atype or "Domain")
                rows.append(_row("Domain Settings", "Enforced", aff_label, "Pass"))
            else:
                aff_label = "Workgroup (Local)" if is_win else "Local (Standalone)"
                rows.append(_row("Domain Settings", "Default", aff_label, "Pass"))
        else:
            rows.append(_row("Domain Settings", "Unknown", "Affiliation", "N/A"))

    # 12. Password Policy
    if pwd and "error" not in pwd:
        settings = pwd.get("settings") or {}
        min_len = (settings.get("minimum_length") or {}).get("value")
        comp = (settings.get("complexity") or {}).get("value")
        req = (settings.get("password_required") or {}).get("value")
        lockout = (settings.get("lockout_threshold") or {}).get("value")
        hello_raw = str((settings.get("pin_or_biometrics") or {}).get("value") or "")
        hello_active = hello_raw.lower().startswith("enabled")
        lockout_active = isinstance(lockout, int) and lockout > 0
        comp_enabled = (comp is True) or (
            isinstance(comp, (dict, list)) and len(comp) > 0
        )

        if req is False:
            rows.append(_row("Password Policy", "Minimal", aff_label, "Fail"))
        elif isinstance(min_len, int) and min_len < 8:
            if hello_active and lockout_active:
                rows.append(_row("Password Policy", "Moderate", aff_label, "Pass"))
            else:
                rows.append(_row("Password Policy", "Minimal", aff_label, "Fail"))
        elif comp is False:
            if hello_active:
                rows.append(_row("Password Policy", "Moderate", aff_label, "Pass"))
            else:
                rows.append(_row("Password Policy", "Minimal", aff_label, "Fail"))
        elif isinstance(min_len, int) and min_len >= 8:
            status_lbl = "Strong" if (comp_enabled and lockout_active) else "Moderate"
            rows.append(_row("Password Policy", status_lbl, aff_label, "Pass"))
        elif comp_enabled:
            status_lbl = "Strong" if lockout_active else "Moderate"
            rows.append(_row("Password Policy", status_lbl, aff_label, "Pass"))
        else:
            rows.append(_row("Password Policy", "Unknown", aff_label, "N/A"))

    # 13. Remote Access rows
    if rem_checks:
        if is_win:
            win_rem_map = (
                ("Bluetooth Component", "Bluetooth"),
                ("PowerShell Remoting", "PowerShell Remoting"),
                ("RPC Print Spooler", "RPC Print Spooler"),
                ("SMBv1 Protocol", "SMB1"),
                ("SMBv2 Protocol", "SMB2"),
                ("FTP Service", "FTP Service"),
                ("DCOM Service", "DCOM"),
                ("WinRM Service", "WinRM"),
                ("Remote Desktop", "Remote Desktop"),
            )
            for label, key in win_rem_map:
                if key in rem_checks:
                    rows.append(_eval_remote_value(label, rem_checks.get(key)))
        elif is_mac:
            mac_rem_map = (
                ("Bluetooth Component", "Bluetooth"),
                ("SSH Service", "SSH (Remote Login)"),
                ("Remote Desktop", "Screen Sharing (VNC)"),
                ("SMB / File Sharing", "File Sharing (SMB)"),
                ("FTP Service", "FTP / TFTP Service"),
                ("Print Service (CUPS)", "Print Sharing (CUPS)"),
            )
            for label, key in mac_rem_map:
                if key in rem_checks:
                    rows.append(_eval_remote_value(label, rem_checks.get(key)))
        else:
            lin_rem_map = (
                ("Bluetooth Component", "Bluetooth"),
                ("SSH Service", "SSH Service"),
                ("Remote Desktop", "Remote Desktop (XRDP / VNC)"),
                ("SMB / File Sharing", "SMB / Samba"),
                ("NFS Server", "NFS Server"),
                ("FTP Service", "FTP / TFTP Service"),
                ("Print Service (CUPS)", "Print Service (CUPS)"),
                ("Telnet Service", "Telnet Service"),
            )
            for label, key in lin_rem_map:
                if key in rem_checks:
                    rows.append(_eval_remote_value(label, rem_checks.get(key)))

    # 14. Shared Folders (-smb)
    if smb and "error" not in smb:
        exposed_cnt = int(smb.get("exposed_count") or 0)
        total_cnt = int(smb.get("count") or 0)
        if exposed_cnt > 0:
            rows.append(_row("Shared Folders", "Exposed", f"{exposed_cnt} Exposed Share(s)", "Fail"))
        elif total_cnt == 0:
            rows.append(_row("Shared Folders", "None", "File Sharing", "Pass"))
        else:
            rows.append(_row("Shared Folders", "Hardened", f"{total_cnt} Restricted Share(s)", "Pass"))

    # 15. Sensitive Paths (-pth)
    if pth and "error" not in pth:
        ps = pth.get("summary") or {}
        high_cnt = int(ps.get("high") or 0)
        med_cnt = int(ps.get("medium") or 0)
        total_cnt = int(ps.get("total_count") or 0)
        if high_cnt > 0:
            rows.append(_row("Sensitive Paths", "Exposed", f"{high_cnt} High Risk File(s)", "Fail"))
        elif total_cnt == 0:
            rows.append(_row("Sensitive Paths", "NoDetect", "File Exposure", "Pass"))
        else:
            ref_txt = f"{med_cnt} Med / {total_cnt} Total" if med_cnt else f"{total_cnt} Low Risk File(s)"
            rows.append(_row("Sensitive Paths", "Low Risk", ref_txt, "Pass"))

    # 16. NTLM Configuration (Windows)
    if dsa and "error" not in dsa and is_win:
        ntlm = dsa.get("ntlm_policy") or {}
        ntlm_val = ntlm.get("value") if isinstance(ntlm, dict) else None
        verdict = str((ntlm_val or {}).get("verdict") or "") if isinstance(ntlm_val, dict) else ""
        vl = verdict.lower()
        if vl.startswith("strong"):
            rows.append(_row("NTLM Configuration", "Strong", "Network Security", "Pass"))
        elif vl.startswith("moderate"):
            rows.append(_row("NTLM Configuration", "Moderate", "Network Security", "Pass"))
        elif vl.startswith(("critical", "warning")):
            rows.append(_row("NTLM Configuration", "Weak", "Network Security", "Fail"))
        else:
            rows.append(_row("NTLM Configuration", "Unknown", "Network Security", "N/A"))

    # 17. Proxy Configuration (-prx)
    if prx and "error" not in prx:
        analysis = prx.get("analysis") or {}
        pv = str(analysis.get("verdict") or "Unknown")
        if pv == "Not Detected":
            rows.append(_row("Proxy Configuration", "NoDetect", "Network Security", "Pass"))
        elif pv == "Likely Legitimate":
            rows.append(_row("Proxy Configuration", "Authorized", "Network Security", "Pass"))
        elif pv == "Suspicious":
            rows.append(_row("Proxy Configuration", "Detected", "Network Security", "Fail"))
        else:
            rows.append(_row("Proxy Configuration", "Unknown", "Network Security", "N/A"))

    # 18. SSL/TLS Interception (-ssl)
    if ssl_res and "error" not in ssl_res:
        sv = str(ssl_res.get("verdict") or "Unknown")
        if sv == "Not Detected":
            rows.append(_row("SSL/TLS Interception", "NoDetect", "Network Security", "Pass"))
        elif sv == "Likely Legitimate":
            rows.append(_row("SSL/TLS Interception", "Authorized", "Network Security", "Pass"))
        elif sv == "Suspicious":
            rows.append(_row("SSL/TLS Interception", "Detected", "Network Security", "Fail"))
        else:
            rows.append(_row("SSL/TLS Interception", "Unknown", "Network Security", "N/A"))

    # 19. Suspicious Activity (-prc)
    if prc and "error" not in prc:
        p_sum = prc.get("summary") or {}
        flagged_cnt = int(p_sum.get("flagged_count") or 0)
        if flagged_cnt > 0:
            rows.append(_row("Suspicious Activity", "Detected", "Process Security", "Fail"))
        else:
            rows.append(_row("Suspicious Activity", "NoDetect", "Process Security", "Pass"))

    pass_cnt = sum(1 for r in rows if r["result"] == "Pass")
    fail_cnt = sum(1 for r in rows if r["result"] == "Fail")
    na_cnt = sum(1 for r in rows if r["result"] == "N/A")

    return {
        "hostname": resolved_host,
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "counts": {
            "pass": pass_cnt,
            "fail": fail_cnt,
            "na": na_cnt,
        },
        "rows": rows,
    }


def _clip(text: str, width: int) -> str:
    s = str(text if text is not None else "Unknown").strip()
    if len(s) <= width:
        return s
    return s[: max(1, width - 3)].rstrip() + "..."


def format_summary_report(summary: dict) -> str:
    """Render the 5-column Summary Report table matching secuditor-lite layout."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "–".encode(encoding)
        dash = "–"
    except (UnicodeEncodeError, LookupError):
        dash = "-"

    w_elem, w_stat, w_ref, w_res, w_mitre = 21, 9, 22, 6, 35
    total_w = w_elem + 2 + w_stat + 2 + w_ref + 2 + w_res + 2 + w_mitre  # 101
    sep = " " + (dash * total_w)

    hostname = summary.get("hostname") or "Unknown Host"
    ts_str = summary.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = summary.get("counts") or {}
    pass_cnt = counts.get("pass", 0)
    fail_cnt = counts.get("fail", 0)
    na_cnt = counts.get("na", 0)
    rows = summary.get("rows") or []

    lines = [
        "",
        f" Summary Report {dash} {hostname}  |  {ts_str}  |  "
        f"Pass: {pass_cnt}   Fail: {fail_cnt}   N/A: {na_cnt}",
        sep,
        (
            f" {'Security Element':<{w_elem}}  "
            f"{'Status':<{w_stat}}  "
            f"{'Reference':<{w_ref}}  "
            f"{'Result':<{w_res}}  "
            f"{'MITRE ATT&CK':<{w_mitre}}"
        ).rstrip(),
        sep,
    ]

    for r in rows:
        elem = _clip(r.get("element", "Unknown"), w_elem)
        stat = _clip(r.get("status", "Unknown"), w_stat)
        ref = _clip(r.get("reference", "Default"), w_ref)
        res = _clip(r.get("result", "Unknown"), w_res)
        mitre_raw = r.get("mitre") or dash
        if dash == "-":
            mitre_raw = mitre_raw.replace("–", "-")
        mitre = _clip(mitre_raw, w_mitre)
        lines.append(
            f" {elem:<{w_elem}}  {stat:<{w_stat}}  {ref:<{w_ref}}  "
            f"{res:<{w_res}}  {mitre:<{w_mitre}}".rstrip()
        )

    return "\n".join(lines)
