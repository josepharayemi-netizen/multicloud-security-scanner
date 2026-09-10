from scanner.models import Finding

CONTROLS = {
    "STORAGE_PUBLIC": ("Public object storage prohibited","CRITICAL","Disable public access and use scoped identities.",["CIS","NIST PR.AC"]),
    "ENCRYPTION_REQUIRED": ("Encryption at rest required","HIGH","Enable provider-managed or customer-managed encryption.",["CIS","NIST PR.DS"]),
    "MGMT_PORT_EXPOSED": ("Management ports restricted","CRITICAL","Remove internet exposure; use private access, VPN or bastion.",["CIS","NIST PR.AC"]),
    "MFA_REQUIRED": ("Multi-factor authentication enabled","HIGH","Require phishing-resistant MFA for privileged identities.",["CIS","NIST PR.AC"]),
    "AUDIT_LOGGING": ("Audit logging enabled","HIGH","Enable centralized, protected and retained audit logs.",["CIS","NIST DE.CM"]),
    "DATABASE_PUBLIC": ("Database public access prohibited","CRITICAL","Disable public networking and use private endpoints.",["CIS","NIST PR.AC"]),
    "BACKUP_REQUIRED": ("Backup and retention enabled","MEDIUM","Configure tested backups and an approved retention period.",["NIST PR.IP"]),
    "OWNER_TAG": ("Resource ownership metadata present","LOW","Add an owner tag for accountability and routing.",["Governance"]),
}


def finding(control_id, resource, evidence):
    title,severity,remediation,frameworks=CONTROLS[control_id]
    return Finding(control_id,title,severity,resource["provider"],resource["id"],
        evidence,remediation,frameworks)
