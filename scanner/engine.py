from collections import Counter
from scanner.controls import finding

MANAGEMENT_PORTS={22,3389,5985,5986}


def assess(resource:dict):
    results=[]; kind=resource.get("type")
    if kind=="storage":
        if resource.get("public",False): results.append(finding("STORAGE_PUBLIC",resource,"public=true"))
        if not resource.get("encrypted",False): results.append(finding("ENCRYPTION_REQUIRED",resource,"encrypted=false"))
    if kind=="network_rule":
        ports=set(resource.get("ports",[]))
        if resource.get("source") in {"0.0.0.0/0","::/0"} and ports & MANAGEMENT_PORTS:
            results.append(finding("MGMT_PORT_EXPOSED",resource,f"internet source exposes {sorted(ports & MANAGEMENT_PORTS)}"))
    if kind=="identity" and resource.get("privileged",False) and not resource.get("mfa",False):
        results.append(finding("MFA_REQUIRED",resource,"privileged=true, mfa=false"))
    if kind=="audit" and not resource.get("enabled",False):
        results.append(finding("AUDIT_LOGGING",resource,"enabled=false"))
    if kind=="database":
        if resource.get("public",False): results.append(finding("DATABASE_PUBLIC",resource,"public=true"))
        if not resource.get("encrypted",False): results.append(finding("ENCRYPTION_REQUIRED",resource,"encrypted=false"))
        if not resource.get("backup",False): results.append(finding("BACKUP_REQUIRED",resource,"backup=false"))
    if not resource.get("tags",{}).get("owner"):
        results.append(finding("OWNER_TAG",resource,"owner tag absent"))
    return results


def scan(inventory:dict):
    findings=[item for resource in inventory.get("resources",[]) for item in assess(resource)]
    counts=Counter(item.severity for item in findings)
    weighted=sum(counts[s]*w for s,w in {"CRITICAL":25,"HIGH":10,"MEDIUM":4,"LOW":1}.items())
    score=max(0,100-weighted)
    return {"provider":inventory.get("provider","unknown"),"resources_scanned":len(inventory.get("resources",[])),
        "security_score":score,"summary":dict(counts),"findings":[item.to_dict() for item in findings]}
