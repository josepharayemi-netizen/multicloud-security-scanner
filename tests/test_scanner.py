from scanner.engine import scan


def test_detects_public_unencrypted_storage():
    result=scan({"provider":"aws","resources":[{"provider":"aws","id":"bucket","type":"storage",
        "public":True,"encrypted":False,"tags":{}}]})
    ids={f["control_id"] for f in result["findings"]}
    assert {"STORAGE_PUBLIC","ENCRYPTION_REQUIRED","OWNER_TAG"}<=ids
    assert result["security_score"]<100


def test_compliant_database_has_no_findings():
    result=scan({"provider":"azure","resources":[{"provider":"azure","id":"db","type":"database",
        "public":False,"encrypted":True,"backup":True,"tags":{"owner":"data"}}]})
    assert result["findings"]==[]
    assert result["security_score"]==100


def test_management_port_is_critical():
    result=scan({"provider":"aws","resources":[{"provider":"aws","id":"sg","type":"network_rule",
        "source":"0.0.0.0/0","ports":[22],"tags":{"owner":"security"}}]})
    assert result["summary"]["CRITICAL"]==1
