"""Optional live inventory adapters. Keep permissions read-only."""


def aws_inventory(session=None):
    import boto3
    session=session or boto3.Session()
    s3=session.client("s3")
    resources=[]
    for bucket in s3.list_buckets().get("Buckets",[]):
        name=bucket["Name"]
        encryption=True
        try: s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ClientError: encryption=False
        resources.append({"provider":"aws","id":name,"type":"storage","public":False,
            "encrypted":encryption,"tags":{}})
    return {"provider":"aws","resources":resources}


def azure_inventory(subscription_id:str,credential=None):
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    credential=credential or DefaultAzureCredential()
    client=ResourceManagementClient(credential,subscription_id)
    return {"provider":"azure","resources":[{"provider":"azure","id":r.id,"type":"resource",
        "tags":r.tags or {}} for r in client.resources.list()]}
