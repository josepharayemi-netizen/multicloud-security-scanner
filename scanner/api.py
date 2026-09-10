from fastapi import FastAPI
from pydantic import BaseModel,Field
from scanner.engine import scan


class Inventory(BaseModel):
    provider:str
    resources:list[dict]=Field(default_factory=list)


app=FastAPI(title="Multi-Cloud Security Compliance Scanner",version="1.0.0")


@app.get("/health")
def health():
    return {"status":"healthy","mode":"read-only"}


@app.post("/scan")
def run_scan(inventory:Inventory):
    return scan(inventory.model_dump())
