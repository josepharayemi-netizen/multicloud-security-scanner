from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    provider: str
    resource_id: str
    evidence: str
    remediation: str
    frameworks: list[str]

    def to_dict(self):
        return asdict(self)
