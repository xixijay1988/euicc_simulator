"""Simulator configuration — read from config.yaml and env vars."""

from pathlib import Path
import yaml
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    tcp_start_port: int = Field(default=9000, description="First TCP port for raw APDU")
    http_port: int = Field(default=8100, description="FastAPI HTTP port")
    host: str = Field(default="0.0.0.0")
    tcp_max_connections: int = Field(default=100)


class EuiccDefaults(BaseModel):
    svn: str = "3.1.0"
    profile_version: str = "2.3.1"
    iot_version: str = "1.2.0"
    total_nvm: int = 524288  # 512KB
    platform_label: str = "GSMA-eSIM-Simulator"
    ipa_mode: int = 0  # 0=IPAd


class SimConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    euicc: EuiccDefaults = EuiccDefaults()
    database_url: str = "sqlite:///./esim_simulator.db"
    certs_dir: str = "./certs"
    eids: dict[int, str] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path = "config.yaml") -> "SimConfig":
        """Load config from YAML file, with env var overrides."""
        cfg_path = Path(path)
        if cfg_path.exists():
            raw = yaml.safe_load(cfg_path.read_text()) or {}
        else:
            raw = {}

        # Build nested defaults
        server = ServerConfig(**raw.get("server", {}))
        euicc = EuiccDefaults(**raw.get("euicc", {}))

        return cls(
            server=server,
            euicc=euicc,
            database_url=raw.get("database_url", "sqlite:///./esim_simulator.db"),
            certs_dir=raw.get("certs_dir", "./certs"),
            eids=raw.get("eids", {}),
        )
