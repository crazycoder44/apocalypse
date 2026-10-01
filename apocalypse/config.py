import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(env_path: Path | None = None) -> None:
    """Lightweight built-in .env parser without requiring external dependencies."""
    if env_path is None:
        env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    try:
        content = env_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            # Only set if not already present in the active environment
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception:
        pass


# Auto-load .env when config module is imported
load_dotenv()


@dataclass(frozen=True)
class Settings:
    tenant_id: str = os.getenv("APOCALYPSE_TENANT_ID", "")
    client_id: str = os.getenv("APOCALYPSE_CLIENT_ID", "")
    client_secret: str = os.getenv("APOCALYPSE_CLIENT_SECRET", "")
    lookback_hours: int = int(os.getenv("APOCALYPSE_LOOKBACK_HOURS", "24"))
    max_records: int = int(os.getenv("APOCALYPSE_MAX_RECORDS", "100"))
    defender_url: str = os.getenv(
        "APOCALYPSE_DEFENDER_URL",
        "https://api.security.microsoft.com/api/incidents",
    )
    sentinel_url: str = os.getenv("APOCALYPSE_SENTINEL_URL", "")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    groq_reasoning_effort: str = os.getenv("GROQ_REASONING_EFFORT", "medium")

    def validate_live(self) -> None:
        missing = [name for name, value in {
            "APOCALYPSE_TENANT_ID": self.tenant_id,
            "APOCALYPSE_CLIENT_ID": self.client_id,
            "APOCALYPSE_CLIENT_SECRET": self.client_secret,
        }.items() if not value]
        if missing:
            raise ValueError("Missing environment variables: " + ", ".join(missing))