from __future__ import annotations

import json
import os
import secrets
import base64
from pathlib import Path
from typing import Optional, Union

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

app = FastAPI(title="Subscription JSON Storage")


def _storage_root() -> Path:
    configured = os.getenv("SUB_SERVICE_ROOT", "").strip()
    if configured:
        return Path(configured)
    return PROJECT_ROOT / "storage"


def _public_base_url() -> str:
    value = (
        os.getenv("SUB_SERVICE_PUBLIC_BASE_URL")
        or os.getenv("SUB_SERVICE_DOMAIN")
        or ""
    ).strip().rstrip("/")
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


def _path_prefix() -> str:
    prefix = os.getenv("SUB_SERVICE_PATH_PREFIX", "/keys").strip() or "/keys"
    return "/" + prefix.strip("/")


def _service_token() -> str:
    return os.getenv("SUB_SERVICE_TOKEN", "").strip()


def _profile_title_header() -> str:
    title = os.getenv("SUB_SERVICE_PROFILE_TITLE", "🔥BlackGate🔥").strip()
    try:
        title.encode("latin-1")
        return title
    except UnicodeEncodeError:
        encoded_title = base64.b64encode(title.encode("utf-8")).decode("ascii")
        return f"base64:{encoded_title}"


def _sanitize(value: str) -> str:
    cleaned = "".join(ch for ch in str(value or "") if ch in SAFE_CHARS)
    if not cleaned:
        raise HTTPException(status_code=400, detail="path_id/token invalid")
    return cleaned


def _make_path_id() -> str:
    return str(secrets.randbelow(9_000_000_000) + 1_000_000_000)


def _make_token() -> str:
    return secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16]


def _json_path(path_id: str, token: str) -> Path:
    return _storage_root() / _sanitize(path_id) / _sanitize(token)


def _public_url(path_id: str, token: str) -> str:
    base_url = _public_base_url()
    suffix = f"{_path_prefix()}/{_sanitize(path_id)}/{_sanitize(token)}"
    return f"{base_url}{suffix}" if base_url else suffix


def require_api_token(authorization: str = Header(default="")) -> None:
    expected = _service_token()
    if not expected:
        return
    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Unauthorized")


class JsonDocumentIn(BaseModel):
    content: Union[object, str]
    path_id: Optional[str] = None
    token: Optional[str] = None


class JsonDocumentOut(BaseModel):
    path_id: str
    token: str
    public_url: str
    content: Optional[str] = None


def normalize_json_content(content: Union[object, str]) -> str:
    if isinstance(content, str):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            return content
    else:
        parsed = content

    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))


def save_json(path_id: str, token: str, content: Union[object, str]) -> JsonDocumentOut:
    safe_path_id = _sanitize(path_id)
    safe_token = _sanitize(token)
    body = normalize_json_content(content)
    target_path = _json_path(safe_path_id, safe_token)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(body, encoding="utf-8")
    return JsonDocumentOut(
        path_id=safe_path_id,
        token=safe_token,
        public_url=_public_url(safe_path_id, safe_token),
    )


def read_json(path_id: str, token: str) -> str:
    target_path = _json_path(path_id, token)
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="JSON not found")
    return target_path.read_text(encoding="utf-8")


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/api/json", response_model=JsonDocumentOut, dependencies=[Depends(require_api_token)])
async def create_json(payload: JsonDocumentIn) -> JsonDocumentOut:
    path_id = payload.path_id or _make_path_id()
    token = payload.token or _make_token()
    return save_json(path_id, token, payload.content)


@app.put(
    "/api/json/{path_id}/{token}",
    response_model=JsonDocumentOut,
    dependencies=[Depends(require_api_token)],
)
async def upsert_json(path_id: str, token: str, payload: JsonDocumentIn) -> JsonDocumentOut:
    return save_json(path_id, token, payload.content)


@app.get(
    "/api/json/{path_id}/{token}",
    response_model=JsonDocumentOut,
    dependencies=[Depends(require_api_token)],
)
async def get_json_metadata(path_id: str, token: str) -> JsonDocumentOut:
    content = read_json(path_id, token)
    safe_path_id = _sanitize(path_id)
    safe_token = _sanitize(token)
    return JsonDocumentOut(
        path_id=safe_path_id,
        token=safe_token,
        public_url=_public_url(safe_path_id, safe_token),
        content=content,
    )


@app.delete("/api/json/{path_id}/{token}", dependencies=[Depends(require_api_token)])
async def delete_json(path_id: str, token: str) -> dict[str, bool]:
    target_path = _json_path(path_id, token)
    if target_path.exists():
        target_path.unlink()
        try:
            target_path.parent.rmdir()
        except OSError:
            pass
    return {"success": True}


@app.get(_path_prefix() + "/{path_id}/{token}")
async def serve_json(path_id: str, token: str) -> PlainTextResponse:
    return PlainTextResponse(
        read_json(path_id, token),
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "Profile-Title": _profile_title_header(),
            "Profile-Update-Interval": "5",
        },
    )


@app.get(_path_prefix() + "/{path_id}/{token}/")
async def serve_json_with_trailing_slash(path_id: str, token: str) -> PlainTextResponse:
    return await serve_json(path_id, token)


@app.get("/keys-v2/{path_id}/{token}")
async def serve_json_v2(path_id: str, token: str) -> PlainTextResponse:
    return await serve_json(path_id, token)


@app.get("/keys-v2/{path_id}/{token}/")
async def serve_json_v2_with_trailing_slash(path_id: str, token: str) -> PlainTextResponse:
    return await serve_json(path_id, token)
