import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import uuid

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Try to import database helpers. If unavailable, fall back to in-memory store
USE_DB = True
try:
    from database import db, create_document, get_documents  # type: ignore
except Exception:
    USE_DB = False
    db = None  # type: ignore
    create_document = None  # type: ignore
    get_documents = None  # type: ignore

# App setup
app = FastAPI(title="Poetry Showcase API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login")

# Dev credentials
DEV_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "Irieimran")
DEV_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD_HASH")  # optional pre-hash
DEV_ADMIN_PLAIN = os.getenv("ADMIN_PASSWORD_PLAIN", "aqsayanu")

if not DEV_ADMIN_PASSWORD:
    DEV_ADMIN_PASSWORD = pwd_context.hash(DEV_ADMIN_PLAIN)

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# In-memory fallback store
_fallback_poems: List[dict] = []

# Utilities

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    if username != DEV_ADMIN_USERNAME:
        raise credentials_exception
    return {"username": username}


@app.get("/")
def root():
    return {"message": "Poetry Showcase API running", "database": "mongo" if USE_DB else "fallback"}


# Data access helpers that abstract DB vs fallback

def fetch_poems(query: Optional[Dict[str, Any]] = None) -> List[dict]:
    if USE_DB and db is not None:
        q = query or {}
        items = list(db["poem"].find(q))
        for it in items:
            it["id"] = str(it.pop("_id"))
        return items
    # fallback: naive filtering
    items = list(_fallback_poems)
    if not query:
        return items
    res: List[dict] = []
    for it in items:
        ok = True
        for k, v in query.items():
            if k == "tags" and isinstance(v, dict) and "$in" in v:
                if not any(t in it.get("tags", []) for t in v["$in"]):
                    ok = False; break
            elif k == "isFeatured":
                if bool(it.get("isFeatured")) != bool(v):
                    ok = False; break
            elif k == "$or":
                or_ok = False
                for cond in v:
                    for kk, vv in cond.items():
                        val = str(it.get(kk, ""))
                        if isinstance(vv, dict) and vv.get("$regex") is not None:
                            import re
                            pattern = vv.get("$regex", "")
                            flags = re.I if vv.get("$options") == "i" else 0
                            if re.search(pattern, val, flags):
                                or_ok = True
                        elif val == vv:
                            or_ok = True
                if not or_ok:
                    ok = False; break
            else:
                if it.get(k) != v:
                    ok = False; break
        if ok:
            res.append(it)
    return res


def insert_poem(data: dict) -> str:
    if USE_DB and db is not None:
        from database import create_document  # local import
        return create_document("poem", data)
    new_id = uuid.uuid4().hex
    _fallback_poems.append({"id": new_id, **data})
    return new_id


def update_poem_doc(poem_id: str, update: dict) -> bool:
    if USE_DB and db is not None:
        from bson import ObjectId
        res = db["poem"].update_one({"_id": ObjectId(poem_id)}, {"$set": update})
        return res.matched_count > 0
    for i, it in enumerate(_fallback_poems):
        if it.get("id") == poem_id:
            _fallback_poems[i] = {**it, **update}
            return True
    return False


def delete_poem_doc(poem_id: str) -> bool:
    if USE_DB and db is not None:
        from bson import ObjectId
        res = db["poem"].delete_one({"_id": ObjectId(poem_id)})
        return res.deleted_count > 0
    global _fallback_poems
    before = len(_fallback_poems)
    _fallback_poems = [p for p in _fallback_poems if p.get("id") != poem_id]
    return len(_fallback_poems) < before


# Public endpoints
@app.get("/poems")
async def list_poems(tag: Optional[str] = None, q: Optional[str] = None, featured: Optional[bool] = None):
    query: Dict[str, Any] = {}
    if tag:
        query["tags"] = {"$in": [tag]}
    if featured is not None:
        query["isFeatured"] = featured
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"excerpt": {"$regex": q, "$options": "i"}},
            {"content": {"$regex": q, "$options": "i"}},
        ]
    items = fetch_poems(query)
    def sort_key(x: dict):
        return x.get("createdAt") or x.get("created_at") or datetime.min
    items.sort(key=sort_key, reverse=True)
    return items


@app.get("/poems/{poem_id}")
async def get_poem(poem_id: str):
    if USE_DB and db is not None:
        from bson import ObjectId
        try:
            obj_id = ObjectId(poem_id)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid poem id")
        res = db["poem"].find_one({"_id": obj_id})
        if not res:
            raise HTTPException(status_code=404, detail="Poem not found")
        res["id"] = str(res.pop("_id"))
        return res
    # fallback
    for it in _fallback_poems:
        if it.get("id") == poem_id:
            return it
    raise HTTPException(status_code=404, detail="Poem not found")


# Auth
@app.post("/admin/login", response_model=Token)
async def admin_login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    if username != DEV_ADMIN_USERNAME or not verify_password(password, DEV_ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token, "token_type": "bearer"}


# Admin endpoints
@app.post("/admin/poems")
async def add_poem(
    title: str = Form(...),
    excerpt: str = Form(...),
    content: str = Form(...),
    tags: str = Form(""),  # comma-separated
    isFeatured: bool = Form(False),
    cover: UploadFile = File(None),
    user: dict = Depends(get_current_user),
):
    cover_path = ""
    if cover is not None:
        data = await cover.read()
        filename = f"poem_{int(datetime.now().timestamp())}_{cover.filename}"
        local_dir = "/tmp/poem_covers"
        os.makedirs(local_dir, exist_ok=True)
        full_path = os.path.join(local_dir, filename)
        with open(full_path, "wb") as f:
            f.write(data)
        cover_path = f"/uploads/{filename}"

    poem_data = {
        "title": title,
        "excerpt": excerpt,
        "content": content,
        "coverImage": cover_path,
        "tags": [t.strip() for t in tags.split(",") if t.strip()],
        "isFeatured": isFeatured,
        "createdAt": datetime.now(timezone.utc),
    }
    new_id = insert_poem(poem_data)
    return {"id": new_id, **poem_data}


@app.put("/admin/poems/{poem_id}")
async def edit_poem(
    poem_id: str,
    title: Optional[str] = Form(None),
    excerpt: Optional[str] = Form(None),
    content: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    isFeatured: Optional[bool] = Form(None),
    cover: UploadFile = File(None),
    user: dict = Depends(get_current_user),
):
    update: Dict[str, Any] = {}
    if title is not None:
        update["title"] = title
    if excerpt is not None:
        update["excerpt"] = excerpt
    if content is not None:
        update["content"] = content
    if tags is not None:
        update["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    if isFeatured is not None:
        update["isFeatured"] = isFeatured

    if cover is not None:
        data = await cover.read()
        filename = f"poem_{int(datetime.now().timestamp())}_{cover.filename}"
        local_dir = "/tmp/poem_covers"
        os.makedirs(local_dir, exist_ok=True)
        full_path = os.path.join(local_dir, filename)
        with open(full_path, "wb") as f:
            f.write(data)
        cover_path = f"/uploads/{filename}"
        update["coverImage"] = cover_path

    if not update:
        raise HTTPException(status_code=400, detail="No fields to update")

    ok = update_poem_doc(poem_id, update)
    if not ok:
        raise HTTPException(status_code=404, detail="Poem not found")
    return {"updated": True}


@app.delete("/admin/poems/{poem_id}")
async def delete_poem(poem_id: str, user: dict = Depends(get_current_user)):
    ok = delete_poem_doc(poem_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Poem not found")
    return {"deleted": True}


# Utility endpoints
@app.get("/stats")
async def stats():
    if USE_DB and db is not None:
        total = db["poem"].count_documents({})
        featured = db["poem"].count_documents({"isFeatured": True})
    else:
        total = len(_fallback_poems)
        featured = len([p for p in _fallback_poems if p.get("isFeatured")])
    return {"total": total, "featured": featured, "mode": "mongo" if USE_DB else "fallback"}


# Seed endpoint (dev)
@app.post("/seed")
async def seed():
    existing = fetch_poems({})
    if existing:
        return {"seeded": False, "message": "Already seeded"}

    samples = [
        {
            "title": "Whispers of Dusk",
            "excerpt": "Amber skies fold into night...",
            "content": "Amber skies fold into night,\nWhere city lights learn to breathe...\nAnd in the hush, a hidden light,\nFinds the quiet we leave.",
            "coverImage": "",
            "tags": ["evening", "city", "quiet"],
            "isFeatured": True,
            "createdAt": datetime.now(timezone.utc),
        },
        {
            "title": "Paper Boats",
            "excerpt": "We launch small hopes in summer rain...",
            "content": "We launch small hopes in summer rain,\nAcross the gutters' silver veins...\nThey carry names we never say,\nAnd sink before the morning.",
            "coverImage": "",
            "tags": ["childhood", "rain"],
            "isFeatured": False,
            "createdAt": datetime.now(timezone.utc),
        },
        {
            "title": "Rooms We Keep",
            "excerpt": "Every house remembers footsteps...",
            "content": "Every house remembers footsteps,\nThe soft arithmetic of leaving...\nWe dust the frames and, sometimes, forgive\nThe ghosts that do the keeping.",
            "coverImage": "",
            "tags": ["memory", "home"],
            "isFeatured": True,
            "createdAt": datetime.now(timezone.utc),
        },
    ]

    for s in samples:
        insert_poem(s)
    return {"seeded": True, "count": len(samples), "mode": "mongo" if USE_DB else "fallback"}


# Static files for uploaded covers
os.makedirs("/tmp/poem_covers", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="/tmp/poem_covers"), name="uploads")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
