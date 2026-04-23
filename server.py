"""
Agro-Secours FastAPI Backend — Version corrigée
"""
from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
UPLOADS_DIR = ROOT_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)
load_dotenv(ROOT_DIR / ".env")

import os, uuid, logging, urllib.parse, bcrypt, jwt, stripe
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, UploadFile, File
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configuration
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"].lower()
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "2290199481002")
XOF_TO_EUR_RATE = float(os.environ.get("XOF_TO_EUR_RATE", "0.00152"))
JWT_ALGO = "HS256"
ACCESS_TOKEN_TTL = 12
REFRESH_TOKEN_TTL = 7
IS_LOCAL = os.environ.get("ENV", "local") == "local"

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:8000,http://localhost:3000,http://127.0.0.1:8000,null"
).split(",") if o.strip()]

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("agrosecours")
limiter = Limiter(key_func=get_remote_address)

# Modèles Pydantic
class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    slug: str
    name_fr: str
    name_en: str
    description_fr: str
    description_en: str
    category: str
    price_xof: float = Field(..., gt=0)
    unit: str = "sachet"
    weight: str = ""
    image: str
    benefits_fr: List[str] = []
    benefits_en: List[str] = []
    is_bestseller: bool = False
    stock: int = Field(default=100, ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProductIn(BaseModel):
    slug: str = Field(..., min_length=2, max_length=100)
    name_fr: str = Field(..., min_length=2, max_length=200)
    name_en: str = Field(..., min_length=2, max_length=200)
    description_fr: str = Field(..., min_length=2)
    description_en: str = Field(..., min_length=2)
    category: str = Field(..., pattern="^(farines|huiles|poudres|graines)$")
    price_xof: float = Field(..., gt=0)
    unit: str = Field(default="sachet", max_length=50)
    weight: str = Field(default="", max_length=50)
    image: str = Field(..., min_length=5)
    benefits_fr: List[str] = []
    benefits_en: List[str] = []
    is_bestseller: bool = False
    stock: int = Field(default=100, ge=0)

class Review(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    text: str
    rating: int = 5
    date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ReviewIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    text: str = Field(..., min_length=5, max_length=1000)
    rating: int = Field(default=5, ge=1, le=5)

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)

class CartItemIn(BaseModel):
    product_id: str
    quantity: int = Field(..., ge=1)

class CheckoutIn(BaseModel):
    items: List[CartItemIn] = Field(..., min_length=1)
    origin_url: str
    customer_name: Optional[str] = None
    customer_phone: Optional[str] = None
    customer_email: Optional[EmailStr] = None

class WhatsAppOrderIn(BaseModel):
    items: List[CartItemIn] = Field(..., min_length=1)
    customer_name: Optional[str] = None
    customer_phone: Optional[str] = None

class MobileMoneyOrderIn(BaseModel):
    items: List[CartItemIn] = Field(..., min_length=1)
    customer_name: str = Field(..., min_length=2)
    customer_phone: str = Field(..., min_length=8)
    operator: str = Field(..., pattern="^(mtn|moov)$")

class OrderStatusIn(BaseModel):
    status: str = Field(..., pattern="^(paid|pending_confirmation|cancelled|completed|initiated)$")

class ConfigUpdateIn(BaseModel):
    xof_to_eur_rate: Optional[float] = Field(default=None, gt=0)
    whatsapp_number: Optional[str] = None

# Helpers Auth
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except:
        return False

def make_token(email: str, token_type: str, ttl_h: float) -> str:
    return jwt.encode(
        {"sub": email, "role": "admin", "type": token_type,
         "exp": datetime.now(timezone.utc) + timedelta(hours=ttl_h)},
        JWT_SECRET, algorithm=JWT_ALGO
    )

def create_access_token(email):
    return make_token(email, "access", ACCESS_TOKEN_TTL)

def create_refresh_token(email):
    return make_token(email, "refresh", REFRESH_TOKEN_TTL * 24)

def set_cookies(response: Response, access: str, refresh: str):
    kw = dict(httponly=True, secure=not IS_LOCAL, samesite="lax" if IS_LOCAL else "none", path="/")
    response.set_cookie("access_token", access, max_age=ACCESS_TOKEN_TTL * 3600, **kw)
    response.set_cookie("refresh_token", refresh, max_age=REFRESH_TOKEN_TTL * 86400, **kw)

async def get_current_admin(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Non authentifié")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Token invalide")
    if payload.get("role") != "admin" or payload.get("type") != "access":
        raise HTTPException(403, "Accès refusé")
    user = await db.users.find_one({"email": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(401, "Utilisateur introuvable")
    return user

async def compute_order(items: List[CartItemIn]):
    total, detail = 0.0, []
    for it in items:
        prod = await db.products.find_one({"id": it.product_id}, {"_id": 0})
        if not prod:
            raise HTTPException(400, f"Produit inconnu : {it.product_id}")
        qty = max(1, int(it.quantity))
        line = float(prod["price_xof"]) * qty
        total += line
        detail.append({
            "product_id": prod["id"], "slug": prod["slug"],
            "name_fr": prod["name_fr"], "name_en": prod["name_en"],
            "image": prod["image"], "unit_price_xof": prod["price_xof"],
            "quantity": qty, "line_total_xof": line,
        })
    return total, detail

# Seed data
SEED_PRODUCTS = [
    {"slug": "farine-soja", "name_fr": "Farine de Soja", "name_en": "Soy Flour", "description_fr": "Très riche en protéines", "description_en": "Very rich in protein", "category": "farines", "price_xof": 1500, "weight": "500g", "image": "https://images.unsplash.com/photo-1586201375761-83865001e31c?auto=format&fit=crop&w=800", "benefits_fr": ["Riche en protéines"], "benefits_en": ["Rich in protein"], "is_bestseller": True},
    {"slug": "farine-fonio", "name_fr": "Farine de Fonio", "name_en": "Fonio Flour", "description_fr": "Céréale sans gluten", "description_en": "Gluten-free cereal", "category": "farines", "price_xof": 2000, "weight": "500g", "image": "https://images.unsplash.com/photo-1509440159596-0249088772ff?auto=format&fit=crop&w=800", "benefits_fr": ["Sans gluten"], "benefits_en": ["Gluten-free"], "is_bestseller": True},
]

SEED_REVIEWS = [
    {"name": "Aïssatou K.", "text": "Produits naturels et de très bonne qualité !", "rating": 5},
    {"name": "Jean-Marc D.", "text": "Livraison rapide et service au top.", "rating": 5},
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.users.create_index("email", unique=True)
    await db.products.create_index("slug", unique=True)
    await db.payment_transactions.create_index("session_id", unique=True)
    await db.orders.create_index("id")
    await db.orders.create_index("created_at")
    await db.orders.create_index("status")
    await db.reviews.create_index("date")

    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if not existing:
        await db.users.insert_one({
            "email": ADMIN_EMAIL,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "name": "Admin Agro-Secours",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info("Admin créé")

    if await db.products.count_documents({}) == 0:
        for p in SEED_PRODUCTS:
            prod = Product(**p)
            doc = prod.model_dump()
            doc["created_at"] = doc["created_at"].isoformat()
            try:
                await db.products.insert_one(doc)
            except:
                pass
        logger.info(f"Seed: {len(SEED_PRODUCTS)} produits insérés")

    if await db.reviews.count_documents({}) == 0:
        for r in SEED_REVIEWS:
            rev = Review(**r)
            doc = rev.model_dump()
            doc["date"] = doc["date"].isoformat()
            await db.reviews.insert_one(doc)
        logger.info(f"Seed: {len(SEED_REVIEWS)} avis insérés")

    yield
    client.close()
    logger.info("MongoDB fermé")

# App
app = FastAPI(title="Agro-Secours API", lifespan=lifespan)
api = APIRouter(prefix="/api")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")

# Routes HTML
@app.get("/")
async def serve_index():
    f = ROOT_DIR / "index.html"
    if f.exists():
        return FileResponse(str(f))
    return JSONResponse({"service": "Agro-Secours API", "status": "ok"})

@app.get("/admin")
@app.get("/admin.html")
async def serve_admin():
    f = ROOT_DIR / "admin.html"
    if f.exists():
        return FileResponse(str(f))
    raise HTTPException(404, "admin.html introuvable")

@app.get("/index.html")
async def serve_index_html():
    f = ROOT_DIR / "index.html"
    if f.exists():
        return FileResponse(str(f))
    raise HTTPException(404, "index.html introuvable")

@app.exception_handler(Exception)
async def global_error(request: Request, exc: Exception):
    logger.error(f"Erreur sur {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(500, {"detail": "Erreur interne. Réessayez."})

@api.get("/")
async def root():
    return {"service": "Agro-Secours API", "status": "ok"}

@api.get("/config")
async def get_config():
    cfg = await db.config.find_one({"key": "global"}, {"_id": 0})
    rate = cfg["xof_to_eur_rate"] if cfg else XOF_TO_EUR_RATE
    wa_num = cfg["whatsapp_number"] if cfg else WHATSAPP_NUMBER
    return {"whatsapp_number": wa_num, "currency": "XOF", "eur_rate": rate}

@api.post("/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginIn, response: Response):
    email = body.email.lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        logger.warning(f"Échec connexion: {email}")
        raise HTTPException(401, "Email ou mot de passe invalide")
    access = create_access_token(email)
    refresh = create_refresh_token(email)
    set_cookies(response, access, refresh)
    logger.info(f"Connexion: {email}")
    return {"email": user["email"], "name": user.get("name"), "role": user.get("role")}

@api.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(401, "Refresh token manquant")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expirée")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Token invalide")
    if payload.get("type") != "refresh":
        raise HTTPException(403, "Token non autorisé")
    user = await db.users.find_one({"email": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(401, "Utilisateur introuvable")
    set_cookies(response, create_access_token(payload["sub"]), create_refresh_token(payload["sub"]))
    return {"email": user["email"], "name": user.get("name"), "role": user.get("role")}

@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}

@api.get("/auth/me")
async def me(user: dict = Depends(get_current_admin)):
    return user

@api.get("/products")
async def list_products(category: Optional[str] = None, page: int = 1, limit: int = 50):
    limit = min(limit, 100)
    skip = (max(page, 1) - 1) * limit
    q = {} if not category or category == "all" else {"category": category}
    total = await db.products.count_documents(q)
    items = await db.products.find(q, {"_id": 0}).skip(skip).limit(limit).to_list(limit)
    return {"total": total, "page": page, "limit": limit, "items": items}

@api.get("/products/{slug}")
async def get_product(slug: str):
    p = await db.products.find_one({"slug": slug}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Produit introuvable")
    return p

@api.post("/products", status_code=201)
async def create_product(body: ProductIn, user: dict = Depends(get_current_admin)):
    if await db.products.find_one({"slug": body.slug}):
        raise HTTPException(400, f"Slug '{body.slug}' déjà utilisé")
    prod = Product(**body.model_dump())
    doc = prod.model_dump()
    doc["created_at"] = doc["created_at"].isoformat()
    await db.products.insert_one(doc)
    doc.pop("_id", None)
    logger.info(f"Produit créé: {prod.slug} par {user['email']}")
    return doc

@api.put("/products/{slug}")
async def update_product(slug: str, body: ProductIn, user: dict = Depends(get_current_admin)):
    res = await db.products.update_one({"slug": slug}, {"$set": body.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(404, "Produit introuvable")
    p = await db.products.find_one({"slug": slug}, {"_id": 0})
    logger.info(f"Produit modifié: {slug} par {user['email']}")
    return p

@api.delete("/products/{slug}")
async def delete_product(slug: str, user: dict = Depends(get_current_admin)):
    res = await db.products.delete_one({"slug": slug})
    if res.deleted_count == 0:
        raise HTTPException(404, "Produit introuvable")
    logger.info(f"Produit supprimé: {slug} par {user['email']}")
    return {"ok": True}

@api.post("/admin/upload-image")
async def upload_image(request: Request, file: UploadFile = File(...), user: dict = Depends(get_current_admin)):
    allowed = {".jpg", ".jpeg", ".png", ".webp"}
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in allowed:
        raise HTTPException(400, "Format non supporté (JPG, PNG, WEBP)")
    content = await file.read()
    if not content:
        raise HTTPException(400, "Fichier vide")
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(400, "Image trop lourde (max 5 Mo)")
    fname = f"{uuid.uuid4().hex}{suffix}"
    (UPLOADS_DIR / fname).write_bytes(content)
    url = str(request.base_url).rstrip("/") + f"/uploads/{fname}"
    return {"url": url, "filename": fname}

@api.get("/reviews")
async def list_reviews():
    return await db.reviews.find({}, {"_id": 0}).sort("date", -1).to_list(200)

@api.post("/reviews", status_code=201)
async def create_review(body: ReviewIn):
    rev = Review(name=body.name.strip(), text=body.text.strip(), rating=body.rating)
    doc = rev.model_dump()
    doc["date"] = doc["date"].isoformat()
    await db.reviews.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api.delete("/reviews/{review_id}")
async def delete_review(review_id: str, user: dict = Depends(get_current_admin)):
    res = await db.reviews.delete_one({"id": review_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Avis introuvable")
    return {"ok": True}

@api.post("/checkout/whatsapp", status_code=201)
async def checkout_whatsapp(body: WhatsAppOrderIn):
    total, detail = await compute_order(body.items)
    cfg = await db.config.find_one({"key": "global"}, {"_id": 0})
    wa_num = cfg["whatsapp_number"] if cfg else WHATSAPP_NUMBER
    order_id = str(uuid.uuid4())
    await db.orders.insert_one({
        "id": order_id, "items": detail, "total_xof": total,
        "customer": {"name": body.customer_name or "", "phone": body.customer_phone or ""},
        "payment_method": "whatsapp", "status": "pending_confirmation",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    lines = ["Bonjour AGRO-SECOURS, je souhaite commander :"]
    for d in detail:
        lines.append(f"- {d['name_fr']} × {d['quantity']} ({int(d['line_total_xof'])} FCFA)")
    lines.append(f"\nTotal : {int(total)} FCFA")
    if body.customer_name:
        lines.append(f"Nom : {body.customer_name}")
    if body.customer_phone:
        lines.append(f"Tél : {body.customer_phone}")
    lines.append(f"\nRéf : {order_id[:8].upper()}")
    wa_url = f"https://wa.me/{wa_num}?text={urllib.parse.quote(chr(10).join(lines))}"
    return {"order_id": order_id, "whatsapp_url": wa_url, "total_xof": total}

@api.post("/checkout/mobile-money", status_code=201)
async def checkout_mobile_money(body: MobileMoneyOrderIn):
    total, detail = await compute_order(body.items)
    order_id = str(uuid.uuid4())
    operator_label = "MTN MoMo" if body.operator == "mtn" else "Moov Money"
    await db.orders.insert_one({
        "id": order_id, "items": detail, "total_xof": total,
        "customer": {"name": body.customer_name, "phone": body.customer_phone},
        "payment_method": body.operator, "status": "pending_confirmation",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    wa_num = WHATSAPP_NUMBER
    lines = [f"Bonjour AGRO-SECOURS, je souhaite payer par {operator_label} :",
             f"Numéro {operator_label} : {body.customer_phone}",
             f"Nom : {body.customer_name}"]
    for d in detail:
        lines.append(f"- {d['name_fr']} × {d['quantity']} ({int(d['line_total_xof'])} FCFA)")
    lines.append(f"\nTotal : {int(total)} FCFA")
    lines.append(f"Réf : {order_id[:8].upper()}")
    wa_url = f"https://wa.me/{wa_num}?text={urllib.parse.quote(chr(10).join(lines))}"
    return {
        "order_id": order_id, "total_xof": total, "operator": body.operator,
        "operator_label": operator_label, "status": "pending_confirmation",
        "whatsapp_url": wa_url,
        "message": f"Envoyez {int(total)} FCFA au numéro {operator_label} de la boutique."
    }

@api.post("/checkout/stripe")
async def checkout_stripe(body: CheckoutIn, http_request: Request):
    if not STRIPE_API_KEY or STRIPE_API_KEY.startswith("sk_test_REMPLACEZ"):
        raise HTTPException(400, "Clé Stripe non configurée. Utilisez WhatsApp ou Mobile Money.")
    total, detail = await compute_order(body.items)
    cfg = await db.config.find_one({"key": "global"}, {"_id": 0})
    eur_rate = cfg["xof_to_eur_rate"] if cfg else XOF_TO_EUR_RATE
    amount_eur = max(round(total * eur_rate, 2), 0.5)
    origin = body.origin_url.rstrip("/")
    success_url = f"{origin}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{origin}/checkout/cancel"
    metadata = {
        "source": "agrosecours_web",
        "customer_name": body.customer_name or "",
        "customer_phone": body.customer_phone or "",
        "customer_email": body.customer_email or "",
        "total_xof": str(total),
    }
    stripe.api_key = STRIPE_API_KEY
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "eur",
                    "product_data": {"name": "Commande Agro-Secours"},
                    "unit_amount": int(amount_eur * 100)
                },
                "quantity": 1
            }],
            mode="payment",
            success_url=success_url,
            cancel_url=cancel_url,
            metadata=metadata,
        )
    except Exception as e:
        raise HTTPException(400, f"Erreur Stripe : {e}")
    await db.payment_transactions.insert_one({
        "session_id": session.id, "amount_eur": amount_eur, "amount_xof": total,
        "currency": "eur", "status": "initiated", "payment_status": "pending",
        "metadata": metadata, "items": detail,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"url": session.url, "session_id": session.id}

@api.get("/checkout/status/{session_id}")
async def checkout_status(session_id: str):
    tx = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
    if not tx:
        raise HTTPException(404, "Transaction introuvable")
    if tx.get("payment_status") == "paid":
        return {"status": tx["status"], "payment_status": "paid", "amount_eur": tx["amount_eur"]}
    try:
        stripe.api_key = STRIPE_API_KEY
        session = stripe.checkout.Session.retrieve(session_id)
        pay_status = session.payment_status
        status_str = "completed" if pay_status == "paid" else "initiated"
        amount_eur = session.amount_total / 100 if session.amount_total else tx["amount_eur"]
    except Exception as e:
        logger.warning(f"Stripe polling échoué {session_id}: {e}")
        return {"status": tx.get("status", "initiated"), "payment_status": tx.get("payment_status", "pending"), "amount_eur": tx.get("amount_eur")}
    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": {"status": status_str, "payment_status": pay_status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if pay_status == "paid" and not await db.orders.find_one({"session_id": session_id}):
        await db.orders.insert_one({
            "id": str(uuid.uuid4()), "session_id": session_id, "items": tx["items"],
            "total_xof": tx["amount_xof"], "total_eur": tx["amount_eur"],
            "customer": {
                "name": tx["metadata"].get("customer_name", ""),
                "phone": tx["metadata"].get("customer_phone", ""),
                "email": tx["metadata"].get("customer_email", "")
            },
            "payment_method": "stripe", "status": "paid",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return {"status": status_str, "payment_status": pay_status, "amount_eur": amount_eur}

@api.get("/admin/orders")
async def admin_orders(page: int = 1, limit: int = 50, status: Optional[str] = None, user: dict = Depends(get_current_admin)):
    limit = min(limit, 200)
    skip = (max(page, 1) - 1) * limit
    q = {}
    if status:
        q["status"] = status
    total = await db.orders.count_documents(q)
    items = await db.orders.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return {"total": total, "page": page, "limit": limit, "items": items}

@api.put("/admin/orders/{order_id}/status")
async def update_order_status(order_id: str, body: OrderStatusIn, user: dict = Depends(get_current_admin)):
    res = await db.orders.update_one(
        {"id": order_id},
        {"$set": {"status": body.status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if res.matched_count == 0:
        raise HTTPException(404, f"Commande {order_id[:8]} introuvable")
    logger.info(f"Commande {order_id[:8]} → {body.status} par {user['email']}")
    return {"ok": True, "status": body.status}

@api.get("/admin/stats")
async def admin_stats(user: dict = Depends(get_current_admin)):
    products = await db.products.count_documents({})
    orders = await db.orders.count_documents({})
    paid = await db.orders.count_documents({"status": "paid"})
    reviews = await db.reviews.count_documents({})
    revenue = 0.0
    async for o in db.orders.find({"status": "paid"}, {"total_xof": 1, "_id": 0}):
        revenue += float(o.get("total_xof", 0))
    return {
        "products": products, "orders": orders, "paid_orders": paid,
        "reviews": reviews, "revenue_xof": revenue
    }

@api.put("/admin/config")
async def update_config(body: ConfigUpdateIn, user: dict = Depends(get_current_admin)):
    update = {}
    if body.xof_to_eur_rate:
        update["xof_to_eur_rate"] = body.xof_to_eur_rate
    if body.whatsapp_number:
        update["whatsapp_number"] = body.whatsapp_number
    if not update:
        raise HTTPException(400, "Aucune valeur à mettre à jour")
    await db.config.update_one({"key": "global"}, {"$set": update}, upsert=True)
    logger.info(f"Config mise à jour par {user['email']}: {update}")
    return {"ok": True, "updated": update}

app.include_router(api)