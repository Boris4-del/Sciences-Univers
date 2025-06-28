from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
import databases
import sqlalchemy
import bcrypt
import jwt
import re
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.cors import CORSMiddleware

# Configuration
DATABASE_URL = "postgresql://user:password@db:5432/securedb"
SECRET_KEY = "v3ry_s3cr3t_k3y_w1th_h1gh_3ntr0py"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialisation
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modèle de données
users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email", sqlalchemy.String(100), unique=True),
    sqlalchemy.Column("hashed_password", sqlalchemy.String(300)),
)


# Schémas Pydantic
class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


# Middlewares de sécurité
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://votre-domaine-securise.com"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization"],
)


# Protection contre le bruteforce
@limiter.limit("5/minute")
@app.post("/login")
async def login(request: Request, credentials: UserLogin):
    # Vérification des entrées
    if not is_valid_email(credentials.email):
        raise HTTPException(400, "Format email invalide")

    # Vérification dans la base
    query = users.select().where(users.c.email == credentials.email)
    user = await database.fetch_one(query)

    # Protection temporelle constante
    if not user or not verify_password(credentials.password, user.hashed_password):
        await asyncio.sleep(0.5)  # Délai anti-bruteforce
        raise HTTPException(401, "Identifiants invalides")

    # Génération JWT
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token}


# Fonctions de sécurité
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=14)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def is_valid_email(email: str) -> bool:
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,6}$", email) is not None


# Audit et monitoring
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    logging.info(f"Path: {request.url.path} | IP: {request.client.host} | Status: {response.status_code}")
    return response


# Gestion des données sensibles
@app.post("/users/")
async def create_user(user: UserCreate):
    # Validation supplémentaire
    if len(user.password) < 12:
        raise HTTPException(400, "Le mot de passe doit contenir au moins 12 caractères")

    # Chiffrement des données
    hashed_pw = hash_password(user.password)

    # Insertion sécurisée
    try:
        query = users.insert().values(email=user.email, hashed_password=hashed_pw)
        await database.execute(query)
    except sqlalchemy.exc.IntegrityError:
        raise HTTPException(400, "Email déjà utilisé")

    return {"message": "Utilisateur créé avec succès"}


# Points de sécurité avancés
@app.on_event("startup")
async def startup():
    await database.connect()
    # Appliquer les migrations
    # Vérifier les configurations de sécurité
    # Initialiser les systèmes de détection d'intrusion


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, ssl_keyfile="./key.pem", ssl_certfile="./cert.pem")