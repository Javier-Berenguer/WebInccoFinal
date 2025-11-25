from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import hashlib
import shutil

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET', 'tu-clave-secreta-super-segura-cambiar-en-produccion')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

# Create the main app
app = FastAPI()

# Create uploads directory
UPLOADS_DIR = ROOT_DIR / 'uploads'
UPLOADS_DIR.mkdir(exist_ok=True)

# Security
security = HTTPBearer()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class Admin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    username: str
    password_hash: str

class AdminLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Noticia(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    titulo: str
    extracto: str
    contenido: str
    imagen_url: Optional[str] = None
    fecha_publicacion: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    autor: str = "Fundación INCCO"

class NoticiaCreate(BaseModel):
    titulo: str
    extracto: str
    contenido: str
    imagen_url: Optional[str] = None
    autor: Optional[str] = "Fundación INCCO"

class NoticiaUpdate(BaseModel):
    titulo: Optional[str] = None
    extracto: Optional[str] = None
    contenido: Optional[str] = None
    imagen_url: Optional[str] = None
    autor: Optional[str] = None

# Helper functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Initialize admin user (username: AdministradorIncco, password: AdminIncco*.2025)
@app.on_event("startup")
async def startup_event():
    """
    Ensure there is at least one administrator account in the database.
    If none exists with the configured username, it will be created.
    """
    admin = await db.admins.find_one({"username": "AdministradorIncco"})
    if not admin:
        admin_doc = {
            "username": "AdministradorIncco",
            "password_hash": hash_password("AdminIncco*.2025")
        }
        await db.admins.insert_one(admin_doc)
        logger.info("Admin user created: username=AdministradorIncco, password=AdminIncco*.2025")

# Routes
@api_router.post("/admin/login", response_model=TokenResponse)
async def admin_login(credentials: AdminLogin):
    admin = await db.admins.find_one({"username": credentials.username})
    if not admin or admin["password_hash"] != hash_password(credentials.password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    access_token = create_access_token(data={"sub": credentials.username})
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.get("/admin/verify")
async def verify_admin(username: str = Depends(verify_token)):
    return {"username": username, "authenticated": True}

@api_router.post("/noticias", response_model=Noticia)
async def crear_noticia(noticia: NoticiaCreate, username: str = Depends(verify_token)):
    noticia_dict = noticia.model_dump()
    noticia_obj = Noticia(**noticia_dict)
    
    doc = noticia_obj.model_dump()
    doc['fecha_publicacion'] = doc['fecha_publicacion'].isoformat()
    
    await db.noticias.insert_one(doc)
    return noticia_obj

@api_router.get("/noticias", response_model=List[Noticia])
async def obtener_noticias():
    noticias = await db.noticias.find({}, {"_id": 0}).sort("fecha_publicacion", -1).to_list(1000)
    
    for noticia in noticias:
        if isinstance(noticia['fecha_publicacion'], str):
            noticia['fecha_publicacion'] = datetime.fromisoformat(noticia['fecha_publicacion'])
    
    return noticias

@api_router.get("/noticias/{noticia_id}", response_model=Noticia)
async def obtener_noticia(noticia_id: str):
    noticia = await db.noticias.find_one({"id": noticia_id}, {"_id": 0})
    
    if not noticia:
        raise HTTPException(status_code=404, detail="Noticia no encontrada")
    
    if isinstance(noticia['fecha_publicacion'], str):
        noticia['fecha_publicacion'] = datetime.fromisoformat(noticia['fecha_publicacion'])
    
    return noticia

@api_router.put("/noticias/{noticia_id}", response_model=Noticia)
async def actualizar_noticia(noticia_id: str, noticia_update: NoticiaUpdate, username: str = Depends(verify_token)):
    noticia_actual = await db.noticias.find_one({"id": noticia_id}, {"_id": 0})
    
    if not noticia_actual:
        raise HTTPException(status_code=404, detail="Noticia no encontrada")
    
    update_data = {k: v for k, v in noticia_update.model_dump().items() if v is not None}
    
    if update_data:
        await db.noticias.update_one({"id": noticia_id}, {"$set": update_data})
    
    noticia_actualizada = await db.noticias.find_one({"id": noticia_id}, {"_id": 0})
    
    if isinstance(noticia_actualizada['fecha_publicacion'], str):
        noticia_actualizada['fecha_publicacion'] = datetime.fromisoformat(noticia_actualizada['fecha_publicacion'])
    
    return noticia_actualizada

@api_router.delete("/noticias/{noticia_id}")
async def eliminar_noticia(noticia_id: str, username: str = Depends(verify_token)):
    result = await db.noticias.delete_one({"id": noticia_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Noticia no encontrada")
    
    return {"message": "Noticia eliminada exitosamente"}

@api_router.post("/upload-imagen")
async def subir_imagen(file: UploadFile = File(...), username: str = Depends(verify_token)):
    # Validar tipo de archivo
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="El archivo debe ser una imagen")
    
    # Generar nombre único
    file_extension = file.filename.split('.')[-1]
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    file_path = UPLOADS_DIR / unique_filename
    
    # Guardar archivo
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Retornar URL
    return {"imagen_url": f"/uploads/{unique_filename}"}

# Include the router in the main app
app.include_router(api_router)

# Serve uploaded files
app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")

# Serve static HTML files
STATIC_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/contacto.html")
async def serve_contacto():
    return FileResponse(STATIC_DIR / "contacto.html")

@app.get("/archivo.html")
async def serve_archivo():
    return FileResponse(STATIC_DIR / "archivo.html")

@app.get("/noticia.html")
async def serve_noticia():
    return FileResponse(STATIC_DIR / "noticia.html")

@app.get("/admin-login.html")
async def serve_admin_login():
    return FileResponse(STATIC_DIR / "admin-login.html")

@app.get("/admin-panel.html")
async def serve_admin_panel():
    return FileResponse(STATIC_DIR / "admin-panel.html")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()