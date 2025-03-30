from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from passlib.hash import bcrypt
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import redis.asyncio as redis
from playhouse.shortcuts import model_to_dict
import random
import string
from .config import REDIS_HOST
from datetime import datetime, timedelta, timezone
from .models import db, User, URL
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Настройка Redis
redis_client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

# OAuth2 схема
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Создание базы данных (если еще не создана)
db.connect()
db.create_tables([User, URL], safe=True)

# Pydantic модели
class URLCreate(BaseModel):
    original_url: str
    custom_alias: str = Field(default="")
    expires_at: datetime = None

    @field_validator("expires_at", mode='before', check_fields=False)
    def set_expires_at(cls, v):
        return v or (datetime.now(tz=timezone.utc) + timedelta(days=7))


class UserCreate(BaseModel):
    username: str
    password: str


# Функция генерации случайного short_code
def generate_short_code(length=6):
    return ''.join(random.choice(
        string.ascii_letters + string.digits) for _ in range(length))


# Регистрация пользователя
@app.post("/register")
async def register(user: UserCreate):
    hashed_password = bcrypt.hash(user.password)
    if User.get_or_none(User.username == user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    User.create(username=user.username, password_hash=hashed_password)
    return {"msg": "User registered successfully"}


# Аутентификация пользователя
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = User.get(User.username == form_data.username)

        if not user.verify_password(form_data.password):
            raise HTTPException(status_code=400, detail="Invalid username or password")

        return {"access_token": user.username, "token_type": "bearer"}
    except User.DoesNotExist:
        raise HTTPException(status_code=400, detail="Invalid username or password")


# Сокращение URL
@app.post("/links/shorten")
async def create_short_url(url: URLCreate, request: Request, token: Optional[str] = Depends(oauth2_scheme)):
    owner = None
    if token:
        owner = User.get_or_none(User.username == token)

    # Использовать пользовательский алиас или сгенерировать новый короткий код
    short_code = url.custom_alias if url.custom_alias else generate_short_code()

    # Проверка на существование алиаса в базе данных и Redis
    if URL.get_or_none(URL.short_code == short_code) or await redis_client.exists(f"url:{short_code}"):
        raise HTTPException(status_code=400, detail="Alias already exists")

    if owner:
        # Создание записи в базе данных для зарегистрированного пользователя
        URL.create(
            original_url=url.original_url,
            short_code=short_code,
            custom_alias=url.custom_alias,
            expires_at=url.expires_at,
            owner=owner
        )
    else:
        # Сохранение только в Redis для незарегистрированного пользователя
        await redis_client.set(f"url:{short_code}", url.original_url, ex=60*60*24*7)  # Expires in 7 days

    await redis_client.set(f"url:{short_code}", url.original_url, ex=60*60*24*7)

    return {"short_url": f"http://{request.headers['host']}/{short_code}"}


# Редирект по короткой ссылке
@app.get("/{short_code}")
async def redirect_to_url(short_code: str, reveal: bool = False):
    original_url = await redis_client.get(f"url:{short_code}")

    if not original_url:
        url_object = URL.get_or_none(URL.short_code == short_code)
        if not url_object:
            raise HTTPException(status_code=404, detail="URL not found")
        original_url = url_object.original_url
        await redis_client.set(f"url:{short_code}", original_url)

    if reveal:
        return {"original_url": original_url}

    if URL.get_or_none(URL.short_code == short_code):
        URL.update(clicks=URL.clicks + 1, last_accessed_at=datetime.now(tz=timezone.utc)).where(
            URL.short_code == short_code).execute()

    return RedirectResponse(original_url)


# Обновление ссылки
@app.put("/links/{short_code}")
async def update_url(
    short_code: str,
    url: URLCreate,
    token: str = Depends(oauth2_scheme)):
    owner = User.get_or_none(User.username == token)
    url_to_update = URL.get_or_none(URL.short_code == short_code, URL.owner == owner)
 
    if not url_to_update:
        raise HTTPException(status_code=403, detail="Operation not allowed")

    # Обновление оригинального URL
    url_to_update.original_url = url.original_url or url_to_update.original_url

    # Обновление срока действия
    if url.expires_at:
        url_to_update.expires_at = url.expires_at
    else:
        url_to_update.expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)

    # Проверка нового алиаса
    if url.custom_alias and url.custom_alias != url_to_update.custom_alias:
        # Проверка существования нового алиаса
        if URL.get_or_none(URL.short_code == url.custom_alias):
            raise HTTPException(status_code=400, detail="Alias already exists")
        # Обновление кастомного алиаса и короткого кода
        url_to_update.custom_alias = url.custom_alias
        url_to_update.short_code = url.custom_alias

    url_to_update.save()

    # Очистка кэша для обновления данных
    await redis_client.delete(f"url:{short_code}")

    return {"msg": "URL updated successfully"}


# Удаление ссылки
@app.delete("/links/{short_code}")
async def delete_url(short_code: str, token: str = Depends(oauth2_scheme)):
    owner = User.get_or_none(User.username == token)
    url_to_delete = URL.get_or_none(URL.short_code == short_code, URL.owner == owner)

    if not url_to_delete:
        raise HTTPException(status_code=403, detail="Operation not allowed")

    url_to_delete.delete_instance()

    # Удаление из кэша
    await redis_client.delete(f"url:{short_code}")
    return {"msg": "URL deleted successfully"}


# Статистика по ссылке
@app.get("/links/{short_code}/stats")
async def get_url_stats(short_code: str):
    url_object = URL.get_or_none(URL.short_code == short_code)
    if not url_object:
        raise HTTPException(status_code=404, detail="URL not found")
    return {
        "original_url": url_object.original_url,
        "clicks": url_object.clicks,
        "created_at": url_object.created_at,
        "last_accessed_at": url_object.last_accessed_at,
    }


# Поиск по оригинальной ссылке
@app.get("/links/search")
async def search(original_url: str):
    url_objects = URL.select().where(URL.original_url == original_url)
    urls = [model_to_dict(url) for url in url_objects]
    return urls


# Получение всех ссылок пользователя
@app.get("/links/user")
async def get_user_links(token: str = Depends(oauth2_scheme)):
    user = User.get_or_none(User.username == token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    user_links = URL.select().where(URL.owner == user)
    return {"links": [model_to_dict(link) for link in user_links]}


# Удаление устаревших ссылок- moved to lifespan
async def remove_expired_urls():
    expired_urls = URL.select().where(URL.expires_at < datetime.now(tz=timezone.utc) - timedelta(days=7))
    for url in expired_urls:
        await redis_client.delete(f"url:{url.short_code}")
        url.delete_instance()


# Функция для очистки кэша Redis и повторной загрузки данных из PostgreSQL- moved to lifespan
async def reload_data_into_redis():
    keys = await redis_client.keys("url:*")
    if keys:
        await redis_client.delete(*keys)
    urls = URL.select()
    for url in urls:
        time_to_expire = (url.expires_at - datetime.now(
            tz=timezone.utc)).total_seconds() if url.expires_at else None
        if time_to_expire and time_to_expire > 0:
            await redis_client.set(f"url:{url.short_code}", url.original_url, ex=int(time_to_expire))
        else:
            await redis_client.set(f"url:{url.short_code}", url.original_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await reload_data_into_redis()
        print("Redis cache reloaded successfully.")
    except Exception as e:
        print(f"Error during startup: {e}")
    await remove_expired_urls()
    yield

app.router.lifespan_context = lifespan


# Просмотр истории всех истекших ссылок
@app.get("/expired_links")
async def expired_urls():
    expired = URL.select().where(URL.expires_at < datetime.now(tz=timezone.utc))
    return [model_to_dict(url) for url in expired]


# Корень сервиса
@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Административная панель
@app.get("/admin/")
async def admin(request: Request):
    # Общее количество уникальных пользователей
    user_count = User.select().count()

    # Количество кешированных URL в Redis
    total_urls_cache = await redis_client.dbsize()

    # Получаем последние 10 ссылок из базы данных и информацию об их владельцах
    last_10_links = (URL
                     .select(URL, User)
                     .join(User, on=(URL.owner == User.id))
                     .order_by(URL.created_at.desc())
                     .limit(10))

    # Общее количество ссылок в базе данных
    count_links_in_db = URL.select().count()

    # Подготовка данных для передачи в шаблон
    context = {
        "request": request,
        "total_urls_cache": total_urls_cache,
        "last_10_links": [{
            "original_url": link.original_url,
            "short_code": link.short_code,
            "owner_username": link.owner.username
        } for link in last_10_links],
        "count_links_in_db": count_links_in_db,
        "user_count": user_count
    }
    return templates.TemplateResponse("admin/index.html", context)
