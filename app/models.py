from peewee import Model, CharField, IntegerField
from peewee import DateTimeField, ForeignKeyField, BooleanField
from playhouse.postgres_ext import PostgresqlExtDatabase
from datetime import datetime
from passlib.hash import bcrypt
from .config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST

# Подключение к базе данных
db = PostgresqlExtDatabase(
    DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST
)

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)
    password_hash = CharField()

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)

class URL(BaseModel):
    original_url = CharField()
    short_code = CharField(unique=True)
    custom_alias = CharField(null=True, unique=True)
    clicks = IntegerField(default=0)
    created_at = DateTimeField(default=datetime.now)
    last_accessed_at = DateTimeField(null=True)
    expires_at = DateTimeField(null=True)
    owner = ForeignKeyField(User, backref='urls', null=True)
    is_expired = BooleanField(default=False)

    def mark_expired(self):
        self.is_expired = True
        self.save()
