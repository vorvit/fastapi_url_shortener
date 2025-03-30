import os
from dotenv import load_dotenv

# Загрузка переменных окружения из .env файла
load_dotenv()

# Получение значений из переменных окружения
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB")
DB_HOST = os.getenv("DATABASE_HOST", "localhost")
DB_PORT = os.getenv("DATABASE_PORT", "5432")

SQLITE_TEST_DB = os.getenv("SQLITE_TEST_DB", "test_database.db")

REDIS_HOST = os.getenv("REDIS_HOST")

class Config:
    TESTING = False
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = f"sqlite:///{SQLITE_TEST_DB}"


def get_config():
    environment = os.getenv('ENV', 'testing')  # dev
    if environment == 'testing':
        print("Running in TESTING mode. DATABASE_URL:", TestingConfig.DATABASE_URL)
        return TestingConfig()
    print("Running in DEVELOPMENT mode. DATABASE_URL:", Config.DATABASE_URL)
    return Config()
