import json
import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base



__usename = 'root'
__password = os.getenv('DB_PASSWORD')

Base = declarative_base()


def create_db_if_not_exist():
    engine = create_engine('mysql+mysqldb://{}:{}@{}:3306/'.format(__usename, __password, os.getenv("DB_HOSTNAME")),
                           echo=True)
    engine.execute("CREATE DATABASE IF NOT EXISTS solitude;")


def return_engine():
    create_db_if_not_exist()
    return create_engine('mysql+mysqldb://{}:{}@{}:3306/solitude'.format(__usename, __password, os.getenv("DB_HOSTNAME")),
                         echo=True)



