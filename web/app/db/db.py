import os
import sqlite3 as sql

from flask import g
from dotenv import load_dotenv


load_dotenv()
DB_PATH = os.getenv("DATABASE")


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sql.connect(DB_PATH)

    create_tables(db)
    return db


def create_tables(db):
    try:
        db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, master_password TEXT NOT NULL)')
    except sql.OperationalError:
        pass
    try:
        db.execute(
            'CREATE TABLE passwords(id INTEGER PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL)')
    except sql.OperationalError:
        pass
    try:
        db.execute(
            'CREATE TABLE attempts(id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip_address TEXT NOT NULL, time timestamp)')
    except sql.OperationalError:
        pass
    try:
        db.execute(
            'CREATE TABLE resets(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, reset_id TEXT NOT NULL, end_time timestamp)')
    except sql.OperationalError:
        pass


def query_db(query, values):
    try:
        db = get_db()
        db.cursor().execute(query, values)
        db.commit()
        return True
    except:
        return False


def select_from_db(query, values, mode="one"):
    try:
        if not mode in ["one", "all"]:
            print("Nieprawidłowy tryb")
            return None

        db = get_db()
        if mode == "one":
            rows = db.execute(query, values).fetchone()
        else:
            rows = db.execute(query, values).fetchall()
        return rows
    except:
        return None

