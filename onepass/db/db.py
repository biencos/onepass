import os
import sqlite3 as sql


class Db:
    def __init__(self, DB_PATH):
        self.db = sql.connect(DB_PATH)
        self.create_tables_if_they_not_exist()

    def query_db(self, query, values):
        try:
            self.db.cursor().execute(query, values)
            self.db.commit()
            return True
        except:
            return False

    def select_from_db(self, query, values, mode="one"):
        try:
            if not mode in ["one", "all"]:
                print("Nieprawidłowy tryb")
                return None

            if mode == "one":
                rows = self.db.execute(query, values).fetchone()
            else:
                rows = self.db.execute(query, values).fetchall()
            return rows
        except:
            return None

    def create_tables_if_they_not_exist(self):
        try:
            self.db.execute(
                'CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, master_password TEXT NOT NULL)')
        except sql.OperationalError:
            pass
        try:
            self.db.execute(
                'CREATE TABLE passwords(id INTEGER PRIMARY KEY, username TEXT NOT NULL, service_name TEXT NOT NULL, service_url TEXT NOT NULL, service_username TEXT NOT NULL, service_password TEXT NOT NULL, password_id TEXT NOT NULL)')
        except sql.OperationalError:
            pass
