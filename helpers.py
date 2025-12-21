import hashlib
import os
import sqlite3
import random

from flask import session, redirect, g, current_app
from functools import wraps
from string import ascii_uppercase

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt.hex() + pwdhash.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    salt = bytes.fromhex(stored_hash[:32])
    stored_pwdhash = stored_hash[32:]
    pwdhash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    ).hex()
    return pwdhash == stored_pwdhash

def create_db(db):
     # 创建用户表（如果不存在）
        db.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    create_time TEXT DEFAULT (datetime('now','localtime'))
                )
            """)
    # 房间表（如果不存在）
        db.execute("""
                CREATE TABLE IF NOT EXISTS room(
                    token TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    member INTEGER NOT NULL,
                    create_time TEXT DEFAULT (datetime('now','localtime'))
            )
            """)
    # 绑定表（如果不存在）
        db.execute("""
                CREATE TABLE IF NOT EXISTS bind(
                    user_id INTEGER NOT NULL,
                    room_token TEXT NOT NULL, 
                    bind_time TEXT DEFAULT (datetime('now','localtime')),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (room_token) REFERENCES room(token),
                    PRIMARY KEY (user_id, room_token)
                )
            """)
        db.execute("""
                CREATE TABLE IF NOT EXISTS message(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_token TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    create_time TEXT DEFAULT (datetime('now','localtime')),
                    FOREIGN KEY (room_token) REFERENCES room(token),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_bind_user_id ON bind(user_id);"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_bind_room_token ON bind(room_token);"
        )
        db.commit()

def get_db_connection():
    # 如果没有现有的数据库连接，则创建一个新的连接
    if getattr(g, 'db', None) is None:
        # 使得数据库能被找到
        db_path = os.path.join(current_app.root_path, "room.db")

        # 给每一个请求建立单独的连接
        # 该连接只在请求上下文当中生效
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row

        # 开启外键支持
        g.db.execute("PRAGMA foreign_keys = ON;")

    return g.db

def close_db(e=None):
   # 移除g的db键
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
        except Exception:
            # 忽略关闭时的异常，保证 teardown 不会抛出
            pass
rooms = {}
online_users = {}
def generate_token(length):
    db = get_db_connection()
    tokens = db.execute("SELECT token FROM room").fetchall()
    existing_tokens = [row["token"] for row in tokens]
    while True:
        token = ""
        for _ in range(length):
            token += random.choice(ascii_uppercase)
        if token not in existing_tokens:
            break
    return token