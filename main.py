import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Body, Header
from fastapi.security import HTTPBasicCredentials, HTTPBasic, HTTPAuthorizationCredentials, HTTPBearer
import secrets
from datetime import datetime, timedelta
from pydantic import BaseModel
from apscheduler.schedulers.background import BackgroundScheduler

sched = BackgroundScheduler()
app = FastAPI()

TOKEN_EXPIRATION = 30

auth_basic = HTTPBasic()
auth_bearer = HTTPBearer()

def db_connect():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    return conn, cur

def init_db():
    conn, cur = db_connect()
    cur.execute('''CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    salary REAL NOT NULL,
                    raising TEXT NOT NULL,
                    token TEXT,
                    exp_time TEXT)''')
    conn.commit()
    conn.close()

@app.on_event("startup")
def on_startup():
    init_db()

def exec_query(query, params=None, fetchone=False):
    try:
        conn, cur = db_connect()
        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)
        res = cur.fetchone() if fetchone else cur.fetchall()
        conn.commit()
        conn.close()
        return res
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Ошибка базы данных: {str(e)}")

def valid_token(token):
    query = "SELECT exp_time FROM employees WHERE token=?"
    res = exec_query(query, (token,), fetchone=True)
    
    if res:
        exp_time = datetime.strptime(res[0], "%Y-%m-%d %H:%M:%S.%f")
        if datetime.now() > exp_time:
            new_token, _ = gen_token_and_update_db(token)
            return new_token
        else:
            return token
    else:
        return None

def gen_token_and_update_db(username):
    token = secrets.token_hex(16)
    exp_time = datetime.now() + timedelta(seconds=TOKEN_EXPIRATION)
    query = "UPDATE employees SET token=?, exp_time=? WHERE username=?"
    exec_query(query, (token, exp_time, username))
    return token, exp_time

def valid_user(username: str, password: str):
    query = "SELECT * FROM employees WHERE username=? AND password=?"
    user = exec_query(query, (username, password), fetchone=True)
    return user is not None

class User(BaseModel):
    username: str
    password: str
    salary: float
    raising: str

@app.post("/token")
def login(credentials: HTTPBasicCredentials = Depends(auth_basic)):
    if valid_user(credentials.username, credentials.password):
        token, exp_time = gen_token_and_update_db(credentials.username)
        return {"token": token, "expires_at": exp_time}
    else:
        raise HTTPException(status_code=401, detail="Неправильное имя пользователя или пароль")

@app.post("/register")
def register(user: User):
    try:
        raising_dt = datetime.fromisoformat(user.raising)
    except ValueError:
        raise HTTPException(status_code=400, detail="Неправильный формат даты для 'raising'. Используйте ISO формат (ГГГГ-ММ-ДДTЧЧ:ММ:СС)")
    
    query = "SELECT * FROM employees WHERE username=?"
    existing_user = exec_query(query, (user.username,), fetchone=True)
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Имя пользователя уже существует")
    
    query = "INSERT INTO employees (username, password, salary, raising) VALUES (?, ?, ?, ?)"
    try:
        exec_query(query, (user.username, user.password, user.salary, raising_dt))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Не удалось зарегистрировать пользователя из-за ошибки целостности")
    
    return {"message": "Пользователь успешно зарегистрирован"}

@app.get("/salary") 
def get_salary(auth: HTTPAuthorizationCredentials = Depends(auth_bearer)):
    if not auth.scheme == "Bearer":
        raise HTTPException(status_code=401, detail="Неправильный токен!")
    
    token = auth.credentials
    valid_tkn = valid_token(token)
    
    if valid_tkn:
        query = "SELECT salary, raising FROM employees WHERE token=?"
        res = exec_query(query, (valid_tkn,), fetchone=True)
        
        if res:
            salary, raising = res
            return {"salary": salary, "raising": raising}
    
    raise HTTPException(status_code=401, detail="Неправильный токен!")
