# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from fastapi.middleware.cors import CORSMiddleware

# 数据库配置
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}  # 仅SQLite需要
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 定义用户表结构
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50))
    phone_number = Column(String(20), unique=True, index=True)
    hashed_password = Column(String(200))

# 创建数据库表（实际生产环境应使用迁移工具）
Base.metadata.create_all(bind=engine)

app = FastAPI()
# 添加CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # 前端开发地址
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from pydantic import BaseModel, Field, root_validator
from passlib.context import CryptContext
from typing import Optional

# 密码哈希配置
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 请求数据模型
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    phone_number: str = Field(..., pattern=r"^\d{11}$")
    password: str = Field(..., min_length=8)
    password_confirm: str

    # 密码一致性验证
    @root_validator(pre=True)
    def check_passwords_match(cls, values):
        password = values.get('password')
        password_confirm = values.get('password_confirm')
        
        if password != password_confirm:
            raise ValueError("两次输入密码不一致")
        return values

# 数据库依赖项
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 注册接口
@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    
    # 检查用户名是否已存在
    existing_username = db.query(DBUser).filter(
        DBUser.username == user.username
    ).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="用户名已被注册"
        )

    
    # 检查手机号是否已存在
    existing_phone = db.query(DBUser).filter(
        DBUser.phone_number == user.phone_number
    ).first()
    
    if existing_phone:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="手机号已被注册"
        )
    
    # 哈希密码（不要存储明文密码！）
    hashed_password = pwd_context.hash(user.password)
    
    # 创建用户记录
    db_user = DBUser(
        username=user.username,
        phone_number=user.phone_number,
        hashed_password=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {"message": "注册成功"}

from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# JWT配置
SECRET_KEY = "your-secret-key"  # 生产环境应从环境变量获取
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

class UserLogin(BaseModel):
    phone_number: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# 登录接口
@app.post("/auth/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    # 查找用户
    db_user = db.query(DBUser).filter(
        DBUser.phone_number == user.phone_number
    ).first()
    
    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="手机号或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 生成JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.phone_number},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)