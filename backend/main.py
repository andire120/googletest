import os
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

# Load environment variables from .env file
load_dotenv()

# Get API keys from environment variables
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID")
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET")
NAVER_CLIENT_ID = os.getenv("NAVER_CLIENT_ID")
NAVER_CLIENT_SECRET = os.getenv("NAVER_CLIENT_SECRET")

# This URL is for the local development environment and must match the address and port where the frontend is running.
FRONTEND_URL = "http://127.0.0.1:5500/frontend/index.html"

# These URLs must match the redirect URIs registered in each API console.
GOOGLE_REDIRECT_URI = "http://127.0.0.1:8000/auth/google"
KAKAO_REDIRECT_URI = "http://127.0.0.1:8000/auth/kakao"
NAVER_REDIRECT_URI = "http://127.0.0.1:8000/auth/naver"

# JWT configuration
SECRET_KEY = "your-super-secret-key"  # Use a more secure key in a real production environment.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In a real production environment, this should be restricted to specific frontend addresses.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Function to create a JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to validate a JWT token
async def get_current_user(request: Request):
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="인증 토큰이 누락되었습니다.")
    
    token = token.split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 토큰입니다.")
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="토큰 검증에 실패했습니다.")


@app.get("/")
async def read_root():
    return {"message": "FastAPI 백엔드가 실행 중입니다."}

# Google login start endpoint
@app.get("/login/google")
async def login_google():
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        "access_type=offline&"
        "prompt=consent"
    )
    return RedirectResponse(url=auth_url)

# Google callback endpoint
@app.get("/auth/google")
async def auth_google(code: str):
    token_url = "https://oauth2.googleapis.com/token"
    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                token_url,
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            token_response.raise_for_status()
            token_data = token_response.json()
        except httpx.HTTPStatusError as e:
            return JSONResponse(status_code=400, content={"message": f"토큰 요청에 실패했습니다: {e.response.text}"})

    user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            user_info_url,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
    user_info = user_info_response.json()
    
    user_email = user_info.get("email")
    user_name = user_info.get("name")
    
    # Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_email, "name": user_name}, expires_delta=access_token_expires
    )
    return RedirectResponse(url=f"{FRONTEND_URL}?token={access_token}")

# Kakao login start endpoint
@app.get("/login/kakao")
async def login_kakao():
    auth_url = (
        "https://kauth.kakao.com/oauth/authorize?"
        f"client_id={KAKAO_CLIENT_ID}&"
        f"redirect_uri={KAKAO_REDIRECT_URI}&"
        "response_type=code"
    )
    return RedirectResponse(url=auth_url)

# Kakao callback endpoint
@app.get("/auth/kakao")
async def auth_kakao(code: str):
    token_url = "https://kauth.kakao.com/oauth/token"
    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": KAKAO_CLIENT_ID,
                    "redirect_uri": KAKAO_REDIRECT_URI,
                    "code": code,
                    "client_secret": KAKAO_CLIENT_SECRET,
                },
            )
            token_response.raise_for_status()
            token_data = token_response.json()
        except httpx.HTTPStatusError as e:
            return JSONResponse(status_code=400, content={"message": f"카카오 토큰 요청 실패: {e.response.text}"})

    user_info_url = "https://kapi.kakao.com/v2/user/me"
    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            user_info_url,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
    user_info = user_info_response.json()
    
    # 카카오 ID를 사용자 식별자로 사용
    user_id = user_info.get("id")
    if not user_id:
        return JSONResponse(status_code=400, content={"message": "카카오 사용자 ID를 가져오는 데 실패했습니다."})

    user_email = user_info.get("kakao_account", {}).get("email")
    user_name = user_info.get("kakao_account", {}).get("profile", {}).get("nickname")

    # 이메일이 없는 경우 카카오 ID를 사용
    jwt_data = {
        "sub": user_email if user_email else str(user_id),
        "name": user_name if user_name else "카카오 사용자"
    }

    # Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=jwt_data, expires_delta=access_token_expires
    )
    return RedirectResponse(url=f"{FRONTEND_URL}?token={access_token}")

# Naver login start endpoint
@app.get("/login/naver")
async def login_naver():
    auth_url = (
        "https://nid.naver.com/oauth2.0/authorize?"
        f"response_type=code&"
        f"client_id={NAVER_CLIENT_ID}&"
        f"redirect_uri={NAVER_REDIRECT_URI}&"
        "state=STATE_STRING_FOR_SECURITY" # In a real production environment, a random string should be generated.
    )
    return RedirectResponse(url=auth_url)

# Naver callback endpoint
@app.get("/auth/naver")
async def auth_naver(code: str, state: str):
    token_url = "https://nid.naver.com/oauth2.0/token"
    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": NAVER_CLIENT_ID,
                    "client_secret": NAVER_CLIENT_SECRET,
                    "redirect_uri": NAVER_REDIRECT_URI,
                    "code": code,
                    "state": state,
                },
            )
            token_response.raise_for_status()
            token_data = token_response.json()
        except httpx.HTTPStatusError as e:
            return JSONResponse(status_code=400, content={"message": f"네이버 토큰 요청 실패: {e.response.text}"})

    user_info_url = "https://openapi.naver.com/v1/nid/me"
    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            user_info_url,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
    user_info = user_info_response.json()

    user_email = user_info.get("response", {}).get("email")
    user_name = user_info.get("response", {}).get("name")
    
    # Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_email, "name": user_name}, expires_delta=access_token_expires
    )
    return RedirectResponse(url=f"{FRONTEND_URL}?token={access_token}")

# Protected endpoint (requires JWT)
@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"message": "인증에 성공했습니다.", "user": current_user}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)