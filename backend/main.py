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

# .env 파일에서 환경 변수를 로드합니다.
load_dotenv()

# 환경 변수에서 Google API 키를 가져옵니다.
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# 이 URL은 로컬 개발 환경용이며, 프론트엔드가 실행되는 주소와 포트와 일치해야 합니다.
FRONTEND_URL = "http://127.0.0.1:5500/frontend/index.html"
# 이 URL은 Google API 콘솔에 등록된 리디렉션 URI와 일치해야 합니다.
GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google"

# JWT 설정
SECRET_KEY = "your-super-secret-key"  # 실제 운영 환경에서는 더 안전한 키를 사용하세요.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 실제 운영 환경에서는 특정 프론트엔드 주소로 제한해야 합니다.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT 토큰 생성 함수
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# JWT 토큰 검증 함수
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

# Google 로그인 시작 엔드포인트
@app.get("/login/google")
async def login_google():
    # Google OAuth 인증 URL을 생성합니다.
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

# Google 콜백 엔드포인트
@app.get("/auth/google")
async def auth_google(code: str):
    # Google로부터 받은 코드를 사용하여 토큰을 요청합니다.
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

    # 토큰을 사용하여 사용자 정보를 가져옵니다.
    user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            user_info_url,
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
    user_info = user_info_response.json()
    
    user_email = user_info.get("email")
    user_name = user_info.get("name")
    
    # JWT를 생성합니다.
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_email, "name": user_name}, expires_delta=access_token_expires
    )

    # JWT를 포함한 상태로 프론트엔드로 리디렉션합니다.
    # 클라이언트는 URL 파라미터를 파싱하여 토큰을 얻습니다.
    return RedirectResponse(url=f"{FRONTEND_URL}?token={access_token}")

# 보호된 엔드포인트 (JWT가 필요합니다)
@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"message": "인증에 성공했습니다.", "user": current_user}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
