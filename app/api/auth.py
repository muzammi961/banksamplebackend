from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
)

from app.db.database import get_db

from app.models.user import User

from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    UserResponse,
    BiometricEnableResponse,
)

from app.core.dependencies import get_current_user


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


# ============================================================
# REGISTER
# ============================================================

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):

    # --------------------------------------------------------
    # Check existing email
    # --------------------------------------------------------

    result = await db.execute(
        select(User).where(
            User.email == data.email.lower()
        )
    )

    existing_user = result.scalar_one_or_none()

    if existing_user:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # --------------------------------------------------------
    # Hash password
    # --------------------------------------------------------

    password_hash = hash_password(
        data.password
    )

    # --------------------------------------------------------
    # Create user
    # --------------------------------------------------------

    user = User(
        email=data.email.lower(),
        password_hash=password_hash,
        is_active=True,
        biometric_enabled=False,
    )

    db.add(user)

    await db.commit()

    await db.refresh(user)

    # --------------------------------------------------------
    # Create JWT
    # --------------------------------------------------------

    access_token = create_access_token(
        user_id=str(user.id)
    )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=(
            settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        ),
        user_id=str(user.id),
        biometric_enabled=False,
    )


# ============================================================
# LOGIN
# ============================================================

@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    result = await db.execute(
        select(User).where(
            User.email == data.email.lower()
        )
    )

    user = result.scalar_one_or_none()

    # --------------------------------------------------------
    # User not found
    # --------------------------------------------------------

    if not user:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # --------------------------------------------------------
    # Check password
    # --------------------------------------------------------

    password_valid = verify_password(
        data.password,
        user.password_hash,
    )

    if not password_valid:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # --------------------------------------------------------
    # Check active
    # --------------------------------------------------------

    if not user.is_active:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # --------------------------------------------------------
    # Create JWT
    # --------------------------------------------------------

    access_token = create_access_token(
        user_id=str(user.id)
    )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=(
            settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        ),
        user_id=str(user.id),
        biometric_enabled=user.biometric_enabled,
    )


# ============================================================
# CURRENT USER
# ============================================================

@router.get(
    "/me",
    response_model=UserResponse,
)
async def get_me(
    current_user: User = Depends(
        get_current_user
    ),
):

    return UserResponse(
        id=str(current_user.id),
        email=current_user.email,
        is_active=current_user.is_active,
        biometric_enabled=current_user.biometric_enabled,
    )


# ============================================================
# ENABLE BIOMETRIC
# ============================================================

@router.post(
    "/biometric/enable",
    response_model=BiometricEnableResponse,
)
async def enable_biometric(
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):

    current_user.biometric_enabled = True

    current_user.biometric_enabled_at = (
        datetime.now(timezone.utc)
    )

    await db.commit()

    return BiometricEnableResponse(
        message="Biometric login enabled",
        biometric_enabled=True,
    )


# ============================================================
# DISABLE BIOMETRIC
# ============================================================

@router.post(
    "/biometric/disable",
    response_model=BiometricEnableResponse,
)
async def disable_biometric(
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):

    current_user.biometric_enabled = False

    current_user.biometric_enabled_at = None

    await db.commit()

    return BiometricEnableResponse(
        message="Biometric login disabled",
        biometric_enabled=False,
    )