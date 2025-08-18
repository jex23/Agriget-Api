from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import bcrypt
from jose import JWTError, jwt
import mysql.connector
from mysql.connector import Error
import os
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone, date
from dotenv import load_dotenv
import boto3
from decimal import Decimal
import uuid
import io
import random
import string
import json

load_dotenv()

app = FastAPI(
    title="Agriget API",
    description="API for Agriget user management system with authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware for allowing all origins and methods
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow requests from any domain
    allow_credentials=True,
    allow_methods=["*"],  # Allow any HTTP method
    allow_headers=["*"],  # Allow any headers
)

SECRET_KEY = "your-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 99999999

security = HTTPBearer()

db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT")
db_name = os.getenv("DB_NAME")

r2_access_key = os.getenv("r2_access_key")
r2_secret_key = os.getenv("r2_secret_key")
r2_endpoint = os.getenv("r2_endpoint")
r2_bucket_name = os.getenv("r2_bucket_name")

# Debug R2 credentials at startup
print("=== R2 CONFIGURATION DEBUG ===")
print(f"r2_access_key: {'✓ Set' if r2_access_key else '✗ Missing'}")
print(f"r2_secret_key: {'✓ Set' if r2_secret_key else '✗ Missing'}")
print(f"r2_endpoint: {r2_endpoint if r2_endpoint else '✗ Missing'}")
print(f"r2_bucket_name: {r2_bucket_name if r2_bucket_name else '✗ Missing'}")
print("==============================")

s3_client = boto3.client(
    's3',
    endpoint_url=r2_endpoint,
    aws_access_key_id=r2_access_key,
    aws_secret_access_key=r2_secret_key,
    region_name='auto'
)

class UserRegister(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    password: str
    gender: str
    phone: Optional[str] = None
    address: Optional[str] = None
    date_of_birth: Optional[date] = None
    role: Optional[str] = "user"
    status: Optional[str] = "active"

class UserLogin(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    date_of_birth: Optional[date] = None
    gender: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    password: Optional[str] = None
    status: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    username: str
    phone: Optional[str]
    address: Optional[str]
    date_of_birth: Optional[date]
    gender: str
    email: str
    role: str
    created_at: datetime
    updated_at: datetime
    last_logon: Optional[datetime]
    status: str

class LoginResponse(BaseModel):
    message: str
    access_token: str
    user: UserResponse

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    unit: str = "cu.m"
    stock_quantity: float = 0
    price: float
    is_active: bool = True

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    unit: Optional[str] = None
    stock_quantity: Optional[float] = None
    price: Optional[float] = None
    is_active: Optional[bool] = None

class ProductResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    category: Optional[str]
    unit: str
    stock_quantity: float
    price: float
    image_url: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

class MessageResponse(BaseModel):
    message: str
    user_id: Optional[int] = None

class CartCreate(BaseModel):
    product_id: int
    quantity: int = 1

class CartUpdate(BaseModel):
    quantity: int

class CartResponse(BaseModel):
    id: int
    user_id: int
    product_id: int
    quantity: int
    created_at: datetime
    updated_at: datetime
    product_name: Optional[str] = None
    product_price: Optional[float] = None
    product_image: Optional[str] = None
    user_first_name: Optional[str] = None
    user_last_name: Optional[str] = None
    user_username: Optional[str] = None
    user_email: Optional[str] = None
    user_phone: Optional[str] = None
    user_address: Optional[str] = None

class OrderCreate(BaseModel):
    product_id: int
    quantity: float = 1.0
    payment_terms: str  # 'cash_on_delivery' or 'over_the_counter'
    shipping_address: Optional[str] = None

class OrderUpdate(BaseModel):
    quantity: Optional[float] = None
    payment_terms: Optional[str] = None
    payment_status: Optional[str] = None
    order_status: Optional[str] = None
    shipping_address: Optional[str] = None

class OrderResponse(BaseModel):
    id: int
    order_number: str
    user_id: int
    product_id: int
    quantity: float
    total_amount: float
    payment_terms: str
    payment_status: str
    order_status: str
    shipping_address: Optional[str]
    created_at: datetime
    updated_at: datetime
    # Optional product details
    product_name: Optional[str] = None
    product_price: Optional[float] = None
    product_image: Optional[str] = None
    # Optional user details
    user_first_name: Optional[str] = None
    user_last_name: Optional[str] = None
    user_email: Optional[str] = None
    user_phone: Optional[str] = None

class NotificationCreate(BaseModel):
    type: str  # 'new_order', 'order_updated', 'payment_received', 'user_registered'
    title: str
    message: str
    related_id: Optional[int] = None
    related_type: Optional[str] = None  # 'order', 'user', 'product'
    triggered_by_user_id: Optional[int] = None
    priority: Optional[str] = "medium"  # 'low', 'medium', 'high', 'urgent'
    metadata: Optional[dict] = None

class NotificationUpdate(BaseModel):
    status: Optional[str] = None  # 'unread', 'read', 'archived'
    priority: Optional[str] = None

class NotificationResponse(BaseModel):
    id: int
    type: str
    title: str
    message: str
    related_id: Optional[int]
    related_type: Optional[str]
    triggered_by_user_id: Optional[int]
    status: str
    priority: str
    metadata: Optional[dict]
    created_at: datetime
    updated_at: datetime
    read_at: Optional[datetime]
    # Optional user details who triggered the notification
    user_first_name: Optional[str] = None
    user_last_name: Optional[str] = None
    user_email: Optional[str] = None

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

async def upload_image_to_r2(file: UploadFile) -> str:
    """
    Upload image to Cloudflare R2 and return the public URL
    """
    try:
        print(f"DEBUG: Starting upload for file: {file.filename}")
        
        # Validate file exists and has content
        if not file or not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
        unique_filename = f"products/{uuid.uuid4()}.{file_extension}"
        print(f"DEBUG: Generated unique filename: {unique_filename}")
        
        file_content = await file.read()
        print(f"DEBUG: File content length: {len(file_content) if file_content else 0}")
        
        # Check if file content is empty
        if not file_content:
            raise HTTPException(status_code=400, detail="Empty file provided")
        
        print(f"DEBUG: R2 config - bucket: {r2_bucket_name}, endpoint: {r2_endpoint}")
        print(f"DEBUG: Content type: {file.content_type}")
        
        s3_client.put_object(
            Bucket=r2_bucket_name,
            Key=unique_filename,
            Body=file_content,
            ContentType=file.content_type or 'application/octet-stream'
        )
        
        # Store only the filename, not the full URL
        image_url = unique_filename
        print(f"DEBUG: Upload successful, URL: {image_url}")
        return image_url
        
    except Exception as e:
        print(f"DEBUG: Upload failed with error: {e}")
        print(f"DEBUG: Error type: {type(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

def delete_image_from_r2(filename: str):
    """
    Delete image from Cloudflare R2 using the filename
    """
    try:
        s3_client.delete_object(Bucket=r2_bucket_name, Key=filename)
    except Exception as e:
        print(f"Failed to delete image: {str(e)}")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return int(user_id_str)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@app.get("/")
async def root():
    """
    Health check endpoint
    
    Returns a simple message to confirm the API is running
    """
    return {"message": "AgriVet API is running"}

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_password
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

@app.post("/register", response_model=MessageResponse, status_code=201)
async def register(user: UserRegister):
    """
    Register a new user
    
    - **first_name**: User's first name
    - **last_name**: User's last name  
    - **username**: Unique username
    - **email**: Valid email address
    - **password**: User's password (will be hashed)
    - **gender**: User's gender
    - **phone**: Optional phone number
    - **address**: Optional address
    - **date_of_birth**: Optional date of birth
    - **role**: User role (defaults to 'user')
    - **status**: Account status (defaults to 'active')
    """
    try:
        hashed_password = hash_password(user.password)
        
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        check_query = "SELECT id FROM users WHERE username = %s OR email = %s"
        cursor.execute(check_query, (user.username, user.email))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username or email already exists")
        
        insert_query = """
        INSERT INTO users (first_name, last_name, username, phone, address, date_of_birth, 
                          gender, email, role, password, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            user.first_name,
            user.last_name,
            user.username,
            user.phone,
            user.address,
            user.date_of_birth,
            user.gender,
            user.email,
            user.role,
            hashed_password,
            user.status
        )
        
        cursor.execute(insert_query, values)
        connection.commit()
        
        user_id = cursor.lastrowid
        
        # Create notification for new user registration
        create_notification(
            notification_type="user_registered",
            title="New User Registered",
            message=f"New user {user.first_name} {user.last_name} ({user.email}) has registered",
            related_id=user_id,
            related_type="user",
            triggered_by_user_id=user_id,
            priority="low",
            metadata={"username": user.username, "email": user.email, "role": user.role}
        )
        
        return MessageResponse(message="User registered successfully", user_id=user_id)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/login", response_model=LoginResponse)
async def login(user_credentials: UserLogin):
    """
    Authenticate user and return access token
    
    - **username**: Username or email address
    - **password**: User's password
    
    Returns access token and user information on successful authentication
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT * FROM users WHERE username = %s OR email = %s"
        cursor.execute(query, (user_credentials.username, user_credentials.username))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=401, detail="Email or username not found")
        
        if user['status'] != 'active':
            raise HTTPException(status_code=401, detail="Account is disabled")
        
        if not verify_password(user_credentials.password, user['password']):
            raise HTTPException(status_code=401, detail="Invalid password")
        
        update_query = "UPDATE users SET last_logon = %s WHERE id = %s"
        cursor.execute(update_query, (datetime.now(), user['id']))
        connection.commit()
        
        access_token = create_access_token(data={"sub": str(user['id'])})
        
        user_data = UserResponse(
            id=user['id'],
            first_name=user['first_name'],
            last_name=user['last_name'],
            username=user['username'],
            phone=user['phone'],
            address=user['address'],
            date_of_birth=user['date_of_birth'],
            gender=user['gender'],
            email=user['email'],
            role=user['role'],
            created_at=user['created_at'],
            updated_at=user['updated_at'],
            last_logon=user['last_logon'],
            status=user['status']
        )
        
        return LoginResponse(
            message="Login successful",
            access_token=access_token,
            user=user_data
        )
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.put("/user", response_model=MessageResponse)
async def edit_user(user_update: UserUpdate, current_user_id: int = Depends(get_current_user)):
    """
    Update current user's profile
    
    Allows users to update their own profile information including:
    - Personal details (first_name, last_name, phone, address, date_of_birth, gender)
    - Email address
    - Password (will be hashed)
    
    Admin-only fields (require admin role):
    - username (must be unique)
    - role (must be 'admin' or 'user')
    - status (must be 'active' or 'disable')
    
    Validation rules:
    - email and username must be unique
    - gender must be 'male', 'female', or 'non-binary'
    - role must be 'admin' or 'user'
    - status must be 'active' or 'disable'
    
    Requires valid authentication token.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        check_query = "SELECT id FROM users WHERE id = %s"
        cursor.execute(check_query, (current_user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        
        update_fields = []
        values = []
        
        update_data = user_update.model_dump(exclude_unset=True)
        
        # Check if user is admin for sensitive field updates
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        current_user = cursor.fetchone()
        is_admin = current_user and current_user[0] == 'admin'
        
        # Standard fields that any user can update
        allowed_fields = ['first_name', 'last_name', 'phone', 'address', 'date_of_birth', 'gender', 'email']
        
        # Sensitive fields that only admins can update
        admin_only_fields = ['username', 'role', 'status']
        
        for field in allowed_fields:
            if field in update_data:
                # Check for unique constraints
                if field == 'email' and update_data[field]:
                    check_email_query = "SELECT id FROM users WHERE email = %s AND id != %s"
                    cursor.execute(check_email_query, (update_data[field], current_user_id))
                    if cursor.fetchone():
                        raise HTTPException(status_code=409, detail="Email already exists")
                
                # Validate gender enum
                if field == 'gender' and update_data[field] not in ['male', 'female', 'non-binary']:
                    raise HTTPException(status_code=400, detail="Gender must be 'male', 'female', or 'non-binary'")
                
                update_fields.append(f"{field} = %s")
                values.append(update_data[field])
        
        # Handle admin-only fields
        for field in admin_only_fields:
            if field in update_data:
                if not is_admin:
                    raise HTTPException(status_code=403, detail=f"Admin access required to update {field}")
                
                # Additional validation for sensitive fields
                if field == 'username' and update_data[field]:
                    check_username_query = "SELECT id FROM users WHERE username = %s AND id != %s"
                    cursor.execute(check_username_query, (update_data[field], current_user_id))
                    if cursor.fetchone():
                        raise HTTPException(status_code=409, detail="Username already exists")
                
                if field == 'role' and update_data[field] not in ['admin', 'user']:
                    raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
                
                if field == 'status' and update_data[field] not in ['active', 'disable']:
                    raise HTTPException(status_code=400, detail="Status must be 'active' or 'disable'")
                
                update_fields.append(f"{field} = %s")
                values.append(update_data[field])
        
        if 'password' in update_data:
            hashed_password = hash_password(update_data['password'])
            update_fields.append("password = %s")
            values.append(hashed_password)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        values.append(current_user_id)
        update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
        
        cursor.execute(update_query, values)
        connection.commit()
        
        return MessageResponse(message="User updated successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/user", response_model=MessageResponse)
async def delete_user(current_user_id: int = Depends(get_current_user)):
    """
    Delete current user's account
    
    Permanently deletes the authenticated user's account.
    This action cannot be undone.
    
    Requires valid authentication token.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        check_query = "SELECT id FROM users WHERE id = %s"
        cursor.execute(check_query, (current_user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        
        delete_query = "DELETE FROM users WHERE id = %s"
        cursor.execute(delete_query, (current_user_id,))
        connection.commit()
        
        return MessageResponse(message="User deleted successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/users", response_model=List[UserResponse])
async def get_users(current_user_id: int = Depends(get_current_user)):
    """
    Get a list of all users (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    Returns a list of all users with complete profile information:
    - id, first_name, last_name, username, phone, address, date_of_birth
    - gender, email, role, created_at, updated_at, last_logon, status
    
    Note: Password field is excluded for security reasons.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        cursor = connection.cursor(dictionary=True)
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        # Get all users (excluding password for security)
        cursor.execute("""
            SELECT id, first_name, last_name, username, phone, address, date_of_birth, 
                   gender, email, role, created_at, updated_at, last_logon, status 
            FROM users
        """)
        users = cursor.fetchall()
        return [UserResponse(**u) for u in users]
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/user/{user_id}", response_model=MessageResponse)
async def delete_user_by_id(user_id: int, current_user_id: int = Depends(get_current_user)):
    """
    Delete a user by ID (Admin only)
    
    Allows administrators to delete any user account by ID.
    This action cannot be undone.
    
    - **user_id**: ID of the user to delete
    
    Requires admin role and valid authentication token.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        current_user_query = "SELECT role FROM users WHERE id = %s"
        cursor.execute(current_user_query, (current_user_id,))
        current_user = cursor.fetchone()
        
        if not current_user or current_user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        check_query = "SELECT id FROM users WHERE id = %s"
        cursor.execute(check_query, (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        
        delete_query = "DELETE FROM users WHERE id = %s"
        cursor.execute(delete_query, (user_id,))
        connection.commit()
        
        return MessageResponse(message="User deleted successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.put("/change-password", response_model=MessageResponse)
async def change_password(password_request: ChangePasswordRequest, current_user_id: int = Depends(get_current_user)):
    """
    Change current user's password
    
    Allows users to change their password by providing their current password
    and a new password. Requires valid authentication token.
    
    - **current_password**: User's current password for verification
    - **new_password**: New password to set (will be hashed)
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT password FROM users WHERE id = %s"
        cursor.execute(query, (current_user_id,))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not verify_password(password_request.current_password, user['password']):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        
        hashed_new_password = hash_password(password_request.new_password)
        
        update_query = "UPDATE users SET password = %s WHERE id = %s"
        cursor.execute(update_query, (hashed_new_password, current_user_id))
        connection.commit()
        
        return MessageResponse(message="Password changed successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/products", response_model=ProductResponse, status_code=201)
async def create_product(
    name: str = Form(...),
    description: str = Form(None),
    category: str = Form(None),
    unit: str = Form("cu.m"),
    stock_quantity: float = Form(0),
    price: float = Form(...),
    is_active: bool = Form(True),
    image: UploadFile = File(None),
    current_user_id: int = Depends(get_current_user)
):
    """
    Create a new product with optional image upload
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Form data fields:
    - **name**: Product name (required)
    - **description**: Product description (optional)
    - **category**: Product category (optional)
    - **unit**: Measurement unit (defaults to "cu.m")
    - **stock_quantity**: Available stock quantity (defaults to 0)
    - **price**: Product price (required)
    - **is_active**: Whether product is active (defaults to true)
    - **image**: Product image file (optional)
    
    Returns the created product with generated ID and timestamps.
    """
    try:
        print(f"DEBUG: image parameter: {image}")
        print(f"DEBUG: image type: {type(image)}")
        if image:
            print(f"DEBUG: image.filename: {image.filename}")
            print(f"DEBUG: image.content_type: {image.content_type}")
        
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        image_url = None
        if image and hasattr(image, 'filename') and image.filename and image.filename.strip():
            print("DEBUG: About to upload image")
            image_url = await upload_image_to_r2(image)
            print(f"DEBUG: Image uploaded, URL: {image_url}")
        else:
            print("DEBUG: No image to upload")
        
        insert_query = """
        INSERT INTO products (name, description, category, unit, stock_quantity, price, image_url, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (name, description, category, unit, stock_quantity, price, image_url, is_active)
        cursor.execute(insert_query, values)
        connection.commit()
        
        product_id = cursor.lastrowid
        
        select_query = "SELECT * FROM products WHERE id = %s"
        cursor.execute(select_query, (product_id,))
        product = cursor.fetchone()
        
        return ProductResponse(**product)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/products", response_model=List[ProductResponse])
async def get_products(
    skip: int = 0,
    limit: int = 100,
    category: Optional[str] = None,
    is_active: Optional[bool] = None
):
    """
    Get all products with optional filtering
    
    **No Authentication Required**: Public endpoint
    
    Query parameters:
    - **skip**: Number of records to skip for pagination (default: 0)
    - **limit**: Maximum number of records to return (default: 100)
    - **category**: Filter by product category (optional)
    - **is_active**: Filter by active status (optional)
    
    Returns a list of products ordered by creation date (newest first).
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT * FROM products WHERE 1=1"
        params = []
        
        if category:
            query += " AND category = %s"
            params.append(category)
        
        if is_active is not None:
            query += " AND is_active = %s"
            params.append(is_active)
        
        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        cursor.execute(query, params)
        products = cursor.fetchall()
        
        return [ProductResponse(**product) for product in products]
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/products/{product_id}", response_model=ProductResponse)
async def get_product(product_id: int):
    """
    Get a specific product by ID
    
    **No Authentication Required**: Public endpoint
    
    Path parameters:
    - **product_id**: ID of the product to retrieve
    
    Returns the product details including image URL if available.
    Returns 404 if product is not found.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT * FROM products WHERE id = %s"
        cursor.execute(query, (product_id,))
        product = cursor.fetchone()
        
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        
        return ProductResponse(**product)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/images/{filename:path}")
async def get_image(filename: str):
    """
    Serve images from R2 storage
    
    **No Authentication Required**: Public endpoint
    
    Path parameters:
    - **filename**: Name of the image file to retrieve (supports path with slashes)
    
    Returns the image file as a streaming response.
    """
    try:
        print(f"DEBUG IMAGE ENDPOINT: Requested filename: '{filename}'")
        print(f"DEBUG IMAGE ENDPOINT: R2 bucket: '{r2_bucket_name}'")
        print(f"DEBUG IMAGE ENDPOINT: R2 endpoint: '{r2_endpoint}'")
        
        response = s3_client.get_object(Bucket=r2_bucket_name, Key=filename)
        file_stream = io.BytesIO(response['Body'].read())
        
        print(f"DEBUG IMAGE ENDPOINT: Successfully fetched file from R2")
        print(f"DEBUG IMAGE ENDPOINT: File size: {len(file_stream.getvalue())} bytes")
        
        # Get content type from response or default to image/jpeg
        content_type = response.get('ContentType', 'image/jpeg')
        print(f"DEBUG IMAGE ENDPOINT: Content type: {content_type}")
        
        return StreamingResponse(
            io.BytesIO(file_stream.getvalue()), 
            media_type=content_type,
            headers={"Cache-Control": "public, max-age=3600"}
        )
        
    except Exception as e:
        print(f"DEBUG IMAGE ENDPOINT ERROR: {type(e).__name__}: {str(e)}")
        print(f"DEBUG IMAGE ENDPOINT ERROR: Bucket: '{r2_bucket_name}', Key: '{filename}'")
        raise HTTPException(status_code=404, detail=f"Image not found: {str(e)}")

@app.put("/products/{product_id}", response_model=ProductResponse)
async def update_product(
    product_id: int,
    name: str = Form(None),
    description: str = Form(None),
    category: str = Form(None),
    unit: str = Form(None),
    stock_quantity: float = Form(None),
    price: float = Form(None),
    is_active: bool = Form(None),
    image: UploadFile = File(None),
    current_user_id: int = Depends(get_current_user)
):
    """
    Update a product with optional image replacement
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Path parameters:
    - **product_id**: ID of the product to update
    
    Form data fields (all optional):
    - **name**: Product name
    - **description**: Product description
    - **category**: Product category
    - **unit**: Measurement unit
    - **stock_quantity**: Available stock quantity
    - **price**: Product price
    - **is_active**: Whether product is active
    - **image**: New product image file (replaces existing image if provided)
    
    Returns the updated product with modified timestamps.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        check_query = "SELECT * FROM products WHERE id = %s"
        cursor.execute(check_query, (product_id,))
        existing_product = cursor.fetchone()
        
        if not existing_product:
            raise HTTPException(status_code=404, detail="Product not found")
        
        update_fields = []
        values = []
        
        if name is not None:
            update_fields.append("name = %s")
            values.append(name)
        if description is not None:
            update_fields.append("description = %s")
            values.append(description)
        if category is not None:
            update_fields.append("category = %s")
            values.append(category)
        if unit is not None:
            update_fields.append("unit = %s")
            values.append(unit)
        if stock_quantity is not None:
            update_fields.append("stock_quantity = %s")
            values.append(stock_quantity)
        if price is not None:
            update_fields.append("price = %s")
            values.append(price)
        if is_active is not None:
            update_fields.append("is_active = %s")
            values.append(is_active)
        
        if image and hasattr(image, 'filename') and image.filename and image.filename.strip():
            if existing_product['image_url']:
                delete_image_from_r2(existing_product['image_url'])
            
            new_image_url = await upload_image_to_r2(image)
            update_fields.append("image_url = %s")
            values.append(new_image_url)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        values.append(product_id)
        
        update_query = f"UPDATE products SET {', '.join(update_fields)} WHERE id = %s"
        cursor.execute(update_query, values)
        connection.commit()
        
        select_query = "SELECT * FROM products WHERE id = %s"
        cursor.execute(select_query, (product_id,))
        updated_product = cursor.fetchone()
        
        return ProductResponse(**updated_product)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/products/{product_id}", response_model=MessageResponse)
async def delete_product(product_id: int, current_user_id: int = Depends(get_current_user)):
    """
    Delete a product and its associated image
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Path parameters:
    - **product_id**: ID of the product to delete
    
    This action permanently deletes the product from the database and removes
    any associated image file from cloud storage. This action cannot be undone.
    
    Returns success message upon completion.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        check_query = "SELECT * FROM products WHERE id = %s"
        cursor.execute(check_query, (product_id,))
        product = cursor.fetchone()
        
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        
        if product['image_url']:
            delete_image_from_r2(product['image_url'])
        
        delete_query = "DELETE FROM products WHERE id = %s"
        cursor.execute(delete_query, (product_id,))
        connection.commit()
        
        return MessageResponse(message="Product deleted successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/cart", response_model=MessageResponse, status_code=201)
async def add_to_cart(cart_item: CartCreate, current_user_id: int = Depends(get_current_user)):
    """
    Add item to cart or update quantity if item already exists
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    - **product_id**: ID of the product to add
    - **quantity**: Quantity to add (default: 1)
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        # Check if product exists
        product_check = "SELECT id FROM products WHERE id = %s"
        cursor.execute(product_check, (cart_item.product_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Product not found")
        
        # Add to cart or update quantity
        insert_query = """
        INSERT INTO cart (user_id, product_id, quantity) 
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
        """
        
        cursor.execute(insert_query, (current_user_id, cart_item.product_id, cart_item.quantity))
        connection.commit()
        
        return MessageResponse(message="Item added to cart successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/cart", response_model=List[CartResponse])
async def get_cart(current_user_id: int = Depends(get_current_user)):
    """
    Get current user's cart items with product details
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Returns list of cart items with product information.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT c.*, p.name as product_name, p.price as product_price, p.image_url as product_image
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s
        ORDER BY c.created_at DESC
        """
        
        cursor.execute(query, (current_user_id,))
        cart_items = cursor.fetchall()
        
        return [CartResponse(**item) for item in cart_items]
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.put("/cart/{product_id}", response_model=MessageResponse)
async def update_cart_item(
    product_id: int, 
    cart_update: CartUpdate, 
    current_user_id: int = Depends(get_current_user)
):
    """
    Update quantity of item in cart
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Path parameters:
    - **product_id**: ID of the product in cart
    
    - **quantity**: New quantity for the item
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        # Check if item exists in user's cart
        check_query = "SELECT id FROM cart WHERE user_id = %s AND product_id = %s"
        cursor.execute(check_query, (current_user_id, product_id))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Item not found in cart")
        
        # Update quantity
        update_query = "UPDATE cart SET quantity = %s WHERE user_id = %s AND product_id = %s"
        cursor.execute(update_query, (cart_update.quantity, current_user_id, product_id))
        connection.commit()
        
        return MessageResponse(message="Cart item updated successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/cart/{product_id}", response_model=MessageResponse)
async def remove_from_cart(product_id: int, current_user_id: int = Depends(get_current_user)):
    """
    Remove item from cart
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Path parameters:
    - **product_id**: ID of the product to remove from cart
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        # Check if item exists in user's cart
        check_query = "SELECT id FROM cart WHERE user_id = %s AND product_id = %s"
        cursor.execute(check_query, (current_user_id, product_id))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Item not found in cart")
        
        # Remove item
        delete_query = "DELETE FROM cart WHERE user_id = %s AND product_id = %s"
        cursor.execute(delete_query, (current_user_id, product_id))
        connection.commit()
        
        return MessageResponse(message="Item removed from cart successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/cart", response_model=MessageResponse)
async def clear_cart(current_user_id: int = Depends(get_current_user)):
    """
    Clear all items from cart
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Removes all items from the current user's cart.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        delete_query = "DELETE FROM cart WHERE user_id = %s"
        cursor.execute(delete_query, (current_user_id,))
        connection.commit()
        
        return MessageResponse(message="Cart cleared successfully")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/cartall", response_model=List[CartResponse])
async def get_all_carts(current_user_id: int = Depends(get_current_user)):
    """
    Get all cart items from all users (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    Returns a list of all cart items from all users with complete details:
    - Cart information: id, user_id, product_id, quantity, created_at, updated_at
    - Product details: product_name, product_price, product_image
    - User credentials: user_first_name, user_last_name, user_username, user_email, user_phone, user_address
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Get all cart items with product and user details
        query = """
        SELECT c.*, 
               p.name as product_name, p.price as product_price, p.image_url as product_image,
               u.first_name as user_first_name, u.last_name as user_last_name, 
               u.username as user_username, u.email as user_email, u.phone as user_phone, u.address as user_address
        FROM cart c
        JOIN products p ON c.product_id = p.id
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
        """
        
        cursor.execute(query)
        cart_items = cursor.fetchall()
        
        return [CartResponse(**item) for item in cart_items]
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def generate_order_number():
    """Generate a unique order number"""
    timestamp = datetime.now().strftime("%Y%m%d")
    random_part = ''.join(random.choices(string.digits, k=6))
    return f"ORD{timestamp}{random_part}"

@app.post("/orders", response_model=OrderResponse, status_code=201)
async def create_order(order: OrderCreate, current_user_id: int = Depends(get_current_user)):
    """
    Create a new order
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    - **product_id**: ID of the product to order
    - **quantity**: Quantity to order (default: 1.0)
    - **payment_terms**: Payment method ('cash_on_delivery' or 'over_the_counter')
    - **shipping_address**: Optional shipping address
    
    Returns the created order with generated order number and calculated total.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Validate payment terms
        if order.payment_terms not in ['cash_on_delivery', 'over_the_counter']:
            raise HTTPException(status_code=400, detail="Payment terms must be 'cash_on_delivery' or 'over_the_counter'")
        
        # Check if product exists and get price
        product_query = "SELECT id, price, name FROM products WHERE id = %s AND is_active = 1"
        cursor.execute(product_query, (order.product_id,))
        product = cursor.fetchone()
        
        if not product:
            raise HTTPException(status_code=404, detail="Product not found or inactive")
        
        # Calculate total amount
        total_amount = float(product['price']) * order.quantity
        
        # Generate unique order number
        order_number = generate_order_number()
        
        # Insert order
        insert_query = """
        INSERT INTO orders (order_number, user_id, product_id, quantity, total_amount, 
                           payment_terms, shipping_address)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            order_number,
            current_user_id,
            order.product_id,
            order.quantity,
            total_amount,
            order.payment_terms,
            order.shipping_address
        )
        
        cursor.execute(insert_query, values)
        connection.commit()
        
        order_id = cursor.lastrowid
        
        # Create notification for new order
        create_notification(
            notification_type="new_order",
            title="New Order Created",
            message=f"New order #{order_number} created for {product['name']} (Qty: {order.quantity})",
            related_id=order_id,
            related_type="order",
            triggered_by_user_id=current_user_id,
            priority="medium",
            metadata={"order_number": order_number, "product_name": product['name'], "total_amount": total_amount}
        )
        
        # Fetch the created order with product details
        select_query = """
        SELECT o.*, p.name as product_name, p.price as product_price, p.image_url as product_image
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.id = %s
        """
        cursor.execute(select_query, (order_id,))
        created_order = cursor.fetchone()
        
        return OrderResponse(**created_order)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/orders", response_model=List[OrderResponse])
async def get_user_orders(current_user_id: int = Depends(get_current_user)):
    """
    Get current user's orders
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Returns a list of orders for the authenticated user with product details.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT o.*, p.name as product_name, p.price as product_price, p.image_url as product_image
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = %s
        ORDER BY o.created_at DESC
        """
        
        cursor.execute(query, (current_user_id,))
        orders = cursor.fetchall()
        
        return [OrderResponse(**order) for order in orders]
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/orders/all", response_model=List[OrderResponse])
async def get_all_orders(current_user_id: int = Depends(get_current_user)):
    """
    Get all orders from all users (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    Returns a list of all orders with product and user details.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Get all orders with product and user details
        query = """
        SELECT o.*, 
               p.name as product_name, p.price as product_price, p.image_url as product_image,
               u.first_name as user_first_name, u.last_name as user_last_name, 
               u.email as user_email, u.phone as user_phone
        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
        """
        
        cursor.execute(query)
        orders = cursor.fetchall()
        
        return [OrderResponse(**order) for order in orders]
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/orders/{order_id}", response_model=OrderResponse)
async def get_order(order_id: int, current_user_id: int = Depends(get_current_user)):
    """
    Get a specific order by ID
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Users can only view their own orders unless they are admin.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        is_admin = user and user['role'] == 'admin'
        
        # Get order with product and user details
        query = """
        SELECT o.*, 
               p.name as product_name, p.price as product_price, p.image_url as product_image,
               u.first_name as user_first_name, u.last_name as user_last_name, 
               u.email as user_email, u.phone as user_phone
        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.user_id = u.id
        WHERE o.id = %s
        """
        
        cursor.execute(query, (order_id,))
        order = cursor.fetchone()
        
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        
        # Check if user owns the order or is admin
        if not is_admin and order['user_id'] != current_user_id:
            raise HTTPException(status_code=403, detail="Access denied: You can only view your own orders")
        
        return OrderResponse(**order)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.put("/orders/{order_id}", response_model=OrderResponse)
async def update_order(order_id: int, order_update: OrderUpdate, current_user_id: int = Depends(get_current_user)):
    """
    Update an order
    
    **Requires Authentication**: Bearer token required in Authorization header
    
    Users can update their own orders. Admins can update any order.
    
    - **quantity**: New quantity (optional)
    - **payment_terms**: Payment method (optional)
    - **payment_status**: Payment status (optional, admin only)
    - **order_status**: Order status (optional, admin only)
    - **shipping_address**: Shipping address (optional)
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        is_admin = user and user['role'] == 'admin'
        
        # Check if order exists and get current details
        check_query = "SELECT * FROM orders WHERE id = %s"
        cursor.execute(check_query, (order_id,))
        existing_order = cursor.fetchone()
        
        if not existing_order:
            raise HTTPException(status_code=404, detail="Order not found")
        
        # Check if user owns the order or is admin
        if not is_admin and existing_order['user_id'] != current_user_id:
            raise HTTPException(status_code=403, detail="Access denied: You can only update your own orders")
        
        update_fields = []
        values = []
        update_data = order_update.model_dump(exclude_unset=True)
        
        # Fields that regular users can update
        user_fields = ['quantity', 'payment_terms', 'shipping_address']
        # Fields only admins can update
        admin_fields = ['payment_status', 'order_status']
        
        for field in user_fields:
            if field in update_data:
                if field == 'payment_terms' and update_data[field] not in ['cash_on_delivery', 'over_the_counter']:
                    raise HTTPException(status_code=400, detail="Payment terms must be 'cash_on_delivery' or 'over_the_counter'")
                
                update_fields.append(f"{field} = %s")
                values.append(update_data[field])
        
        for field in admin_fields:
            if field in update_data:
                if not is_admin:
                    raise HTTPException(status_code=403, detail=f"Admin access required to update {field}")
                
                if field == 'payment_status' and update_data[field] not in ['pending', 'paid', 'failed']:
                    raise HTTPException(status_code=400, detail="Payment status must be 'pending', 'paid', or 'failed'")
                
                if field == 'order_status' and update_data[field] not in ['pending', 'processing', 'on_delivery', 'completed', 'canceled']:
                    raise HTTPException(status_code=400, detail="Order status must be 'pending', 'processing', 'on_delivery', 'completed', or 'canceled'")
                
                update_fields.append(f"{field} = %s")
                values.append(update_data[field])
        
        # Recalculate total if quantity changed
        if 'quantity' in update_data:
            # Get product price
            cursor.execute("SELECT price FROM products WHERE id = %s", (existing_order['product_id'],))
            product = cursor.fetchone()
            if product:
                new_total = float(product['price']) * update_data['quantity']
                update_fields.append("total_amount = %s")
                values.append(new_total)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        values.append(order_id)
        update_query = f"UPDATE orders SET {', '.join(update_fields)} WHERE id = %s"
        
        cursor.execute(update_query, values)
        connection.commit()
        
        # Create notification for order update
        if 'payment_status' in update_data and update_data['payment_status'] == 'paid':
            # Special notification for payment received
            create_notification(
                notification_type="payment_received",
                title="Payment Received",
                message=f"Payment received for order #{existing_order['order_number']}",
                related_id=order_id,
                related_type="order",
                triggered_by_user_id=current_user_id,
                priority="medium",
                metadata={"order_number": existing_order['order_number'], "payment_status": "paid"}
            )
        else:
            # General order update notification
            create_notification(
                notification_type="order_updated",
                title="Order Updated",
                message=f"Order #{existing_order['order_number']} has been updated",
                related_id=order_id,
                related_type="order",
                triggered_by_user_id=current_user_id,
                priority="low",
                metadata={"order_number": existing_order['order_number'], "updated_fields": list(update_data.keys())}
            )
        
        # Return updated order with details
        select_query = """
        SELECT o.*, 
               p.name as product_name, p.price as product_price, p.image_url as product_image,
               u.first_name as user_first_name, u.last_name as user_last_name, 
               u.email as user_email, u.phone as user_phone
        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.user_id = u.id
        WHERE o.id = %s
        """
        cursor.execute(select_query, (order_id,))
        updated_order = cursor.fetchone()
        
        return OrderResponse(**updated_order)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def create_notification(notification_type: str, title: str, message: str, 
                       related_id: int = None, related_type: str = None,
                       triggered_by_user_id: int = None, priority: str = "medium",
                       metadata: dict = None):
    """Helper function to create notifications"""
    try:
        connection = get_db_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        
        metadata_json = json.dumps(metadata) if metadata else None
        
        insert_query = """
        INSERT INTO notifications (type, title, message, related_id, related_type, 
                                 triggered_by_user_id, priority, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (notification_type, title, message, related_id, related_type,
                 triggered_by_user_id, priority, metadata_json)
        
        cursor.execute(insert_query, values)
        connection.commit()
        return True
        
    except Error as e:
        print(f"Error creating notification: {str(e)}")
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/notifications", response_model=List[NotificationResponse])
async def get_notifications(
    status: Optional[str] = None,
    type: Optional[str] = None,
    priority: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user_id: int = Depends(get_current_user)
):
    """
    Get all notifications (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    Query parameters:
    - **status**: Filter by status ('unread', 'read', 'archived')
    - **type**: Filter by type ('new_order', 'order_updated', 'payment_received', 'user_registered')
    - **priority**: Filter by priority ('low', 'medium', 'high', 'urgent')
    - **skip**: Number of records to skip for pagination (default: 0)
    - **limit**: Maximum number of records to return (default: 50)
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Build query with filters
        query = """
        SELECT n.*, 
               u.first_name as user_first_name, u.last_name as user_last_name, u.email as user_email
        FROM notifications n
        LEFT JOIN users u ON n.triggered_by_user_id = u.id
        WHERE 1=1
        """
        params = []
        
        if status:
            query += " AND n.status = %s"
            params.append(status)
        
        if type:
            query += " AND n.type = %s"
            params.append(type)
        
        if priority:
            query += " AND n.priority = %s"
            params.append(priority)
        
        query += " ORDER BY n.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        cursor.execute(query, params)
        notifications = cursor.fetchall()
        
        # Parse metadata JSON
        for notification in notifications:
            if notification['metadata']:
                try:
                    notification['metadata'] = json.loads(notification['metadata'])
                except:
                    notification['metadata'] = None
        
        return [NotificationResponse(**notification) for notification in notifications]
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/notifications/{notification_id}", response_model=NotificationResponse)
async def get_notification(notification_id: int, current_user_id: int = Depends(get_current_user)):
    """
    Get a specific notification by ID (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        query = """
        SELECT n.*, 
               u.first_name as user_first_name, u.last_name as user_last_name, u.email as user_email
        FROM notifications n
        LEFT JOIN users u ON n.triggered_by_user_id = u.id
        WHERE n.id = %s
        """
        
        cursor.execute(query, (notification_id,))
        notification = cursor.fetchone()
        
        if not notification:
            raise HTTPException(status_code=404, detail="Notification not found")
        
        # Parse metadata JSON
        if notification['metadata']:
            try:
                notification['metadata'] = json.loads(notification['metadata'])
            except:
                notification['metadata'] = None
        
        return NotificationResponse(**notification)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.put("/notifications/{notification_id}", response_model=NotificationResponse)
async def update_notification(
    notification_id: int, 
    notification_update: NotificationUpdate, 
    current_user_id: int = Depends(get_current_user)
):
    """
    Update a notification (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    - **status**: Update status ('unread', 'read', 'archived')
    - **priority**: Update priority ('low', 'medium', 'high', 'urgent')
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Check if notification exists
        check_query = "SELECT id FROM notifications WHERE id = %s"
        cursor.execute(check_query, (notification_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Notification not found")
        
        update_fields = []
        values = []
        update_data = notification_update.model_dump(exclude_unset=True)
        
        if 'status' in update_data:
            if update_data['status'] not in ['unread', 'read', 'archived']:
                raise HTTPException(status_code=400, detail="Status must be 'unread', 'read', or 'archived'")
            
            update_fields.append("status = %s")
            values.append(update_data['status'])
            
            # Set read_at timestamp when marking as read
            if update_data['status'] == 'read':
                update_fields.append("read_at = %s")
                values.append(datetime.now())
        
        if 'priority' in update_data:
            if update_data['priority'] not in ['low', 'medium', 'high', 'urgent']:
                raise HTTPException(status_code=400, detail="Priority must be 'low', 'medium', 'high', or 'urgent'")
            
            update_fields.append("priority = %s")
            values.append(update_data['priority'])
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        values.append(notification_id)
        update_query = f"UPDATE notifications SET {', '.join(update_fields)} WHERE id = %s"
        
        cursor.execute(update_query, values)
        connection.commit()
        
        # Return updated notification
        select_query = """
        SELECT n.*, 
               u.first_name as user_first_name, u.last_name as user_last_name, u.email as user_email
        FROM notifications n
        LEFT JOIN users u ON n.triggered_by_user_id = u.id
        WHERE n.id = %s
        """
        cursor.execute(select_query, (notification_id,))
        updated_notification = cursor.fetchone()
        
        # Parse metadata JSON
        if updated_notification['metadata']:
            try:
                updated_notification['metadata'] = json.loads(updated_notification['metadata'])
            except:
                updated_notification['metadata'] = None
        
        return NotificationResponse(**updated_notification)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/notifications", response_model=NotificationResponse, status_code=201)
async def create_notification_endpoint(
    notification: NotificationCreate, 
    current_user_id: int = Depends(get_current_user)
):
    """
    Create a new notification (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    - **type**: Notification type ('new_order', 'order_updated', 'payment_received', 'user_registered')
    - **title**: Notification title
    - **message**: Notification message
    - **related_id**: Optional ID of related entity
    - **related_type**: Optional type of related entity ('order', 'user', 'product')
    - **triggered_by_user_id**: Optional ID of user who triggered the notification
    - **priority**: Priority level ('low', 'medium', 'high', 'urgent')
    - **metadata**: Optional additional data
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor(dictionary=True)
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Validate enum values
        if notification.type not in ['new_order', 'order_updated', 'payment_received', 'user_registered']:
            raise HTTPException(status_code=400, detail="Invalid notification type")
        
        if notification.priority not in ['low', 'medium', 'high', 'urgent']:
            raise HTTPException(status_code=400, detail="Invalid priority level")
        
        if notification.related_type and notification.related_type not in ['order', 'user', 'product']:
            raise HTTPException(status_code=400, detail="Invalid related type")
        
        metadata_json = json.dumps(notification.metadata) if notification.metadata else None
        
        insert_query = """
        INSERT INTO notifications (type, title, message, related_id, related_type, 
                                 triggered_by_user_id, priority, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            notification.type,
            notification.title,
            notification.message,
            notification.related_id,
            notification.related_type,
            notification.triggered_by_user_id,
            notification.priority,
            metadata_json
        )
        
        cursor.execute(insert_query, values)
        connection.commit()
        
        notification_id = cursor.lastrowid
        
        # Return created notification
        select_query = """
        SELECT n.*, 
               u.first_name as user_first_name, u.last_name as user_last_name, u.email as user_email
        FROM notifications n
        LEFT JOIN users u ON n.triggered_by_user_id = u.id
        WHERE n.id = %s
        """
        cursor.execute(select_query, (notification_id,))
        created_notification = cursor.fetchone()
        
        # Parse metadata JSON
        if created_notification['metadata']:
            try:
                created_notification['metadata'] = json.loads(created_notification['metadata'])
            except:
                created_notification['metadata'] = None
        
        return NotificationResponse(**created_notification)
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/notifications/unread/count")
async def get_unread_notifications_count(current_user_id: int = Depends(get_current_user)):
    """
    Get count of unread notifications (admin only)
    
    **Requires Authentication**: Bearer token required in Authorization header
    **Requires Admin Role**: Only admin users can access this endpoint
    
    Returns the number of unread notifications for dashboard badges.
    """
    try:
        connection = get_db_connection()
        if not connection:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        cursor = connection.cursor()
        
        # Check if current user is admin
        cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user or user[0] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        cursor.execute("SELECT COUNT(*) FROM notifications WHERE status = 'unread'")
        count = cursor.fetchone()[0]
        
        return {"unread_count": count}
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)