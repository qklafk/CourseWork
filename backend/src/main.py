# Backend 
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from pydantic import BaseModel, EmailStr, SecretStr, field_validator, Field
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from decimal import Decimal
import bcrypt
from flask_session import Session

app = Flask(__name__)
# Обновленная конфигурация CORS и сессий
app.config.update(
    SECRET_KEY='your-secret-key-here',
    SESSION_TYPE='filesystem',
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=86400
)

CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:3000"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"]
)
Session(app)

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: SecretStr
    
    @field_validator('username')
    def username_length(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: SecretStr

class ItemResponse(BaseModel):
    id: int
    name: str
    float_condition: Optional[str] = Field(None, alias="float")
    float_number: Optional[Decimal] = Field(None, alias="floatNumber")
    count: int
    image_link: str = Field(alias="imageLink")
    price: Decimal

    class Config:
        allow_population_by_field_name = True
        json_encoders = {
            Decimal: lambda v: round(float(v), 2)
        }

# Утилиты для работы с БД
def get_db_connection():
    return psycopg2.connect(
        dbname="mydb",
        user="myuser",
        password="mypassword",
        host="db",
        cursor_factory=RealDictCursor
    )

def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(100) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS items (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    float VARCHAR(20),
                    float_number NUMERIC(6,5),
                    count INT NOT NULL,
                    image_link TEXT NOT NULL,
                    price NUMERIC(10,2) NOT NULL
                );

                -- Добавление отсутствующих таблиц
                CREATE TABLE IF NOT EXISTS cart_items (
                    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    quantity INT NOT NULL DEFAULT 1,
                    PRIMARY KEY (user_id, item_id)
                );

                CREATE TABLE IF NOT EXISTS orders (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    total NUMERIC(10,2) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS order_items (
                    order_id INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                    item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    quantity INT NOT NULL,
                    price NUMERIC(10,2) NOT NULL,
                    PRIMARY KEY (order_id, item_id)
                );
            """)
        conn.commit()
    finally:
        conn.close()

init_db()

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = UserRegister.model_validate(request.json)
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM users WHERE email = %s OR username = %s",
                    (data.email, data.username)
                )
                if cursor.fetchone():
                    return jsonify({"error": "User already exists"}), 409
                
                hashed_pw = bcrypt.hashpw(
                    data.password.get_secret_value().encode('utf-8'), 
                    bcrypt.gensalt()
                ).decode('utf-8')

                cursor.execute(
                    """INSERT INTO users (username, email, password_hash)
                    VALUES (%s, %s, %s) RETURNING id""",
                    (data.username, data.email, hashed_pw)
                )
                user_id = cursor.fetchone()['id']
                conn.commit()
                
        session.clear()
        session['user_id'] = user_id
        session.permanent = True
        
        return jsonify({"message": "Registration successful"}), 201
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = UserLogin.model_validate(request.json)
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, password_hash FROM users WHERE email = %s",
                    (data.email,)
                )
                user = cursor.fetchone()
                
                if not user or not bcrypt.checkpw(
                    data.password.get_secret_value().encode('utf-8'),
                    user['password_hash'].encode('utf-8')
                ):
                    return jsonify({"error": "Invalid credentials"}), 401
                
                session.clear()
                session['user_id'] = user['id']
                session.permanent = True
                
                return jsonify({"message": "Login successful"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logout successful"})

@app.route('/api/me', methods=['GET'])
def get_current_user():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, email FROM users WHERE id = %s",
                (session['user_id'],)
            )
            user = cursor.fetchone()
            return jsonify(user)

@app.route('/api/cart', methods=['GET'])
def get_cart():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT ci.item_id, ci.quantity, i.name, i.price, i.image_link as "imageLink"
                    FROM cart_items ci
                    JOIN items i ON ci.item_id = i.id
                    WHERE ci.user_id = %s
                """, (session['user_id'],))
                items = cursor.fetchall()
                
                cursor.execute("""
                    SELECT COALESCE(SUM(i.price * ci.quantity), 0) as total
                    FROM cart_items ci
                    JOIN items i ON ci.item_id = i.id
                    WHERE ci.user_id = %s
                """, (session['user_id'],))
                total = cursor.fetchone()['total']
                
        return jsonify({
            "items": items,
            "total": total
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    item_id = data.get('item_id')
    quantity = data.get('quantity', 1)

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO cart_items (user_id, item_id, quantity)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id, item_id) 
                    DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity
                """, (session['user_id'], item_id, quantity))
                conn.commit()
                
        return jsonify({"message": "Item added to cart"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/cart/update', methods=['PUT'])
def update_cart_item():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    item_id = data.get('item_id')
    quantity = data.get('quantity')

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                if quantity <= 0:
                    cursor.execute(
                        "DELETE FROM cart_items WHERE user_id = %s AND item_id = %s",
                        (session['user_id'], item_id)
                    )
                else:
                    cursor.execute(
                        """UPDATE cart_items SET quantity = %s 
                        WHERE user_id = %s AND item_id = %s""",
                        (quantity, session['user_id'], item_id)
                    )
                conn.commit()
                
        return jsonify({"message": "Cart updated"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cart/remove', methods=['DELETE'])
def remove_from_cart():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    item_id = data.get('item_id')

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM cart_items WHERE user_id = %s AND item_id = %s",
                    (session['user_id'], item_id)
                )
                conn.commit()
                
        return jsonify({"message": "Item removed from cart"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/items', methods=['GET'])
def get_items():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                id,
                name,
                float,
                float_number as "floatNumber",
                count,
                image_link as "imageLink",
                price::numeric AS price
            FROM items 
            ORDER BY id
        """)
        
        items = []
        for record in cursor.fetchall():
            item_data = {
                **record,
                "price": Decimal(str(record['price']))
            }
            items.append(ItemResponse(**item_data).model_dump())
        
        return jsonify({
            "data": items
        })
        
    except psycopg2.Error as e:
        return jsonify({
            "status": "error",
            "message": f"Database error: {str(e)}"
        }), 500
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)