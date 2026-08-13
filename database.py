import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = "phishing_history.db"


def connect():

    db = sqlite3.connect(
        DATABASE,
        timeout=10,
        check_same_thread=False
    )

    db.row_factory = sqlite3.Row

    return db

def delete_review(review_id):

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM reviews WHERE id=?",
        (review_id,)
    )

    conn.commit()
    conn.close()
def make_admin(user_id):

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET role='admin'
        WHERE id=?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

def delete_user(user_id):

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scans WHERE user_id=?",
        (user_id,)
    )

    cursor.execute(
        "DELETE FROM users WHERE id=?",
        (user_id,)
    )

    conn.commit()
    conn.close()
    
# ================================
# СОЗДАНИЕ БАЗЫ
# ================================

def init_database():


  
    db = connect()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        device TEXT,
        operating_system TEXT,
        browser TEXT,
        language TEXT,
        user_agent TEXT,
        latitude REAL,
        longitude REAL
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        domain TEXT,
        score INTEGER,
        risk TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reviews(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        username TEXT,
        rating INTEGER,
        text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER,

    url TEXT,

    domain TEXT,

    score INTEGER,

    risk_level TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id) REFERENCES users(id)

)
""")
    db.commit()
    db.close()



# ================================
# ADMIN
# ================================

def create_admin():

    db = connect()

    user = db.execute(
        "SELECT * FROM users WHERE username=?",
        ("Sadi",)
    ).fetchone()


    if not user:

        db.execute("""
        INSERT INTO users
        (username,password_hash,role)
        VALUES(?,?,?)
        """,
        (
            "Sadi",
            generate_password_hash("Aser15"),
            "admin"
        ))

    else:

        db.execute("""
        UPDATE users
        SET role='admin'
        WHERE username='Sadi'
        """)


    db.commit()
    db.close()



# ================================
# USER
# ================================

def create_user(
    username,
    password,
    ip=None,
    device=None,
    os=None,
    browser=None,
    language=None,
    user_agent=None,
    latitude=None,
    longitude=None
):
    db = connect()

    try:
        # Проверяем, существует ли пользователь
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing:
            return False

        password_hash = generate_password_hash(password)

        # Создаём пользователя
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO users
            (
                username,
                password_hash,
                role
            )
            VALUES (?, ?, ?)
        """, (
            username,
            password_hash,
            "user"
        ))

        user_id = cursor.lastrowid

        # Сохраняем информацию об устройстве
        cursor.execute("""
            INSERT INTO user_devices
            (
                user_id,
                ip_address,
                device,
                operating_system,
                browser,
                language,
                user_agent,
                latitude,
                longitude
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            ip,
            device,
            os,
            browser,
            language,
            user_agent,
            latitude,
            longitude
        ))

        # Записываем регистрацию в журнал
        cursor.execute("""
            INSERT INTO logs
            (
                user_id,
                action
            )
            VALUES (?, ?)
        """, (
            user_id,
            "Регистрация"
        ))

        db.commit()

        return True

    except sqlite3.IntegrityError as e:
        db.rollback()
        print("Ошибка базы данных при регистрации:", e)
        return False

    except Exception as e:
        db.rollback()
        print("Ошибка регистрации:", e)
        return False

    finally:
        db.close()



def get_user(username):

    db=connect()

    user=db.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()

    db.close()

    return user



# ================================
# LOGS
# ================================

def update_last_login(user_id):

    save_log(user_id,"Вход")



def save_logout(user_id):

    save_log(user_id,"Выход")



def save_log(user_id,text):

    db=connect()

    db.execute("""
    INSERT INTO logs(user_id,action)
    VALUES(?,?)
    """,
    (user_id,text))

    db.commit()
    db.close()



# ================================
# SCANS
# ================================

def save_scan(user_id,url,domain,score,risk):

    db=connect()

    db.execute("""
    INSERT INTO scans
    (user_id,url,domain,score,risk)
    VALUES(?,?,?,?,?)
    """,
    (
        user_id,
        url,
        domain,
        score,
        risk
    ))

    db.commit()
    db.close()



def get_scans():

    db=connect()

    data=db.execute("""
    SELECT scans.*,users.username
    FROM scans
    LEFT JOIN users
    ON users.id=scans.user_id
    ORDER BY scans.id DESC
    """).fetchall()

    db.close()

    return data



# ================================
# USERS ADMIN
# ================================

def get_users():

    db=connect()

    data=db.execute("""
    SELECT * FROM users
    ORDER BY id DESC
    """).fetchall()

    db.close()

    return data

# ================================
# REVIEWS
# ================================

def save_review(user_id, username, rating, text):

    db = connect()

    try:

        db.execute("""
        INSERT INTO reviews
        (
            user_id,
            username,
            rating,
            text
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            username,
            rating,
            text
        ))

        db.commit()

    except Exception as e:
        db.rollback()
        print("Ошибка сохранения отзыва:", e)

    finally:
        db.close()



def get_reviews():

    db = connect()

    try:

        data = db.execute("""
            SELECT *
            FROM reviews
            ORDER BY id DESC
        """).fetchall()

        return data

    finally:

        db.close()



def get_average_rating():

    db = connect()

    try:

        data = db.execute("""
            SELECT 
                COUNT(*) AS count,
                AVG(rating) AS average
            FROM reviews
        """).fetchone()

        return data

    finally:

        db.close()

def get_user_profile(username):

    conn = connect()
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username=?
        """,
        (username,)
    )

    user = cursor.fetchone()

    conn.close()

    return user       

def get_user_scan_count(user_id):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id=?
        """,
        (user_id,)
    )

    count = cursor.fetchone()[0]

    conn.close()

    return count

def create_scans_table():

    import sqlite3

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        domain TEXT,
        score INTEGER,
        risk_level TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

    