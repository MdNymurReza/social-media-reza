import sqlite3

def create_tables():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    # Create the 'users' table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unique_id TEXT NOT NULL,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            university TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            profile_picture TEXT,
            bio TEXT,
            facebook_link TEXT,
            twitter_link TEXT,
            linkedin_link TEXT,
            is_verified INTEGER DEFAULT 1
        )
    ''')

    # Create the 'ids' table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unique_id TEXT NOT NULL UNIQUE,
            is_registered INTEGER DEFAULT 0
        )
    ''')

    # Create the 'friends' table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (friend_id) REFERENCES users (id)
        )
    ''')

    # Create the 'friend_requests' table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_tables()

print("Database Created")