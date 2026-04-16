import sqlite3
import os

def init():
    # Connect to the database file
    conn = sqlite3.connect('stadium.db')
    cursor = conn.cursor()
    
    # 1. Clean up old tables
    cursor.execute('DROP TABLE IF EXISTS players')
    cursor.execute('DROP TABLE IF EXISTS secret_scout_notes')
    
    # 2. Create the Public Players Table (ID 1-11)
    cursor.execute('''
        CREATE TABLE players (
            id INTEGER PRIMARY KEY, 
            name TEXT, 
            position TEXT
        )
    ''')
    
    # Moroccan National Team - Starting XI
    players = [
        (1, 'Yassine Bounou', 'Goalkeeper'),
        (2, 'Achraf Hakimi', 'Defender'),
        (3, 'Noussair Mazraoui', 'Defender'),
        (4, 'Sofyan Amrabat', 'Midfielder'),
        (5, 'Nayef Aguerd', 'Defender'),
        (6, 'Romain Saïss', 'Defender'),
        (7, 'Hakim Ziyech', 'Forward'),
        (8, 'Azzedine Ounahi', 'Midfielder'),
        (9, 'Youssef En-Nesyri', 'Forward'),
        (10, 'Brahim Diaz', 'Forward'),
        (11, 'Sofiane Boufal', 'Forward')
    ]
    
    cursor.executemany('INSERT INTO players VALUES (?,?,?)', players)
    
    # 3. Create the Secret Table for the Flag
    cursor.execute('CREATE TABLE secret_scout_notes (flag TEXT)')
    flag = os.environ.get('FLAG', 'INFODAYS{SQLI_CH4R_N0_5P4C3_2026}')
    cursor.execute("INSERT INTO secret_scout_notes VALUES (?)", (flag,))
    
    conn.commit()
    conn.close()
    print("✅ Database initialized! 11 players added with IDs 1-11.")

if __name__ == "__main__":
    init()
