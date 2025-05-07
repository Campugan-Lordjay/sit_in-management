import sqlite3
import os

def update_database():
    try:
        # Connect to the database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Check if the instructor column exists
        cursor.execute("PRAGMA table_info(lab_schedules)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'instructor' not in columns:
            print("Adding instructor column to lab_schedules table...")
            # Add instructor column
            cursor.execute('''
                ALTER TABLE lab_schedules 
                ADD COLUMN instructor VARCHAR(100) NOT NULL DEFAULT 'TBA'
            ''')
            
            # Update existing records with a default value
            cursor.execute('''
                UPDATE lab_schedules 
                SET instructor = 'TBA' 
                WHERE instructor IS NULL
            ''')
            
            print("Instructor column added successfully!")
        else:
            print("Instructor column already exists.")

        # Commit changes and close connection
        conn.commit()
        conn.close()
        print("Database update completed successfully!")

    except Exception as e:
        print(f"Error updating database: {str(e)}")
        if conn:
            conn.close()

if __name__ == "__main__":
    update_database() 