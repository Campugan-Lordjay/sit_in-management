import sqlite3
import os

# Database file name
DATABASE = 'users.db'

def init_db():
    """Initialize the SQLite database and create the lab_schedules table if it doesn't exist."""
    # Check if database file exists
    db_exists = os.path.exists(DATABASE)
    
    # Connect to database (this will create the file if it doesn't exist)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Drop the existing table if it exists
    cursor.execute('DROP TABLE IF EXISTS lab_schedules')

    # Create the lab_schedules table with all VARCHAR fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lab_schedules (
            id VARCHAR(20) PRIMARY KEY,
            edp_code VARCHAR(20) NOT NULL,
            course VARCHAR(100) NOT NULL,
            time VARCHAR(50) NOT NULL,
            days VARCHAR(20) NOT NULL,
            room VARCHAR(20) NOT NULL,
            created_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Insert sample data
    sample_schedules = [
        ('1', 'EDP001', 'Computer Science 101', '8:00 AM - 9:30 AM', 'MWF', 'Lab 1'),
        ('2', 'EDP002', 'Information Technology 101', '10:00 AM - 11:30 AM', 'TTh', 'Lab 2'),
        ('3', 'EDP003', 'Computer Engineering 101', '1:00 PM - 2:30 PM', 'MWF', 'Lab 3'),
        ('4', 'EDP004', 'Information Systems 101', '3:00 PM - 4:30 PM', 'TTh', 'Lab 1'),
        ('5', 'EDP005', 'Computer Science 102', '5:00 PM - 6:30 PM', 'MWF', 'Lab 2')
    ]
    
    cursor.executemany('''
        INSERT INTO lab_schedules (id, edp_code, course, time, days, room)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', sample_schedules)

    # Commit changes and close connection
    conn.commit()
    conn.close()

    print("Database initialized successfully!")
    print("Lab schedules table created with VARCHAR fields and sample data.")

if __name__ == '__main__':
    init_db() 