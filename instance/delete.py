import sqlite3

# Connect to the database
conn = sqlite3.connect("app.db")
cursor = conn.cursor()

# Delete all records
cursor.execute("DELETE FROM scanned_data")
conn.commit()

# Confirm deletion
cursor.execute("SELECT COUNT(*) FROM scanned_data")
count = cursor.fetchone()[0]

if count == 0:
    print("\n✅ All entries deleted successfully!\n")
else:
    print(f"\n❌ Deletion failed. {count} entries still exist.\n")

# Close connection
conn.close()
