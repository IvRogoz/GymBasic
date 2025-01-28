import sqlite3
import json

# Connect to the database
conn = sqlite3.connect("app.db")
cursor = conn.cursor()

# Run the SQL query
cursor.execute("SELECT barcode, product_name, nutritional_values FROM scanned_data")
results = cursor.fetchall()

# Print all results
if results:
    print("\n✅ Found in Database:\n")
    for row in results:
        barcode, product_name, nutritional_values = row

        # Try parsing the nutritional values (if stored as JSON)
        try:
            nutrition = json.loads(nutritional_values) if nutritional_values else {}
        except json.JSONDecodeError:
            nutrition = {}

        print(f"🔹 Barcode: {barcode}")
        print(f"   Product Name: {product_name}")
        print(f"   Nutritional Values: {json.dumps(nutrition, indent=4)}\n")
else:
    print("\n❌ No data found in the database.\n")

# Close the connection
conn.close()
