import pandas as pd
from pymongo import MongoClient

# ====== CONFIG ======
CSV_FILE = "upload.csv"  # your CSV file name
MONGO_URI = "mongodb+srv://vangalagiricharanreddy7_db_user:2ohRy0KsFwSNKoX9@urldata.rwjokkb.mongodb.net/?appName=urldata"
DB_NAME = "phishing_detection"
COLLECTION_NAME = "training_data"
# ====================

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# Read CSV
df = pd.read_csv(CSV_FILE)

# Convert dataframe to dictionary list
data = df.to_dict(orient="records")

# Insert data into MongoDB
if data:
    collection.insert_many(data)
    print(f"✅ Inserted {len(data)} records into MongoDB collection '{COLLECTION_NAME}' in '{DB_NAME}' database.")
else:
    print("⚠️ CSV file is empty. Nothing inserted.")
