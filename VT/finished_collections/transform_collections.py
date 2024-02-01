import pymongo
from tqdm import tqdm

# MongoDB connection details
mongo_uri = "***REMOVED***"
client = pymongo.MongoClient(mongo_uri)
db = client['drdb']

# Collections
benign_2310 = db['benign_2310']
benign_2312 = db['benign_2312']
benign_2401 = db['benign_2401']

# Check if benign_2401 already exists
if 'benign_2401' in db.list_collection_names():
    print("Collection 'benign_2401' already exists. Aborting to prevent overwriting.")
else:
    # Insert all documents from benign_2312 into benign_2401
    for record in benign_2312.find():
        benign_2401.insert_one(record)

    # Insert unique documents from benign_2310 into benign_2401
    for record in benign_2310.find():
        domain_name = record.get('domain_field')  # Replace 'domain_field' with the actual field name
        if not benign_2401.find_one({'domain_field': domain_name}):
            benign_2401.insert_one(record)

    print("Collection 'benign_2401' has been created with unique documents.")
