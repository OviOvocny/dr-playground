import pymongo
from tqdm import tqdm

# MongoDB connection details
mongo_uri = "mongodb://root:doktorkolektor@feta3.fit.vutbr.cz:27017/"
client = pymongo.MongoClient(mongo_uri)
db = client['drdb']

# Read domain names from the file
with open('finished_collections/misp2311_finished_list.txt', 'r') as file:
    domain_names = [line.strip() for line in file]

# Query and insert records into the new collection
misp_2310 = db['misp_2310']
misp_2311 = db['misp_2311']

# Initialize tqdm with total count equal to the number of domain names
total_domains = len(domain_names)
with tqdm(total=total_domains, desc='Processing') as pbar:
    for domain_name in domain_names:
        records = misp_2310.find({'domain_field': domain_name})  # Adjust 'domain_field' to the actual field name in your documents
        for record in records:
            misp_2311.insert_one(record)
        pbar.update(1)  # Update progress bar after processing each domain name
