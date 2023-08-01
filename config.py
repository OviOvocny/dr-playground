from os import getenv
from dotenv import load_dotenv
load_dotenv()

class Config:
  # MongoDB setup
  MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
  MONGO_DB = 'drdb'
  # Collections to process by loader - {label: collection_name}
  COLLECTIONS = {
    'benign_cesnet_intersect_2307': 'benign_cesnet_intersect_2307'
      # 'benign': 'benign',
      # 'malign': 'malign',
  }