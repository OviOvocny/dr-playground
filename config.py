from os import getenv
from dotenv import load_dotenv
load_dotenv()

class Config:
  # MongoDB setup
  MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
  MONGO_DB = 'drdb'
  # Collections to process by loader - {label: collection_name}
  COLLECTIONS = {
      'benign': 'benign_2307',
      'malign': 'misp_2307',
      'cesnet': 'cesnet_2307'
  }
