from os import getenv
from dotenv import load_dotenv
load_dotenv()

class Config:
  # MongoDB setup
  MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
  MONGO_DB = 'drdb'
  # Collections to process by loader - {label: collection_name}
  COLLECTIONS = {
      #'cesnet_2307': 'cesnet_2307',
      'phishing_2311': 'misp_2311',
      #'benign_2307': 'benign_2307',
      #'phishing_2310': 'misp_2310',
      'benign_2310': 'benign_2310',
      #'cesnet2': 'cesnet2',
      #'malware_2311': 'malware_2311',
      #'cesnet2_2310': 'cesnet2_2310',
      #'benign_cesnet_intersect_2307': 'benign_cesnet_intersect_2307',
      #'benign_cesnet_union_2307': 'benign_cesnet_union_2307',
      #'dga_2310': 'dga_2310'
  }

