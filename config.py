from os import getenv
from dotenv import load_dotenv

load_dotenv()


class Config:
    # MongoDB setup
    MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = 'drdb'
    # Collections to process by loader - {label: collection_name}
    COLLECTIONS = {
        # 'cesnet': 'cesnet_2307',
        # 'cesnet2': 'cesnet2',
        # 'benign': 'benign_2307',
        'phishing': 'misp_2307',
        # 'benign_cesnet_intersect': 'benign_cesnet_intersect_2307'
        # 'benign_cesnet_union': 'benign_cesnet_union_2307',
        # 'benign_cesnet2_intersect': 'benign_cesnet2_intersect',
        'malware': 'malware'
    }
