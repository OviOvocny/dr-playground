from os import getenv
from dotenv import load_dotenv

load_dotenv()


class Config:
    # MongoDB setup
    MONGO_URI = getenv("DR_MONGO_URI", "mongodb://root:doktorkolektor@feta3.fit.vutbr.cz:27017/")
    MONGO_DB = "drdb"
    # Collections to process by loader - {label: collection_name}
    COLLECTIONS = {
        # "phishing_2307": "misp_2307",
        "benign_cesnet_union_2307": "benign_cesnet_union_2307",
        # "misp_2310": "misp_2310",
    }
