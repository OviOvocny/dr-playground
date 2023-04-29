# transform functions for dataframes
# [DF with projected fields] -> transformer 1 -> transformer 2 -> ... -> [DF for training]
# executed in order of appearance in this file

# transform functions must take a pandas DataFrame as input and return a DataFrame as output
# IMPORTANT! import them here as transform_<name> so they can be called automatically in loader.py
#                             ===================

# to save an intermedieate dataframe after a transform, append _save to the imported name

# combine label and category into a single field
from .label import label as transform_label
# flatten nested fields + SAVE
from .flatten import flatten as transform_flatten_save
# analyze TLS certificates
from .tls import tls as transform_tls
# calculate length of domain name
from .lexical import lex as transform_lexical
# calculate entropy from inner octets of IP addresses
from .ip_entropy import ip_entropy as transform_ip_entropy
# count number of unique countries
from .count import countries_count as transform_countries_count
# calculate standard deviation of latitudes and longitudes
from .geo import coord_stddev as transform_coords_stddev
# count number of DNS records of each type
from .count import dns_count as transform_dns_count
# get mean of average RTT
from .lists import rtt_mean as transform_rtt_mean

# transform RDAP
from .rdap import rdap as transform_rdap

# transform DNS
from .dns import dns as transform_dns