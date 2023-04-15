from .helpers import size_, map_with_guard_, filter_none_

match = {
    # only take domains that have been evaluated
    "evaluated_on": {"$ne": None},
}


project = {
    "_id": 0,
    "domain_name": 1,
    ## label fields
    "label": {"$concat": ["$category", ":", "$label"]},
    ## projected fields:
    # lex
    "name_length": {"$strLenCP": "$domain_name"},
    # rdap
    "domain_registration_date": "$rdap.registration_date",
    "domain_expiration_date": "$rdap.expiration_date",
    "domain_last_changed_date": "$rdap.last_changed_date",
    "registrar_handle": {"$arrayElemAt": ["$rdap.entities.registrar.handle", 0]},
    # tls
    "tls": 1,
    # ip data
    "countries": {
        "$setUnion": map_with_guard_("$ip_data", "geo.country", guarded_field="geo")
    },
    "latitudes": map_with_guard_("$ip_data", "geo.latitude", guarded_field="geo"),
    "longitudes": map_with_guard_("$ip_data", "geo.longitude", guarded_field="geo"),
}

# dns
dns_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
for dns_type in dns_types:
    project[f"dns_{dns_type}"] = f"$dns.{dns_type}"


add_fields = {
    "countries_count": size_("$countries"),
    "lat_stddev": {"$stdDevSamp": filter_none_("$latitudes")},
    "lon_stddev": {"$stdDevSamp": filter_none_("$longitudes")},
}

# dns record counts
for dns_type in dns_types:
    add_fields[f"dns_{dns_type}_count"] = size_(f"$dns_{dns_type}")


# these are not used for training, just for preprocessing
nontraining_fields = [
    "domain_name",
    "tls",
    "countries",
    "latitudes",
    "longitudes",
    *[f"dns_{t}" for t in dns_types],
]


pipeline = [
    {"$match": match},
    {"$project": project},
    {"$addFields": add_fields},
    #{"$unset": nontraining_fields},
]
