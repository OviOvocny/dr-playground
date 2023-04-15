# This is a mongo aggregation pipeline that selects the 
# fields we want to keep for transformation.
# We use two stages:
# 1. $match to filter out documents of domains that haven't been resoloved yet
# 2. $project to select the fields we want to use
#
# If you're authoring a new transformer, you'll need to add the
# fields you want to use to this pipeline.
# At the most basic level, use a 1 to select the field. 
# Fields not specified in the projection will be excluded.
# More complex projections can be done, but try to avoid them.
# We can do complex stuff in the transformers.
#
# See the mongo docs for more info on accessing nested fields:
# https://docs.mongodb.com/manual/tutorial/project-fields-from-query-results/
#
# IMPORTANT
# After adding a new field, you'll need to add it to the schema
# in schema.py - see that file for more information.

pipeline = [
    {"$match": { "evaluated_on": {"$ne": None} }},
    {"$project": {
        "_id": 0,
        "domain_name": 1,
        "label": 1,
        "category": 1,
        #
        "dns": 1,
        #
        "tls": 1,
        "remarks.tls_evaluated_on": 1,
        #
        "rdap.registration_date": 1,
        "rdap.expiration_date": 1,
        "rdap.last_changed_date": 1,
        #"rdap.entities.registrar.handle": 1,
        #
        "ip_data.geo.country": 1,
        "ip_data.geo.latitude": 1,
        "ip_data.geo.longitude": 1,
        "ip_data.geo.asn": 1,
    }},
]