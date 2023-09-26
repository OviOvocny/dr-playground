from pymongoarrow.api import Schema
from pyarrow import list_, string, int64, float64, bool_, struct, timestamp

# Welcome to the schema file. This is where you define the schema of
# the data you're loading from MongoDB. This is needed because the
# mongo arrow loader can't reliably infer the schema from the data.
#
# As you can see, this is a bit of a weird one. Luckily, the schema
# is basically the same as the projection, just with types added.
#
# Not so luckily, the schema is a bit of a pain to write. Arrow has
# its own idea of how to define a schema, and only its mother could
# love it. So, we have to convert the projection into a schema.
#
# You can define the schema as a dict, but as soon as you have a
# list of things, you have to use the arrow types. The Arrow list
# accepts Arrow types, so you can't just use a list of dicts. You
# have to use the arrow struct type. The arrow struct type accepts
# a list of tuples, where the first element is the field name and
# the second element is the field type.
#
# You'll get the gist of it from the existing schema and projection.
# Try cross-referencing the projection and schema to see how they
# match up. If you need help, consult the arrow docs:
# https://arrow.apache.org/docs/python/api.html
#
# Also keep in mind that the mongo arrow loader can't handle all
# arrow types. See the docs for more info:
# https://mongo-arrow.readthedocs.io/en/latest/supported_types.html

rdap_entity = struct([
    ("handle", string()),
    ("type", string()),
    ("name", string()),
    ("email", string())
])

tls_data = struct([
    ("protocol", string()),
    ("cipher", string()),
    ("count", int64()),
    ("certificates", list_(struct([
        ("common_name", string()),
        ("country", string()),
        ("is_root", bool_()),
        ("organization", string()),
        ("valid_len", int64()),
        ("validity_start", timestamp('ms')),
        ("validity_end", timestamp('ms')),
        ("extension_count", int64()),
        ("extensions", list_(struct([
            ("critical", int64()),
            ("name", string()),
            ("value", string()),
        ]))),
    ]))),
])

ip_rdap_data = struct([
    ("handle", string()),
    ("parent_handle", string()),
    ("type", string()),
    ("last_changed_date", timestamp("ms")),
    ("registration_date", timestamp("ms")),
    ("expiration_date", timestamp("ms")),
    ("rir", string()),
    ("entities", struct([
        ("registrant", list_(rdap_entity)),
        ("registrar", list_(rdap_entity)),
        ("abuse", list_(rdap_entity)),
        ("technical", list_(rdap_entity)),
        ("noc", list_(rdap_entity)),
        ("administrative", list_(rdap_entity))
    ])),
    ("country", string()),
    ("ip_version", int64()),
    ("assignment_type", string()),
    ("network", struct([
        ("prefix_length", int64()),
        ("network_address", string())
    ]))
])

ip_data = struct([
    ("geo", struct([
        ("country", string()),
        ("latitude", float64()),
        ("longitude", float64()),
    ])),
    ("remarks", struct([
        ("average_rtt", float64()),
    ])),
    ("asn", struct([
        ("asn", int64()),
        ("as_org", string()),
        ("network_address", string()),
        ("prefix_len", int64())
    ])),
    ("from_record", string()),
    ("ip", string()),
    ("rdap", ip_rdap_data)
])

dns_types_all = ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT')

dns_types_ints = {
    **{dns_type: int64() for dns_type in dns_types_all}
}

dns_soa = struct([
    ("primary_ns", string()),
    ("resp_mailbox_dname", string()),
    # TODO: Does it make sense to represent the serial number as a number?
    ("serial", int64()),
    ("refresh", int64()),
    ("retry", int64()),
    ("expire", int64()),
    ("min_ttl", int64())
])

schema = Schema({
    "domain_name": string(),
    "label": string(),
    "category": string(),
    #
    "dns_evaluated_on": timestamp('ms'),
    "rdap_evaluated_on": timestamp('ms'),
    "tls_evaluated_on": timestamp('ms'),
    #
    "dns_dnssec": dns_types_ints,
    "dns_email_extras": struct([
        ("spf", bool_()),
        ("dkim", bool_()),
        ("dmarc", bool_()),
    ]),
    "dns_ttls": dns_types_ints,
    "dns_zone": string(),
    "dns_has_dnskey": bool_(),
    **{f"dns_{dns_type}": list_(string()) for dns_type in ('A', 'AAAA', 'NS', 'TXT')},
    "dns_CNAME": string(),
    "dns_SOA": dns_soa,
    "dns_zone_SOA": dns_soa,
    "dns_MX": list_(struct([
        ("name", string()),
        ("priority", int64())
    ])),
    "rdap_registration_date": timestamp('ms'),
    "rdap_expiration_date": timestamp('ms'),
    "rdap_last_changed_date": timestamp('ms'),
    "rdap_dnssec": bool_(),
    "rdap_entities": struct([
        ("administrative", list_(rdap_entity)),
        ("registrant", list_(rdap_entity)),
        ("registrar", list_(rdap_entity)),
        ("abuse", list_(rdap_entity)),
        ("technical", list_(rdap_entity))
    ]),
    "tls": tls_data,
    "ip_data": list_(ip_data),
})
