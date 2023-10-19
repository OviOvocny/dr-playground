import sys

import dr_collector.resolvers as resolver
import loader.transformers
from loader.transformers import drop_nontrain
import loader.schema
import pyarrow as pa


def resolve(domain: str):
    return resolver.resolve_single(domain)


def extract(domain: str, drop_unused: bool = False):
    resolved = resolver.resolve_single(domain)
    resolved = _project(resolved)
    resolved = {x: [y] for x, y in resolved.items()}

    pyma_schema = loader.schema.schema
    pa_schema = pa.schema([(f, pyma_schema.typemap[f]) for f in pyma_schema])
    table = pa.Table.from_pydict(resolved, schema=pa_schema)
    df = table.to_pandas()

    transformations = loader.transformers.get_transformations()
    for name, (save, func) in transformations.items():
        print(f'Running transformation {name}', file=sys.stderr)
        df = func(df)

    if drop_unused:
        df = drop_nontrain.drop_nontrain_df(df)

    return df.iloc[0].to_dict()


def _project(domain: dict):
    return {
        "domain_name": domain["domain_name"],
        "label": domain["label"],
        "category": domain["category"],
        #
        "dns_dnssec": domain["dns"]["dnssec"],
        "dns_email_extras": {
            "spf": domain["dns"]["dnssec"]["has_spf"] if "has_spf" in domain["dns"]["dnssec"] else False,
            "dkim": domain["dns"]["dnssec"]["has_dkim"] if "has_dkim" in domain["dns"]["dnssec"] else False,
            "dmarc": domain["dns"]["dnssec"]["has_dmarc"] if "has_dmarc" in domain["dns"]["dnssec"] else False,
        },
        "dns_ttls": domain["dns"]["ttls"],
        "dns_zone": domain["dns"]["remarks"]["zone"],
        "dns_has_dnskey": domain["dns"]["remarks"]["has_dnskey"],
        "dns_zone_dnskey_selfsign_ok": domain["dns"]["remarks"]["zone_dnskey_selfsign_ok"],
        **{f"dns_{dns_type}": domain["dns"][dns_type] if
        dns_type in domain["dns"] else None for dns_type in ['A', 'AAAA', 'SOA', 'zone_SOA', 'MX', 'TXT']},
        "dns_CNAME": domain["dns"]["CNAME"]["value"] if "CNAME" in domain["dns"] else None,
        "dns_NS": list(domain["dns"]["NS"].keys()) if "NS" in domain["dns"] else None,
        "dns_MX": [{"name": x, "priority": y["priority"]} for x, y in domain["dns"]["MX"].items()] if "MX" in domain[
            "dns"] else None,
        #
        "tls": domain["tls"],
        "dns_evaluated_on": domain["remarks"]["dns_evaluated_on"],
        "rdap_evaluated_on": domain["remarks"]["rdap_evaluated_on"],
        "tls_evaluated_on": domain["remarks"]["tls_evaluated_on"],
        #
        "rdap_registration_date": domain["rdap"]["registration_date"],
        "rdap_expiration_date": domain["rdap"]["expiration_date"],
        "rdap_last_changed_date": domain["rdap"]["last_changed_date"],
        "rdap_dnssec": domain["rdap"]["dnssec"] if "dnssec" in domain["rdap"] else None,
        "rdap_entities": domain["rdap"]["entities"],
        #
        "ip_data": [{
            "geo": {
                "country": ip["geo"]["country"],
                "latitude": ip["geo"]["latitude"],
                "longitude": ip["geo"]["longitude"],
            },
            "asn": ip["asn"],
            "remarks": {
                "average_rtt": ip["remarks"]["average_rtt"]
            },
            "from_record": ip["from_record"],
            "ip": ip["ip"],
            "rdap": ip["rdap"]
        } for ip in domain["ip_data"]]
    }
