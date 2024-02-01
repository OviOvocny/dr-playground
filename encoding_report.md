# Categorical features to encode

One-hot encoding (?) 

### lex_

``tld_hash`` - očíslujeme si známé TLD, řešení neznámých

### dns_

nufing

### ip_

nufing

### rdap_

``registrar_name_hash`` - očíslujeme si známé registrátory, řešení neznámých

### tls_

``root_authority_hash`` - očíslujeme si známé root autority + uknown autority \
``leaf_authority_hash`` - očíslujeme si známé leaf autority + uknown autority

### geo_

``countries_hash`` - one-hot encoding \
``continent_hash`` - one-hot encoding (only 20 unique values)