# Spoofable
This is a tool used to check if a domain is spoofable via email.

Domains are considered spoofable if any of the following conditions are met:
+ Lack of SPF Record
+ Lack of DMARC Record
+ SPF Record does not specify ~all or -all
+ DMARC policy is set to p=none
+ DMARC policy is nonexistant

# Usage

Install the requirements with `$ pip install requirements.txt`

Run with `$ python3 spoofable.py [domain]`
