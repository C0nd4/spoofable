#!/usr/bin/env python3

# Author: Brandon Rossi
# 2/24/2020

# Domains are spoofable if any of the following conditions are met:
#	Lack of SPF Record
# 	Lack of DMARC Record
#	SPF Record does not specify ~all
#	SPF Record does not specify -all
#	DMARC policy is set to p=none
# 	DMARC policy is nonexistant

import dns.resolver
import re
import sys

def getSPF(resolver, domain):
	spfRegex = re.compile("^\"(v=spf1).*\"$")
	try:
		answer = resolver.query(domain, 'txt')
		for item in answer.response.answer:
			for line in item.items:
				if spfRegex.match(line.to_text()):
					return str(line)
	except dns.resolver.NoAnswer:
		print("No SPF record found for " + domain)
		return False

def getDMARC(resolver, domain):
	spfRegex = re.compile("^\"(v=DMARC).*\"$")
	try:
		answer = resolver.query("_dmarc." + domain, 'txt')
		for item in answer.response.answer:
			for line in item.items:
				if spfRegex.match(line.to_text()):
					return str(line)
	except dns.resolver.NoAnswer:
		print("No DMARC record found for " + domain)
		return False

def main():
	domain = sys.argv[1]
	resolver = dns.resolver.Resolver()
	spfRecord = getSPF(resolver, domain)
	if spfRecord:
		if "~all" not in spfRecord and "-all" not in spfRecord:
			print(domain + " is spoofable, it does not contain \"-all\" or \"~all\" in the SPF record.")
			exit(0)
	else:
		print(domain + " is spoofable, it does not have an SPF record.")
		exit(0)
	dmarcRecord = getDMARC(resolver, domain)
	dmarcTagRegex = r";\s*p=(.[^;]*)\s*;"
	dmarcTagMatch = re.search(dmarcTagRegex, dmarcRecord)
	dmarcTag = dmarcTagMatch.group(1)
	if dmarcRecord:
		if not dmarcTagMatch:
			print(domain + " is spoofable, it does not have a policy set in the DMARC record.")
			exit(0)
		elif dmarcTag == "none":
			print(domain + " is spoofable, it has policy set to \"none\" in the DMARC record.")
			exit(0)
	else:
		print(domain + " is spoofable, it does not have a DMARC record.")
		exit(0)
	print(domain + " is not spoofable.")

if __name__== "__main__":
	main()
	