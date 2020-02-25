#!/usr/bin/env python

# Author: Brandon Rossi
# 2/24/2020

# Domains are spoofable if any of the following conditions are met:
#	Lack of SPF Record
# 	Lack of DMARC Record
#	SPF Record does not specify ~all or -all
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
	spfRecord = getSPF(resolver, domain).strip('"')
	spoofable = False
	if spfRecord:
		print("[X] SPF record found: ")
		print(spfRecord)
		if "~all" not in spfRecord and "-all" not in spfRecord:
			print("[+] " + domain + " does not contain \"-all\" or \"~all\" in the SPF record.")
			spoofable = True
	else:
		print("[+] SPF record not found for " + domain)
		spoofable = True
	dmarcRecord = getDMARC(resolver, domain).strip('"')
	dmarcTagRegex = r";\s*p=([^;]*)\s*;"
	dmarcTagMatch = re.search(dmarcTagRegex, dmarcRecord)
	dmarcTag = None 
	if dmarcTagMatch:
		dmarcTag = dmarcTagMatch.group(1)
	if dmarcRecord:
		print("[X] DMARC record found: ")
		print(dmarcRecord)
		if not dmarcTagMatch:
			print("[+] " + domain + " does not have a policy set in the DMARC record.")
			spoofable = True
		elif dmarcTag == "none":
			print("[+] " + domain + " has policy set to \"none\" in the DMARC record.")
			spoofable = True
	else:
		print("[+] DMARC record not found for " + domain)
		spoofable = True
	if spoofable:
		print(domain + " is spoofable.")
	else:
		print(domain + " is NOT spoofable.")

if __name__== "__main__":
	main()
	
