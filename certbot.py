#!/usr/bin/env python2
from getpass import getpass
from jsonrpclib import Server
import json
import ssl

#CREDS
user = raw_input("Enter username: ")
passwd = getpass()
ssl._create_default_https_context = ssl._create_unverified_context

### List of Arista devices ###
dev_list = ['192.168.255.5',
            '192.168.255.6',
            '192.168.255.7',
            '192.168.255.8']

### Certificate Info - expected to be PEM format.
# Replace with your own cert and key.
cert = """\
-----BEGIN CERTIFICATE-----
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
-----END CERTIFICATE-----"""
certparsed = cert.split('\n')

cert_key = """\
-----BEGIN RSA PRIVATE KEY-----
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
-----END RSA PRIVATE KEY-----"""
key_parsed = cert_key.split('\n')

def main():
  for SwitchNumber in dev_list:
    ip = SwitchNumber
    #SESSION SETUP FOR eAPI TO DEVICE
    url = "https://%s:%s@%s/command-api" % (user, passwd, ip)
    ss = Server(url)

    #CONNECT TO DEVICE
    try:
      remove_certificate = ss.runCmds ( 1, [ 'enable', 'bash timeout 10 rm -rf /tmp/cert.cer'])
      remove_key = ss.runCmds ( 1, [ 'enable', 'bash timeout 10 rm -rf /tmp/cert.key'])
      for line in certparsed:
        upload_cert = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+line+'" >> /tmp/cert.cer'])
      for line in key_parsed:
        upload_cert = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+line+'" >> /tmp/cert.key'])
      response = ss.runCmds( 1, [ 'enable', 'copy file:/tmp/cert.cer certificate:cert',
                                  'copy file:/tmp/cert.key sslkey:certkey'])
      response2 = ss.runCmds( 1, [ 'enable', 'configure', 'management security',
      'ssl profile https-secure', 'certificate cert key certkey', 'cipher-list HIGH:!NULL:!MD5:!aNULL' ])
      response3 = ss.runCmds( 1, [ 'enable', 'configure', 'management api http-commands',
      'protocol https ssl profile https-secure' ])
      print 'Success on '+ip
    except:
      print 'Failure on '+ip
      pass

if __name__ == "__main__":
  main()
