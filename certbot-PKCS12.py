#!/usr/bin/env python2
from getpass import getpass
from jsonrpclib import Server
import json
from OpenSSL import crypto
import ssl
import base64

## Path to SSL Certificate in PKCS12 Format

certlocation = 'cert.p12'
certpass = 'Arista'

#CREDS
user = raw_input("Enter username: ")
passwd = getpass()
ssl._create_default_https_context = ssl._create_unverified_context

### List of Arista devices ###
dev_list = ['192.168.255.5',
            '192.168.255.6',
            '192.168.255.7',
            '192.168.255.8']


p12 = crypto.load_pkcs12(open(certlocation, 'rb').read(), certpass)

cert = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
cert_encoded = cert.encode('base64','strict')
cert_stripped = cert_encoded.replace('\n','')

cert_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
key_encoded = cert_key.encode('base64','strict')
key_stripped = key_encoded.replace('\n','')

def main():
  for SwitchNumber in dev_list:
    ip = SwitchNumber
    #SESSION SETUP FOR eAPI TO DEVICE
    url = "https://%s:%s@%s/command-api" % (user, passwd, ip)
    ss = Server(url)

    #CONNECT TO DEVICE
    try:
      remove_certificate = ss.runCmds ( 1, [ 'enable', 'bash timeout 10 rm -rf /tmp/cert*'])
      upload_cert = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+cert_stripped+'" > /tmp/certcer.tmp', 'bash timeout 2 base64 -d /tmp/certcer.tmp > /tmp/cert.cer'])
      upload_key = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+key_stripped+'" > /tmp/certkey.tmp', 'bash timeout 2 base64 -d /tmp/certkey.tmp > /tmp/cert.key'])
      response = ss.runCmds( 1, [ 'enable', 'copy file:/tmp/cert.cer certificate:cert',
                                  'copy file:/tmp/cert.key sslkey:certkey'])
      response2 = ss.runCmds( 1, [ 'enable', 'configure', 'management security',
      'ssl profile https-secure', 'certificate cert key certkey', 'cipher-list HIGH:!NULL:!MD5:!aNULL' ])
      response3 = ss.runCmds( 1, [ 'enable', 'configure', 'management api http-commands',
      'protocol https ssl profile https-secure' ])
      remove_certificate = ss.runCmds ( 1, [ 'enable', 'bash timeout 10 rm -rf /tmp/cert*'])
      print 'Success on '+ip
    except:
      print 'Failure on '+ip
      pass

if __name__ == "__main__":
  main()
