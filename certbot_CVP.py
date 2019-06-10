from jsonrpclib import Server
import ssl
import base64
from cvplibrary import CVPGlobalVariables, GlobalVariableNames

ssl._create_default_https_context = ssl._create_unverified_context

###Variables
cert_name = 'cert.cer'
key_name = 'cert.key'
ca_name = 'ca.cer'
intermediate_name = 'intermediate.cer' 

cert = '''-----BEGIN CERTIFICATE-----
Your Cert Goes Here.
-----END CERTIFICATE-----'''
cert_encoded = cert.encode('base64','strict')
cert_stripped = cert_encoded.replace('\n','')

key = '''-----BEGIN RSA PRIVATE KEY-----
Your Key Goes Here.
-----END RSA PRIVATE KEY-----'''
key_encoded = key.encode('base64','strict')
key_stripped = key_encoded.replace('\n','')

ca_cert = '''-----BEGIN CERTIFICATE-----
Your CA Certificate Goes Here.
-----END CERTIFICATE-----'''
ca_cert_encoded = ca_cert.encode('base64','strict')
ca_cert_stripped = ca_cert_encoded.replace('\n','')

intermediate = '''-----BEGIN CERTIFICATE-----
Your Intermediate Certificate Goes Here.
-----END CERTIFICATE-----'''
intermediate_encoded = intermediate.encode('base64','strict')
intermediate_stripped = intermediate_encoded.replace('\n','')

ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
user = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
passwd = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)

### Rest of script
def main():
  #SESSION SETUP FOR eAPI TO DEVICE
  url = "https://%s:%s@%s/command-api" % (user, passwd, ip)
  ss = Server(url)

  #Add Certs to /tmp/
  remove_certificate = ss.runCmds ( 1, [ 'enable', 'bash timeout 10 rm -rf /tmp/cert*'])
  upload_cert = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+cert_stripped+'" > /tmp/certcer.tmp', 'bash timeout 2 base64 -d /tmp/certcer.tmp > /tmp/cert.cer'])
  upload_key = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+key_stripped+'" > /tmp/certkey.tmp', 'bash timeout 2 base64 -d /tmp/certkey.tmp > /tmp/cert.key'])
  upload_intermediate = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+intermediate_stripped+'" > /tmp/cert.intermediate.tmp', 'bash timeout 2 base64 -d /tmp/cert.intermediate.tmp > /tmp/cert.intermediate'])
  upload_ca = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+ca_cert_stripped+'" > /tmp/cert.ca.tmp', 'bash timeout 2 base64 -d /tmp/cert.ca.tmp > /tmp/cert.ca'])
  #Move certs from /tmp to EOS.
  response = ss.runCmds( 1, [ 'enable', 'copy file:/tmp/cert.cer certificate:'+cert_name, 'copy file:/tmp/cert.key sslkey:'+key_name, 'copy file:/tmp/cert.intermediate certificate:'+intermediate_name, 'copy file:/tmp/cert.ca certificate:'+ca_name])
  #Remove certs from /tmp.
  remove_certificate = ss.runCmds ( 1, [ 'enable', 'bash timeout 10 rm -rf /tmp/cert*'])

if __name__ == "__main__":
  main()
