#!/usr/bin/python

import sys
import os
import boto3
import requests
import getpass
import ConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse

##########################################################################
# Variables
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'settings.ini'))

# The default AWS region to be used
region = Config.get('Settings', 'region')

# The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = Config.get('Settings', 'outputformat')

# The file where this script will store the STS credentials
awsconfigfile = Config.get('Settings', 'awsconfigfile')

# The initial url that starts the authentication process
idpentryurl = Config.get('Settings', 'URL')

# If only using locally/for yourself, you can hardcode your login email
if Config.has_option('Settings', 'Email'):
    email = Config.get('Settings', 'Email')
else:
    email = None

# False should only be used for dev/test
sslverification = True

# Uncomment to enable low level debugging
#logging.basicConfig(level=logging.DEBUG)
##########################################################################

# Get the credentials from the user
if not email:
    print "Email: ",
    email = raw_input()
else:
    print "Using: %s" % email
password = getpass.getpass()
print "MFA Pin: ",
mfapin = raw_input()
print ''

# Initiate session handler
session = requests.Session()
# Configure Session Headers
session.headers['User-Agent'] = 'AWS Sign-In'
# Initial Page load
google_session = session.get(idpentryurl)
google_session.raise_for_status()
session.headers['Referrer'] = google_session.url

# Collect information from the page source
decoded = BeautifulSoup(google_session.text, 'html.parser')
galx = decoded.find('input', {'name': 'GALX'}).get('value')
gxf = decoded.find('input', {'name': 'gxf'}).get('value')
cont = decoded.find('input', {'name': 'continue'}).get('value')
page = decoded.find('input', {'name': 'Page'}).get('value')
sign_in = decoded.find('input', {'name': 'signIn'}).get('value')
account_login_url = decoded.find('form', {'id': 'gaia_loginform'}).get('action')

# Setup the payload
payload = {
    'Page': page,
    'GALX': galx,
    'gxf': gxf,
    'continue': cont,
    'ltmpl': 'popup',
    'scc': 1,
    'sarp': 1,
    'oauth': 1,
    'ProfileInformation': '',
    'SessionState': '',
    '_utf8': '?',
    'bgresponse': 'js_disabled',
    'pstMsg': 0,
    'checkConnection': '',
    'checkedDomains': 'youtube',
    'Email': email,
    'identifiertoken': '',
    'identifiertoken_audio': '',
    'identifier-captcha-input': '',
    'signIn': sign_in,
    'Passwd': '',
    'PersistentCookie': 'yes',
}

# POST to account login info page, to collect profile and session info
google_session = session.post(account_login_url, data=payload)
google_session.raise_for_status()
session.headers['Referrer'] = google_session.url

# Collect ProfileInformation, SessionState, signIn, and Password Challenge URL
decoded = BeautifulSoup(google_session.text, 'html.parser')
profile_information = decoded.find('input', {'name': 'ProfileInformation'}).get('value')
session_state = decoded.find('input', {'name': 'SessionState'}).get('value')
sign_in = decoded.find('input', {'name': 'signIn'}).get('value')
passwd_challenge_url = decoded.find('form', {'id': 'gaia_loginform'}).get('action')

# Update the payload
payload['SessionState'] = session_state
payload['ProfileInformation'] = profile_information
payload['signIn'] = sign_in
payload['Passwd'] = password

# POST to Authenticate Password
google_session = session.post(passwd_challenge_url, data=payload)
google_session.raise_for_status()
session.headers['Referrer'] = google_session.url

# Collect the TL, and Updated gxf
decoded = BeautifulSoup(google_session.text, 'html.parser')
tl = decoded.find('input', {'name': 'TL'}).get('value')
gxf = decoded.find('input', {'name': 'gxf'}).get('value')

# Dynamically configure TOTP URL and ID based upon the session url
challenge_url = google_session.url.split("?")[0]
challenge_id = challenge_url.split("totp/")[1]

# Create a new payload
payload = {
    'challengeId': challenge_id,
    'challengeType': 6,
    'continue': cont,
    'scc': 1,
    'sarp': 1,
    'checkedDomains': 'youtube',
    'pstMsg': 0,
    'TL': tl,
    'gxf': gxf,
    'Pin': mfapin,
    'TrustDevice': 'on',
}

# Submit TOTP
google_session = session.post(challenge_url, data=payload)
google_session.raise_for_status()

response = session.get(idpentryurl)
# Debug the response if needed
#print (response.text)

parsed = BeautifulSoup(response.text, 'html.parser')
saml_element = parsed.find('input', {'name':'SAMLResponse'})

if not saml_element:
    raise StandardError, 'Could not get a SAML reponse, check credentials.'

saml = saml_element['value']

# Overwrite and delete the credential variables, just for safety
username = '#################################################'
password = '#################################################'
mfapin   = '#################################################'
del username
del password
del mfapin

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(saml))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn, but
# lots of blogs list it as principal_arn,role_arn so let's reverse if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If there's more than one role, ask the user to pick one; otherwise proceed
if len(awsroles) > 1:
    i = 0
    print "Please choose the role you would like to assume:"
    for awsrole in awsroles:
        print ' [', i, ']: ', awsrole.split(',')[0]
        i += 1
    print "Selection: ",
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print 'You selected an invalid role index, please try again'
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
stsclient = boto3.client('sts')
token = stsclient.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=saml)
creds = token['Credentials']
aws_key = creds['AccessKeyId']
aws_sec = creds['SecretAccessKey']
aws_tok = creds['SessionToken']
aws_exp = creds['Expiration']

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = ConfigParser.RawConfigParser()
config.read(filename)

# Put the creds into a saml-specific profile instead of clobbering other creds
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', aws_key)
config.set('saml', 'aws_secret_access_key', aws_sec)
config.set('saml', 'aws_session_token', aws_tok)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print '\n\n-------------------------------------------------------------------'
print 'Your new access key pair has been stored in the AWS configuration file:'
print '    {0} (under the saml profile).'.format(filename)
print 'Note that it will expire at {0}.'.format(aws_exp)
print 'To use this credential, call the AWS CLI with the --profile option'
print '    (e.g. aws --profile saml ec2 describe-instances).'
print '-------------------------------------------------------------------\n\n'
