# -*- encoding: utf-8 -*-
from __future__ import unicode_literals
import requests
from requests_oauthlib import OAuth1
from urlparse import parse_qs

from xml.etree import ElementTree

auth = ElementTree.parse('Auth.xml')

request_token_url = auth.find('url/request_token_url')
REQUEST_TOKEN_URL = request_token_url.attrib['name']
authorize_url = auth.find('url/authorize_url')
AUTHORIZE_URL = authorize_url.attrib['name']
access_token_url = auth.find('url/access_token_url')
ACCESS_TOKEN_URL = access_token_url.attrib['name']

access_token_key = auth.find('account/access_token_key')
OAUTH_TOKEN = access_token_key.attrib['name']
access_token_secret = auth.find('account/access_token_secret')
OAUTH_TOKEN_SECRET = access_token_secret.attrib['name']

consumer_key = auth.find('account/consumer_key')
CONSUMER_KEY = consumer_key.attrib['name']
consumer_secret = auth.find('account/consumer_secret')
CONSUMER_SECRET = consumer_secret.attrib['name']

def setup_oauth():
    """Authorize your app via identifier."""
    # Request token
    oauth = OAuth1(CONSUMER_KEY, client_secret=CONSUMER_SECRET)
    r = requests.post(url=REQUEST_TOKEN_URL, auth=oauth)
    credentials = parse_qs(r.content)

    resource_owner_key = credentials.get('oauth_token')[0]
    resource_owner_secret = credentials.get('oauth_token_secret')[0]

    # Authorize
    authorize_url = AUTHORIZE_URL + resource_owner_key
    print 'Please go here and authorize: ' + authorize_url

    verifier = raw_input('Please input the verifier: ')
    oauth = OAuth1(CONSUMER_KEY,
                   client_secret=CONSUMER_SECRET,
                   resource_owner_key=resource_owner_key,
                   resource_owner_secret=resource_owner_secret,
                   verifier=verifier)

    # Finally, Obtain the Access Token
    r = requests.post(url=ACCESS_TOKEN_URL, auth=oauth)
    credentials = parse_qs(r.content)
    token = credentials.get('oauth_token')[0]
    secret = credentials.get('oauth_token_secret')[0]

    return token, secret


def get_oauth():
    oauth = OAuth1(CONSUMER_KEY,
                client_secret=CONSUMER_SECRET,
                resource_owner_key=OAUTH_TOKEN,
                resource_owner_secret=OAUTH_TOKEN_SECRET)
    return oauth

if __name__ == "__main__":
    if not OAUTH_TOKEN:
        token, secret = setup_oauth()
        print "OAUTH_TOKEN: " + token
        print "OAUTH_TOKEN_SECRET: " + secret
        print
    else:
        oauth = get_oauth()
        r = requests.get(url="https://api.twitter.com/1.1/search/tweets.json?q=microsoft", auth=oauth)
        response = r.json()
        statuses = response['statuses']
        for status in statuses:
            print status['text']
