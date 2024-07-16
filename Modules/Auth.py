import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import base64
import datetime
import os.path
import pickle
from .Logger import get_logger

#var
tokens_filename = 'tokens.pickle'
tokens = {'accessToken': '', 'expiresAt': '', 'refreshToken': '', 'refreshExpiresAt': ''}

#logger
LOG = get_logger("vectra-saas-auth",stream_level='DEBUG')


class VectraSaaSAuth:
    
    def __init__(self, url, id, secret):
        
        if url == '' or id == '' or secret == '':
        
            LOG.error(f'Configuration is not set. Edit config file! Exiting..')
            exit()
        
        self.url = url
        self.client_id = id
        self.client_secret = secret
        self.accessToken = ""
        self.refreshToken = ""
        self.expiresAt = ""
        self.refreshExpiresAt = ""
        
    def getToken(self):
        '''
        Return Token string
        '''
        
        return self.accessToken
        
    def retry_session(retries=5, session=None, backoff_factor=0.3):
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

        
    def loadSavedTokens(self):
        '''
        load Tokens saved on disk
        '''
        
        with open(tokens_filename, 'rb') as f:
            
            tokens = pickle.load(f)
            
        self.accessToken = tokens['accessToken']
        self.expiresAt = tokens['expiresAt']
        self.refreshToken = tokens['refreshToken']
        self.refreshExpiresAt = tokens['refreshExpiresAt']
        
        self.printDict(tokens)
        
    def saveTokens(self):
        '''
        save token and refresh token (including expiry date) in a pickle file
        '''
        
        tokens = {'accessToken': self.accessToken, 'expiresAt': self.expiresAt, 'refreshToken': self.refreshToken, 'refreshExpiresAt': self.refreshExpiresAt}
        
        with open(tokens_filename, 'wb') as f:
            
            pickle.dump(tokens, f)

    def authManager(self):
        '''
        This function is making sure there is a valid accessToken to use
        '''
        
        credsLoadedFromFile = False
        
        #no existing token in global variables or store locally
        if not os.path.exists(tokens_filename) and self.accessToken == '':
            
            LOG.info(f'No existing tokens found ({ tokens_filename } does not exist). Initiating authentication.. ')
            
            self.authenticate()
            
        elif os.path.exists(tokens_filename) and self.accessToken == '':
            
            #loading stored information
            LOG.info(f'Loading saved tokens')
            self.loadSavedTokens()
            credsLoadedFromFile = True  
        
        if self.accessToken != '' or credsLoadedFromFile == True:
            
            #access token exists - still valid?
            now = datetime.datetime.utcnow()
            format = '%Y-%m-%d %H:%M:%S.%f'
            token_exp = datetime.datetime.strptime(str(self.expiresAt), format)
            refresh_token_exp = datetime.datetime.strptime(str(self.refreshExpiresAt), format)
            if now > token_exp and now > refresh_token_exp:
                
                #all expired - get new token
                LOG.info(f'All tokens expired - Initiating new authentication')
                self.authenticate()
                
            elif now > token_exp and now < refresh_token_exp:
                
                #refresh token still valid - getting a new token
                LOG.info(f'Token has expired at { self.expiresAt } (current UTC Time: { now }) - Using refresh token to get a new token')
                self.refresh_auth()
                
            else:
                LOG.info(f'Access token is still valid! Expire at { self.expiresAt } (current UTC time: { now})')
                
        else:
            LOG.debug(f'New tokens have just been created. All set!')

    def authenticate(self):
        '''
        Authenticate to SaaS API
        '''
        
        url = self.url+"oauth2/token"

        auth_string = self.client_id+':'+self.client_secret
        auth_string_base64 = base64.b64encode(auth_string.encode('ascii'))

        payload='grant_type=client_credentials'
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': 'Basic '+auth_string_base64.decode('ascii')
        }
        
        LOG.debug(f'OAuth query: { url } with payload { payload }')
        
        try:
            
            session = self.retry_session()
            response = session.post(url=url, data=payload, headers=headers)
            #LOG.error(response.raise_for_status())
            
            LOG.debug(f'{ response }')
            
            self.accessToken = response.json()['access_token']
            self.expiresAt = str(datetime.datetime.utcnow() + datetime.timedelta(seconds=response.json()['expires_in']))
            self.refreshToken = response.json()['refresh_token']
            self.refreshExpiresAt = str(datetime.datetime.utcnow() + datetime.timedelta(seconds=response.json()['refresh_expires_in']))

            LOG.info(f'Access Token: { self.accessToken}')
            LOG.info(f'Access Token expires at: { self.expiresAt }')
            LOG.info(f'Refresh Token: { self.refreshToken}')
            LOG.info(f'Refresh Token expires at: { self.refreshExpiresAt }')
            
            self.saveTokens()
                
        except requests.exceptions.TooManyRedirects:
            
            LOG.error(f'Too many redirect. Check the URL: { url }')
            
        except requests.exceptions.RequestException as e:
            
            LOG.error(f'Request Error: { e }')
            raise SystemExit(e)
        
    def refresh_auth(self):
        '''
        get new access token with refresh token
        '''
        
        auth_string = self.client_id+':'+self.client_secret
        auth_string_base64 = base64.b64encode(auth_string.encode('ascii'))
        
        url = self.url+"oauth2/token"

        payload=f'grant_type=refresh_token&refresh_token={self.refreshToken}'
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
        }
        
        try:
            
            session = self.retry_session()
            response = session.post(url=url, data=payload, headers=headers)

            #response = requests.request("POST", url, headers=headers, data=payload)
            
            LOG.debug(response.json())
            
            #store new value
            self.accessToken = response.json()['access_token']
            self.expiresAt = str(datetime.datetime.utcnow() + datetime.timedelta(seconds=response.json()['expires_in']))
            
            LOG.info(f'New access Token: { self.accessToken}')
            LOG.info(f'New access Token expires at: { self.expiresAt }')
            
            #save to disk
            self.saveTokens()
            
        except requests.exceptions.TooManyRedirects:
            
            LOG.error(f'Too many redirect. Check the URL: { url }')
            
        except requests.exceptions.RequestException as e:
            
            LOG.error(f'Request Error: { e }')
            raise SystemExit(e)
            LOG.info(f'Access Token: { accessToken}')
            LOG.info(f'Access Token expires at: { expiresAt }')
            LOG.info(f'Refresh Token: { refreshToken}')
            LOG.info(f'Refresh Token expires at: { refreshExpiresAt }')
            
            saveTokens()
                
        except requests.exceptions.TooManyRedirects:
            
            LOG.error(f'Too many redirect. Check the URL: { url }')
            
        except requests.exceptions.RequestException as e:
            
            LOG.error(f'Request Error: { e }')
            raise SystemExit(e)

    def printDict(self, dict):
        '''
        Generic function to print a dict
        '''    
        
        for key, value in dict.items():
            LOG.debug(f'{ key} : { value}')