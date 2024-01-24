#Detections
import os
import json 
import base64
import requests
import datetime
from datetime import date, time
from .APIAuth import client_id,client_secret, tenant_url

request_url = tenant_url+"/api/v3.3"

def RequestAccessToken():
    ###Do not modify this section###
    if "" in [client_id, client_secret, tenant_url]:
        print("\nAuthentication credentials missing. \nAdd credentials to /Modules/APIAuth.py")
        print("Exiting now!")
        quit()
    else:
        try:
            request_url = tenant_url+"/oauth2/token"
            basic_auth_token_encoded = base64.standard_b64encode((client_id+':'+client_secret).encode("ascii"))
            basic_auth_token = basic_auth_token_encoded.decode("ascii")
            

            payload='grant_type=client_credentials'
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'Authorization': 'Basic '+ basic_auth_token
            }
            ###___###

            response = requests.request("POST", request_url, headers=headers, data=payload)

            print(response.status_code)

            if response.status_code == 200: 
                structured_response = json.loads(response.text)
                current_time = datetime.datetime.now()
                access_token_expire_time = current_time + datetime.timedelta(seconds=structured_response['expires_in'])

                #Update json with enriched information
                structured_response.update({'access_token_expire_time':str(access_token_expire_time)})

                #Update the config file with new token
                with open('./access.json', 'w') as config_file:
                    json.dump(structured_response, config_file)
                
                return True

            else:
                print(f"Response: {response.status_code}")
                return False
        except:
            print("Invalid credentials provided. Check Modules/APIAuth.py")
            print("Exiting now!")
            quit()

def UpdateGlobalAuthConfig():
    with open('./access.json', 'r') as config_file:
        config = json.load(config_file)
    #Access token retrieved:
    access_token = config.get('access_token')
    #Refresh token retrieved:
    refresh_token = config.get('refresh_token')

    token_type = "Bearer"
    headers = {
        'Authorization': 'Bearer '+access_token
        }
    
    return headers


#This will trigger before every API call
def CheckTokenValidity():
    current_time = datetime.datetime.now()

    with open('./access.json', 'r') as config_file:
        config = json.load(config_file)

    access_token = config.get('access_token')
    access_token_expires_in = config.get('expires_in')
    access_token_expire_time = config.get('access_token_expire_time')
    access_token_expire_time = datetime.datetime.strptime(access_token_expire_time,"%Y-%m-%d %H:%M:%S.%f")

    #If no access token found then request one
    if access_token == '' or None:
        token_generation = RequestAccessToken()
        if token_generation == True:
            print('token generated')
            return "Token valid"
        else:
            print('token invalid')
            return "Token invalid"
    
    #If current time is beyond expiration time, refresh token
    elif (current_time >= access_token_expire_time):
        token_generation = RequestAccessToken()
        if token_generation == True:
            print("Token valid")
            return "Token valid"
        else:
            print('token invalid')
            return "Token invalid"
    
    #Check if token is expiring in less than an hour of the token expiry. If token expires in 6 hours, refresh token every 5 hours
    elif (current_time-access_token_expire_time).total_seconds() > (access_token_expires_in-3600):
        token_generation = RequestAccessToken()
        if token_generation == True:
            print("Token valid")
            return "Token valid"
        else:
            print('token invalid')
            return "Token invalid"
    else:
        print(f'Token is valid and expires at: {access_token_expire_time}')
        return 'Token valid'


def ReadDatabase(filename):
    f = open(filename)
    file_data = json.load(f)
    return file_data

def WriteToDatabase(file_name, json_data):
    with open(file_name, "w") as outfile:
        json.dump(json_data, outfile)


def GetAllDetections(detection_by=None, id = None, state = None):
    #Acceptable values for 'detection_type' are 'account' or 'detection' or 'None'
    #Accceptable value for 'id' is an integer representing individual detection ID or Accoutn ID
    #Acceptable value for 'state' are 'active' or 'fixed' or 'None'
    if CheckTokenValidity() == 'Token valid':
        headers = UpdateGlobalAuthConfig()
        endpoint_url = request_url+"/detections"
        payload = {}
        params = {}
        main_structured_response = {}

        if detection_by == 'account':
            params['src_account'] = id
        elif detection_by == 'detection':
            params['id'] = id
        else:
            pass

        if state in ['active','fixed']:
            params['state'] = state
        else:
            pass

        #handle pagination
        page = 1
        next = True
        while next == True:
            # response = requests.request("GET", endpoint_url, headers=headers, data=payload, params=params, verify=False)
            response = requests.request("GET", endpoint_url, headers=headers, data=payload, params=params)
            page += 1
            params['page'] = page
            structured_response = json.loads(response.text)
            
            if structured_response['previous'] == None:
                main_structured_response = structured_response

            else:
                #building the main response
                for detection in structured_response['results']:
                    main_structured_response['results'].append(detection)
                        #check if next result page exists
            if structured_response['next'] == None:
                next = False

        return main_structured_response
    
    else:
        return None



def ListAllDetections(print_results = False):
    
    structured_response_detections = GetAllDetections()
    all_detections = []

    for results in structured_response_detections['results']:
        all_detections.append(results['detection_type'])
    
    unique_all_detections = list(set(all_detections))
    
    if print_results == True: 
        print(f"\nAll unique detections triggered: {len(unique_all_detections)}\n")
        for detection in unique_all_detections:
            print(detection)

    return all_detections,unique_all_detections


def GetAllEntities(is_prioritized= None, severity = None):
    #Function to return all (or just active) entities in the environment
    #Accepts optional parameters is_prioritized= None, severity = None, urgency_score = None'
    
    if CheckTokenValidity() == 'Token valid':
        headers = UpdateGlobalAuthConfig()
        endpoint_url = request_url+"/entities"  
        params = {}
        main_structured_response = {}

        if is_prioritized == 'true':
            params['is_prioritized'] ='true' 
        else:
            pass

        if severity in ["Critical","High","Medium","Low"]:
            params['severity'] = severity
        else:
            pass

        #handle pagination
        page = 1
        next = True
        while next == True:
            response = requests.request("GET", endpoint_url, headers=headers, params=params, verify=False)
            page += 1
            params['page'] = page

            if response.status_code == 200:
                structured_response = json.loads(response.text)

                if structured_response['previous'] == None:
                    main_structured_response = structured_response
                
                else:
                    #building the main response
                    for entity in structured_response['results']:
                        main_structured_response['results'].append(entity)

                #check if next result page exists
                if structured_response['next'] == None:
                    next = False
        
        
        #return structured_response
        return main_structured_response
    
    else:
        return None