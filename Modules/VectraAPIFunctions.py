#Detections
import os
import json 
import base64
import requests
import datetime

def RequestAccessToken(tenant_url, client_id, client_secret):
    ###Do not modify this section###
    if None in [client_id, client_secret, tenant_url]:
        return None
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

            response = requests.request("POST", request_url, headers=headers, data=payload)

            if response.status_code == 200: 
                structured_response = json.loads(response.text)
                current_time = datetime.datetime.now()
                access_token_expire_time = current_time + datetime.timedelta(seconds=structured_response['expires_in'])

                structured_response.update({'access_token_expire_time':str(access_token_expire_time)})

                access_token = structured_response.get('access_token')
                
                return access_token

            else:
                print(f"Response: {response.status_code}")
                return None
        except:
            return None

def ReadDatabase(filename):
    f = open(filename)
    file_data = json.load(f)
    return file_data

def WriteToDatabase(file_name, json_data):
    with open(file_name, "w") as outfile:
        json.dump(json_data, outfile)


def GetAllDetections(access_token, request_url, detection_by=None, id = None, state = None):
    #Acceptable values for 'detection_type' are 'account' or 'detection' or 'None'
    #Accceptable value for 'id' is an integer representing individual detection ID or Accoutn ID
    #Acceptable value for 'state' are 'active' or 'fixed' or 'None'
    if access_token:
        print("Info: GetAllDetections execution")
        headers = {
            'Authorization': 'Bearer '+access_token
            }
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



def ListAllDetections(access_token, request_url):
    print("Info: ListAllDetections Execution")
    
    structured_response_detections = GetAllDetections(access_token, request_url)
    all_detections = []

    for results in structured_response_detections['results']:
        all_detections.append(results['detection_type'])
    
    unique_all_detections = list(set(all_detections))

    return all_detections,unique_all_detections


def GetAllEntities(access_token, request_url, is_prioritized= None, severity = None):
    #Function to return all (or just active) entities in the environment
    #Accepts optional parameters is_prioritized= None, severity = None, urgency_score = None'
    
    if access_token:
        headers = {
            'Authorization': 'Bearer '+access_token
            }
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