import json 
import requests

def GetAllDetections(auth, request_url, detection_by=None, id = None, state = None):
    #Acceptable values for 'detection_type' are 'account' or 'detection' or 'None'
    #Accceptable value for 'id' is an integer representing individual detection ID or Accoutn ID
    #Acceptable value for 'state' are 'active' or 'fixed' or 'None'

    # validate access token
    auth.authManager()

    if auth.accessToken:
        print("Info: GetAllDetections execution")
        headers = {
            'Authorization': 'Bearer '+auth.accessToken
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
        
        # set state
        if state == 'fixed':
            params['state'] = 'fixed'
        elif state == 'all':
            # no api param required, default state is all
            pass
        else:
            params['state'] = 'active'

        # handle pagination
        page = 1
        next = True
        while next == True:
            print("Fetching detections")
 
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

def ListAllDetections(auth, request_url, detection_by=None, id = None, state = None):
    print("Info: ListAllDetections Execution")
    
    structured_response_detections = GetAllDetections(auth, request_url, detection_by = detection_by, id = id, state = state)
    all_detections = []

    for results in structured_response_detections['results']:
        all_detections.append(results['detection_type'])
    
    unique_all_detections = list(set(all_detections))

    return all_detections,unique_all_detections