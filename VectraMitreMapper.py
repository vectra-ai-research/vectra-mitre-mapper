from Modules.Navigator import BuildVectraMitreLayerInfo, CreateMitreLayerFile
import os
from Modules.Auth import VectraSaaSAuth
from argparse import ArgumentParser

def InitializationFileCheck():
    ###Check primary data files
    print("\nCheck: Initialization check running")
    parent_dir = os.path.abspath("")
    if os.path.exists(parent_dir+"/Output") == False:
        os.mkdir(parent_dir+"/Output")
    
    print("\nCheck: All primary files available")

if __name__ == '__main__':
    parser = ArgumentParser(description='Build a MITRE map of detections in Vectra AI platform.')
    parser.add_argument('-url', '--tenant_url', required=True)
    parser.add_argument('-client', '--client_id', required=True)
    parser.add_argument('-secret', '--client_secret', required=True)
    parser.add_argument('-name', '--layer_name')
    parser.add_argument('-by', '--detection_by')
    parser.add_argument('-id', '--id')
    parser.add_argument('-state', '--detection_state', choices=['active', 'fixed', 'all'])
    
    args = parser.parse_args()

    tenant_url = args.tenant_url
    client_id = args.client_id
    client_secret = args.client_secret

    detection_by = args.detection_by
    id = args.id
    state = args.detection_state

    if args.layer_name == None:
        layer_name = "Vectra AI Tenant Detections MITRE Map"
    else:
        layer_name = args.layer_name

    # api request url
    request_url = tenant_url+"api/v3.3"
    
    # perform initial file check
    InitializationFileCheck()
    
    # authenticate to tenant
    auth = VectraSaaSAuth(tenant_url, client_id, client_secret)
    auth.authenticate()
    auth.authManager()

    # get detection information from tenant
    techniques, total_triggered_techniques = BuildVectraMitreLayerInfo(auth = auth, request_url = request_url, detection_by = detection_by, id = id, state = state)

    # build mitre navigator file
    CreateMitreLayerFile(layer_name, techniques, total_triggered_techniques, tenant_url)