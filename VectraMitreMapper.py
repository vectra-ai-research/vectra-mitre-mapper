from Modules.Navigator import BuildVectraMitreLayerInfo, CreateMitreLayerFile
from Modules.VectraAPIFunctions import RequestAccessToken
import os
import sys

def InitializationFileCheck():
    ###Check primary data files
    print("\nCheck: Initialization check running")
    parent_dir = os.path.abspath("")
    if os.path.exists(parent_dir+"/Output") == False:
        os.mkdir(parent_dir+"/Output")
    
    print("\nCheck: All primary files available")

if __name__ == '__main__':
    tenant_url = sys.argv[1]
    client_id = sys.argv[2]
    client_secret = sys.argv[3]
    try:
        layer_name = sys.argv[4]
    except:
        layer_name = "Vectra MITRE Detection Map"

    request_url = tenant_url+"/api/v3.3"
    InitializationFileCheck()
    access_token = RequestAccessToken(tenant_url, client_id, client_secret)
    techniques, total_triggered_techniques = BuildVectraMitreLayerInfo(access_token = access_token, request_url = request_url)
    CreateMitreLayerFile(layer_name, techniques, total_triggered_techniques, tenant_url)