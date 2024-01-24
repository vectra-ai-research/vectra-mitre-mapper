from Modules.Navigator import BuildVectraMitreLayerInfo, CreateMitreLayerFile
from Modules.BuildDatabase import BuildDatabase
from Modules.VectraAPIFunctions import RequestAccessToken
import os

def InitializationFileCheck():
    ###Check primary data files
    print("\nCheck: Initialization check running")
    parent_dir = os.path.abspath("")
    if os.path.exists(parent_dir+"/Output") == False:
        os.mkdir(parent_dir+"/Output")

    if os.path.isfile(parent_dir+"/config.json") == False:
        with open(parent_dir+"/config.json", "w") as fp:
            pass

    if os.path.exists(parent_dir+"/Output/Nav_Layers") == False:
        os.mkdir(parent_dir+"/Output/Nav_Layers")

    if os.path.exists(parent_dir+"/Tool_Data") == False:
        os.mkdir(parent_dir+"/Tool_Data")

    if os.path.exists(parent_dir+"/Tool_Data/DB") == False:
        os.mkdir(parent_dir+"/Tool_Data/DB") 
    
    print("\nCheck: All primary files available")

    

if __name__ == '__main__':
    InitializationFileCheck()
    RequestAccessToken()
    BuildDatabase()
    techniques = BuildVectraMitreLayerInfo()
    CreateMitreLayerFile(techniques)