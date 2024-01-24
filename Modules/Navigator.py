import json 
import time
from .VectraAPIFunctions import ListAllDetections
from stix2 import Filter
from .BaseMitreFunctions import *

#Load the latest mitre data to memory
mitre_data_ent_latest = get_attack_version("enterprise-attack", "14.0")

def GetTechniques(mitre_data = mitre_data_ent_latest, x_mitre_platform = None, name = None, x_mitre_is_subtechnique = "All",revoked_n_deprecated=None):
    """Queries and return Technique information based on specified parameters. If no parameters are supplied, the function returns all Techniques in latest enterprise matrix"""
    filter = [
        Filter('type', '=', 'attack-pattern')
    ]

    if x_mitre_platform != None:
        if x_mitre_platform in ["Windows","macOS", "Linux","Office 365","Azure AD","Google Workspace","SaaS","IaaS","Network","Containers"]:
            filter.append(Filter("x_mitre_platforms","=",x_mitre_platform))
        else:
            raise RuntimeError(f"Invalid option platform: {x_mitre_platform}")

    if name != None:
        filter.append(Filter('name', '=', name))

    if x_mitre_is_subtechnique != "All":
        if x_mitre_is_subtechnique in [True, False]:
            filter.append(Filter("x_mitre_is_subtechnique","=", x_mitre_is_subtechnique))
        else:
            raise RuntimeError(f"Invalid option is_subtechnique: {x_mitre_is_subtechnique}")

    if revoked_n_deprecated == None:
        return mitre_data.query(filter)
    else:
        if revoked_n_deprecated == False:
            """Return only currently valid objects"""
            return remove_revoked_deprecated(mitre_data.query(filter))
        elif remove_revoked_deprecated == True:
            return None
        else:
            raise RuntimeError(f"Invalid option revoked_n_deprecated: {revoked_n_deprecated}")


def TechniqueToPhaseMapping():
    '''Function builds a json map of techniques and their kill chain phases aka Tactics'''
    mitre_technique_to_phase_map = {}

    all_mitre_techniques = GetTechniques(x_mitre_is_subtechnique = False, revoked_n_deprecated=False)

    for technique in all_mitre_techniques:
        technique_phases = []
        for phase in technique['kill_chain_phases']:
            technique_phases.append(phase['phase_name'])
        
        mitre_technique_to_phase_map[technique['external_references'][0]['external_id']] = technique_phases
    
    return mitre_technique_to_phase_map


def CreateMitreTechniquePhaseMapFile():
    '''Function to create or update the MITRE techniques to phase mapping file'''
    with open(f"./Resources/Mitre_Technique_To_Phase_Map.json", "w") as outfile:
        json.dump(TechniqueToPhaseMapping(), outfile)


def BuildVectraMitreLayerInfo():
    '''Function to construct the techniques json for the MITRE layer file'''
    vectra_mitre_map_file = "./Resources/vectra_att&ck_v13-detection_to_technique.json"

    mitre_technique_to_phase_map_file = "./Resources/Mitre_Technique_To_Phase_Map.json"

    #Create or update existing file for MITRE techniques to Phase mapping
    CreateMitreTechniquePhaseMapFile()

    with open(vectra_mitre_map_file, 'r') as vectra_mitre_file:
            vectra_mitre_map = json.load(vectra_mitre_file)

    with open(mitre_technique_to_phase_map_file, 'r') as mitre_technique_to_phase_file:
            mitre_technique_to_phase_map = json.load(mitre_technique_to_phase_file)

    #Fetch latest detections from tenant
    all_triggered_detections,unique_triggered_detections = ListAllDetections()

    tenant_mitre_map = {}

    all_triggered_techniques =[]

    for detection in unique_triggered_detections:
        try:
            detection_technique = vectra_mitre_map[detection]
            tenant_mitre_map[detection] = vectra_mitre_map[detection]
            all_triggered_techniques += vectra_mitre_map[detection]
        except:
            pass
        
    unique_triggered_techniques = list(set(all_triggered_techniques))

    techniques = []

    for technique in unique_triggered_techniques:
        tactic = mitre_technique_to_phase_map[technique]

        if len(tactic) > 1:
            for ind_tactic in tactic:
                technique_layer_info = {"techniqueID": technique, "tactic": ind_tactic, "color": "#e60d0d", "comment": "", "enabled": True, "metadata": [], "links": [], "showSubtechniques": False}
                techniques.append(technique_layer_info)
        else:
            technique_layer_info = {"techniqueID": technique, "tactic": tactic, "color": "#e60d0d", "comment": "", "enabled": True, "metadata": [], "links": [], "showSubtechniques": False}
            techniques.append(technique_layer_info)
    
    return techniques


def CreateMitreLayerFile(techniques):
    basic_layer_file = "./Resources/basic_layer_structure.json"

    #Read from saas_iaas_layer.json for structure & convert to dictionary
    with open(basic_layer_file, 'r') as basic_layer:
            basic_layer_info = json.load(basic_layer)

    #Add the created techniques dictionary to it
    basic_layer_info["techniques"] = techniques

    timestamp = int(time.time())
    #Convert back to json file
    with open(f"./Output/Nav_Layers/tenant_layer_{timestamp}.json", "w") as outfile:
        json.dump(basic_layer_info, outfile)