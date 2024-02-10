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


def CreateMitreLayerFile(techniques, total_triggered_techniques, tenant_url):
    basic_layer_file = "./Resources/basic_layer_structure.json"

    all_mitre_techniques = GetTechniques(x_mitre_is_subtechnique = False, revoked_n_deprecated=False)
    
    all_mitre_technique_id = []
    for technique in all_mitre_techniques:
        for reference in technique["external_references"]:
            if reference["source_name"] == "mitre-attack":
                all_mitre_technique_id.append(reference["external_id"])

    # Read from saas_iaas_layer.json for structure & convert to dictionary
    with open(basic_layer_file, 'r') as basic_layer:
            basic_layer_info = json.load(basic_layer)

    # Set platforms scope
    basic_layer_info["filters"]["platforms"] = ["Linux", "Windows", "Network", "Office 365", "SaaS", "IaaS", "Azure AD"]
    # Add the created techniques dictionary to it
    basic_layer_info["techniques"] = techniques

    # Add layer name
    basic_layer_info["name"] = "Vectra MITRE Detection Map"

    # Add sorting
    basic_layer_info["sorting"] = 3

    # Add layer description
    basic_layer_info["description"] = f"Total Coverage : 109 , Detected : {total_triggered_techniques}"

    #Add link to vectra tenant
    basic_layer_info["links"].append({"label" : "Vectra Tenant Link", "url" : tenant_url})

    # Add row background color
    basic_layer_info["showTacticRowBackground"] = True
    basic_layer_info["tacticRowBackground"] = "#08392a"

    # Hide out of scope techniques
    basic_layer_info["hideDisabled"] = True

    # Add legend
    basic_layer_info["legendItems"].append({"label" : "Detected Techniques", "color" : "#e99913"})

    timestamp = int(time.time())
    # Convert back to json file
    with open(f"./Output/Nav_Layers/tenant_layer_{timestamp}.json", "w") as outfile:
        json.dump(basic_layer_info, outfile)

    print("\nNavigator layer file available: /Output/Nav_Layers/")

def BuildVectraMitreLayerInfo(access_token, request_url):
    '''Function to construct the techniques json for the MITRE layer file'''
    vectra_mitre_map_file = "./Resources/vectra_att&ck_v13-detection_to_technique.json"

    mitre_technique_to_phase_map_file = "./Resources/Mitre_Technique_To_Phase_Map.json"

    #Create or update existing file for MITRE techniques to Phase mapping
    CreateMitreTechniquePhaseMapFile()

    with open(vectra_mitre_map_file, 'r') as vectra_mitre_file:
            vectra_mitre_map = json.load(vectra_mitre_file)

    #Fetch latest detections from tenant
    all_triggered_detections,unique_triggered_detections = ListAllDetections(access_token = access_token, request_url = request_url)

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

    total_triggered_techniques = len(unique_triggered_techniques)

    techniques = []
    
    '''Exclude out of scope techniques'''
    all_vectra_techniques = []
    for phase in vectra_mitre_map:
        all_vectra_techniques += vectra_mitre_map[phase]
    
    # List of only unique techniques in vectra coverage
    all_vectra_techniques = list(set(all_vectra_techniques))

    all_mitre_techniques = GetTechniques(x_mitre_is_subtechnique = False, revoked_n_deprecated=False)
    technique_to_sub_technique_map = subtechniques_of(mitre_data_ent_latest)

    for technique in all_mitre_techniques:
        
        technique_id = technique.external_references[0]['external_id']
        
        tactics = technique.kill_chain_phases
        technique_tactics_names = []
        for ind_tactic in tactics:
            technique_tactics_names.append(ind_tactic['phase_name'])

        if technique_id in unique_triggered_techniques :
            for ind_tactic in technique_tactics_names :
                technique_layer_info = {"techniqueID": technique_id, "tactic": ind_tactic, "color": "#e99913", "comment": "", "enabled": True, "metadata": [], "links": [], "showSubtechniques": False, "score": 3}
                techniques.append(technique_layer_info)

        elif technique_id in all_vectra_techniques:
            for ind_tactic in technique_tactics_names :
                technique_layer_info = {"techniqueID": technique_id, "tactic": ind_tactic, "color": "#00000000", "comment": "", "enabled": True, "metadata": [], "links": [], "showSubtechniques": False, "score": 1}
                techniques.append(technique_layer_info)

        else :
            for ind_tactic in technique_tactics_names :
                technique_layer_info = {"techniqueID": technique_id, "tactic": ind_tactic, "color": "#", "comment": "", "enabled": False, "metadata": [], "links": [], "showSubtechniques": False, "score": 0}
                techniques.append(technique_layer_info)
                
                if technique.id in technique_to_sub_technique_map.keys():
                    for sub_technique in technique_to_sub_technique_map[str(technique.id)]:
                        sub_technique_id = sub_technique['object'].external_references[0]['external_id']
                        technique_layer_info = {"techniqueID": sub_technique_id, "tactic": ind_tactic, "color": "#", "comment": "", "enabled": False, "metadata": [], "links": [], "showSubtechniques": False, "score": 0}
                        techniques.append(technique_layer_info)

    return techniques, total_triggered_techniques