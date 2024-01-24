import time
import os
from datetime import datetime, date
from .VectraAPIFunctions import WriteToDatabase, GetAllDetections, GetAllEntities

def BuildDatabase():
    parent_dir = os.path.abspath("")
    today = str(date.today())
    if os.path.exists(parent_dir+"/Tool_Data/DB/"+today)== False:
        os.mkdir(parent_dir+"/Tool_Data/DB/"+today)
    
    folder_name = today

    try:
        database_build_start_time = datetime.today()
        print(f"database_build_start at {str(database_build_start_time)} ...")
        ##Query primary endpoints

        ##List all accounts
        '''
        all_accounts = GetAllAccounts()
        print("api query: GetAllAccounts")
        file_name = "./DB/"+folder_name+"/all_accounts_"+today+".json"
        WriteToDatabase(file_name,all_accounts)
        WriteToLogger(datetime.today(),"F_GetAllAccounts","success")
        time.sleep(10)
        '''

        ##List all detections
        all_detections = GetAllDetections()
        print("api query: GetAllDetections")
        file_name = "./Tool_Data/DB/"+folder_name+"/all_detections_"+today+".json"
        WriteToDatabase(file_name,all_detections )
        time.sleep(10)

        ##List all entities
        all_entities = GetAllEntities()
        print("api query: GetAllEntities")
        file_name = "./Tool_Data/DB/"+folder_name+"/all_entities_"+today+".json"
        WriteToDatabase(file_name,all_entities )
        time.sleep(10)

        '''
        #List account detection events
        all_detection_events = GetAccountDetectionEvents()
        print("api query: GetAccountDetectionEvents")
        file_name = "./DB/"+folder_name+"/all_detection_events_"+today+".json"
        WriteToDatabase(file_name,all_detection_events)
        WriteToLogger(datetime.today(),"F_GetAllDetectionEvents","success")
        time.sleep(10)

        #List all assignments
        all_assignments = GetAllAssignments()
        print("api query: GetAllAssignments")
        file_name = "./DB/"+folder_name+"/all_assignments_"+today+".json"
        WriteToDatabase(file_name,all_assignments )
        WriteToLogger(datetime.today(),"F_GetAllAssignments","success")
        ''' 
        database_build_end_time = datetime.today()
        print(f"database_build completed successfully at {str(database_build_end_time)} !")

        total_build_time = (database_build_end_time - database_build_start_time).total_seconds()/60
        print(f"Total DB build time: {total_build_time} mins")
        return None
    except:
        print(f"database_build failed {str(datetime.today().time())}")
        return None