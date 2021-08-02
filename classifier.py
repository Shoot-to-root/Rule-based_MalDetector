import sys
import json
import os

def bruteforce():
    if "url" not in data:
        return False
    if "query" not in data["url"]:
        return False
    if "Login=Login&password=" in data["url"]["query"]:
        return True
    return False

def ddos(): 
    global portCounter, packetCounter
    
    if "packets" not in data["network"]:
        return False
    
    if "source" not in data:
        return False
    if "port" not in data["source"]:
        return False
    if "network" not in data:
        return False
    if "packets" not in data["network"]:
        return False
    
    if data["source"]["port"] == 80:
        portCounter = portCounter + 1
    if data["network"]["packets"] > 100:
        packetCounter = packetCounter + 1
    
def phishing():
    if "winlog" not in data:
        return False
    if "ObjectName" not in data['winlog']['event_data']:
        return False
    if "ProcessName" not in data['winlog']['event_data']:
        return False
    if ".pdf" in data["winlog"]["event_data"]["ObjectName"] or ("Adobe" in data["winlog"]["event_data"]["ProcessName"]):
        return True
    
def sql():
    if "url" not in data:
        return False
    if "query" not in data["url"]:
        return False
    if "user_agent" not in data:
        return False
    if "original" not in data["user_agent"]:
        return False
        
    if "sqlmap" in data["user_agent"]["original"] or ("SELECT" or "UNION" in data["url"]["query"]):
        return True

def portscan():
    if "destination" not in data:
        return False
    if "ip" not in data["destination"]:
        return False
    if "port" not in data["destination"]:
        return False
    if "host" not in data:
        return False
    if "ip" not in data["host"]:
        return False
    
    if data["destination"]["ip"] in data["host"]["ip"]:
        portscanCounter.add(data["destination"]["port"])

path = sys.argv[1]

bruteThreshold = 1000
portscanThreshold = 1000
sqlThreshold = 50

for files in os.listdir(path):
    ppath = os.path.join(path, files, "packetbeat.json")
    wpath = os.path.join(path, files, "winlogbeat.json")
    
    portCounter = 0
    packetCounter = 0
    bruteCounter = 0
    phishingCounter = 0
    sqlCounter = 0
    portscanCounter = set()

    for line in open(ppath,'r'):
        data = json.loads(line)
        
        ddos()
        portscan()
        
        if bruteforce():
            bruteCounter = bruteCounter + 1  
            
        if sql():
            sqlCounter = sqlCounter + 1
            
    for line in open(wpath, 'r'):
        data = json.loads(line)
        
        if phishing():
            phishingCounter = phishingCounter + 1
            break
    
    if bruteCounter > bruteThreshold:
        print(files + ": attack 1")
    elif (portCounter > 100) and (packetCounter > 50):
        print(files + ": attack 2")
    elif len(portscanCounter) > portscanThreshold:
        print(files + ": attack 3")
    elif sqlCounter > sqlThreshold:
        print(files + ": attack 5")
    else:
        print(files + ": attack 4")
    

