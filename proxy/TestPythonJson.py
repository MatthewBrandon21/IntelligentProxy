import json

with open("FirewallRulesClone.json", "r+") as jsonFile:
    data = json.load(jsonFile)

    data["ListOfBannedIpAddr"].append("192.168.1.1")

    jsonFile.seek(0)  # rewind
    json.dump(data, jsonFile)
    jsonFile.truncate()