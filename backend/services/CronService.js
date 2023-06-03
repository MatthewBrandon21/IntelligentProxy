var cron = require("node-cron");
const CRABService = require("../services/CRABService");

const crabService = new CRABService("myModel");

const fs = require("fs");
const fileName = "FirewallRulesClone.json";
let firewallRules = require("../FirewallRulesClone.json");

cron.schedule("* * * * *", () => {
  console.log("Checking firewall blockchain");
  crabService.retrieveAllAssets().then((value) => {
    // res.json(value);
    // res.json(value.map((asset) => asset.data));
    // console.log(firewallRules.ListOfBannedIpAddr);
    // console.log(firewallRules.ListOfBannedIpAddr.map((ip) => ip));
    value.map((asset) => {
      if (firewallRules.ListOfBannedIpAddr.includes(asset.data.ipAddress) == false) {
        if (asset.data.status != "BURNED") {
          console.log("adding ip " + asset.data.ipAddress + " to FirewallRules.json");
          firewallRules.ListOfBannedIpAddr.push(asset.data.ipAddress);
          fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
            if (err) return console.log(err);
            console.log(JSON.stringify(firewallRules));
            console.log("writing to " + fileName);
          });
        }
      }
    });
  });
});

module.exports = cron;
