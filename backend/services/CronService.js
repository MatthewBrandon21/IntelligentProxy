var cron = require("node-cron");

const CRABService = require("../services/CRABService");
const crabService = new CRABService("myModel");

const fs = require("fs");
// change the firewall rules file
const fileName = "../proxy/FirewallRulesClone.json";
let firewallRules = require("../../proxy/FirewallRulesClone.json");

cron.schedule("* * * * *", () => {
  console.log("Cron for checking firewall rule blockchain");

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type == "firewall" && asset.data.status != "BURNED") {
        let firewallConfiguration = [];
        asset.data.data.map((asset) => {
          firewallConfiguration.push(asset.ipAddress);
        });

        console.log("updating firewall rules to FirewallRules.json");
        firewallRules.ListOfBannedIpAddr = firewallConfiguration;
        fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
          if (err) return console.log(err);
          // console.log(JSON.stringify(firewallRules));
          // console.log("writing to " + fileName);
        });
        status = true;
      }
    });

    if (status == false) {
      let firewallConfiguration = [];

      console.log("updating firewall rules to FirewallRules.json");
      firewallRules.ListOfBannedIpAddr = firewallConfiguration;
      fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
        if (err) return console.log(err);
        // console.log(JSON.stringify(firewallRules));
        // console.log("writing to " + fileName);
      });
    }
  });
});

module.exports = cron;
