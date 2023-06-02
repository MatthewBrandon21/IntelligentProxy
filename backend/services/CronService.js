var cron = require("node-cron");
const CRABService = require("../services/CRABService");

const crabService = new CRABService("myModel");

const fs = require("fs");
const fileName = "FirewallRulesClone.json";
let firewallRules = require("../FirewallRulesClone.json");

cron.schedule("* * * * *", () => {
  console.log("running a task every minute");
  crabService.retrieveAsset().then((value) => {
    // console.log(value);
    // res.json(value.map((asset) => asset.data));
    // console.log(firewallRules.ListOfBannedIpAddr);
    console.log(firewallRules.ListOfBannedIpAddr.map((ip) => ip));
    value.map((asset) => {
      if (firewallRules.ListOfBannedIpAddr.includes(asset.data.ip) == false) {
        console.log("adding ip " + asset.data.ip + " to FirewallRules.json");
        firewallRules.ListOfBannedIpAddr.push(asset.data.ip);
        fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
          if (err) return console.log(err);
          console.log(JSON.stringify(firewallRules));
          console.log("writing to " + fileName);
        });
        // fs.writeFileSync("../new.json", JSON.stringify(firewallRules));
      }
    });
  });
});

module.exports = cron;
