const CRABService = require("../services/CRABService");
const crabService = new CRABService("intelligentProxy");

var Democracy = require("democracy");

const fs = require("fs");
// change the firewall rule name
const fileName = "FirewallRulesClone.json";
let firewallRules = require("../../proxy/FirewallRulesClone.json");

var dem = new Democracy({
  source: "0.0.0.0:5000",
  peers: ["0.0.0.0:5000", "0.0.0.0:5001", "0.0.0.0:5002"],
});

dem.on("added", function (data) {
  console.log("Added: ", data);
});

dem.on("removed", function (data) {
  console.log("Removed: ", data);
});

dem.on("elected", function (data) {
  console.log("You are elected leader!");
});

dem.on("leader", function (data) {
  console.log("New Leader: ", data);
});

dem.on("test_democracy", (data) => {
  console.log(data.hello);
});

dem.send("test_democracy", { hello: "Hello node!" });

dem.on("default-channel", (data) => {
  console.log(data.hello);
});

dem.subscribe("default-channel");
dem.publish("default-channel", { hello: "default message" });

dem.on("firewall-channel", (msg) => {
  console.log("New firewall rules from other nodes, firewall id : " + msg);

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

dem.subscribe("firewall-channel");

module.exports = dem;
