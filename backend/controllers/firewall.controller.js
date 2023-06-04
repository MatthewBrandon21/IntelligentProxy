const CRABService = require("../services/CRABService");

const dem = require("../services/DemocracyService");

const crabService = new CRABService("intelligentProxy");

const fs = require("fs");
const fileName = "FirewallRulesClone.json";
let firewallRules = require("../FirewallRulesClone.json");

exports.create = function (req, res) {
  if (!req.body.keypair) {
    return res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.ipAddress) {
    return res.status(400).send({ message: "ip address is required" });
  }
  if (!req.body.source) {
    return res.status(400).send({ message: "source is required" });
  }

  console.log(req.body.keypair);

  const userKeypair = req.body.keypair;
  const topublickey = req.body.keypair.publicKey;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    var date = new Date();

    value.map((asset) => {
      if (asset.data.type === "firewall" && asset.data.status != "BURNED") {
        // Use existing blockchain
        assetId = asset.id;
        let newData = {
          ipAddress: req.body.ipAddress,
          source: req.body.source,
          timestamp: date.toGMTString(),
        };

        asset.data.data.push(newData);
        let dataFirewall = asset.data.data;

        const metadata = {
          type: "firewall",
          data: dataFirewall,
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          dem.publish("firewall-channel", "A new firewall data has been created, id : " + value.id);
          let firewallConfiguration = [];
          value.data.data.map((asset) => {
            firewallConfiguration.push(asset.ipAddress);
          });
          console.log("updating firewall rules to FirewallRules.json");
          firewallRules.ListOfBannedIpAddr = firewallConfiguration;
          fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
            if (err) return console.log(err);
            console.log(JSON.stringify(firewallRules));
            console.log("writing to " + fileName);
          });
          return res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      // Create new blockchain
      const metadata = {
        type: "firewall",
        data: [
          {
            ipAddress: req.body.ipAddress,
            source: req.body.source,
            timestamp: date.toGMTString(),
          },
        ],
      };
      console.log(userKeypair);
      crabService.createAsset(userKeypair, metadata).then((value) => {
        dem.publish("firewall-channel", "A new firewall data has been created, id : " + value.id);
        let firewallConfiguration = [];
        value.data.data.map((asset) => {
          firewallConfiguration.push(asset.ipAddress);
        });
        console.log("updating firewall rules to FirewallRules.json");
        firewallRules.ListOfBannedIpAddr = firewallConfiguration;
        fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
          if (err) return console.log(err);
          console.log(JSON.stringify(firewallRules));
          console.log("writing to " + fileName);
        });
        return res.json(value);
      });
    }
  });
};

exports.deleteIpAddress = function (req, res) {
  if (!req.body.keypair) {
    return res.status(400).send({ message: "keypair is required" });
  }

  const userKeypair = req.body.keypair;
  const topublickey = req.body.keypair.publicKey;
  const ipAddress = req.params.ipAddress;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "firewall" && asset.data.status != "BURNED") {
        assetId = asset.id;

        var filteredArray = asset.data.data.filter(function (e) {
          return e.ipAddress !== ipAddress;
        });

        const metadata = {
          type: "firewall",
          data: filteredArray,
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          dem.publish("firewall-channel", "A firewall data has been modified, id : " + value.id);
          let firewallConfiguration = [];
          value.data.data.map((asset) => {
            firewallConfiguration.push(asset.ipAddress);
          });
          console.log("updating firewall rules to FirewallRules.json");
          firewallRules.ListOfBannedIpAddr = firewallConfiguration;
          fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
            if (err) return console.log(err);
            console.log(JSON.stringify(firewallRules));
            console.log("writing to " + fileName);
          });
          return res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      return res.status(404).send({ message: "Firewall data not found" });
    }
  });
};

exports.findAll = function (req, res) {
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
          console.log(JSON.stringify(firewallRules));
          console.log("writing to " + fileName);
        });
        status = true;
        return res.json(asset);
      }
    });
    if (status == false) {
      let firewallConfiguration = [];
      console.log("updating firewall rules to FirewallRules.json");
      firewallRules.ListOfBannedIpAddr = firewallConfiguration;
      fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
        if (err) return console.log(err);
        console.log(JSON.stringify(firewallRules));
        console.log("writing to " + fileName);
      });
      return res.status(404).send({ message: "Firewall configuration not Found" });
    }
  });
};

exports.delete = function (req, res) {
  if (!req.body.keypair) {
    return res.status(400).send({ message: "keypair is required" });
  }

  const userKeypair = req.body.keypair;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "firewall" && asset.data.status != "BURNED") {
        assetId = asset.id;
        crabService.burnAsset(assetId, userKeypair).then((value) => {
          let firewallConfiguration = [];
          console.log("updating firewall rules to FirewallRules.json");
          firewallRules.ListOfBannedIpAddr = firewallConfiguration;
          fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
            if (err) return console.log(err);
            console.log(JSON.stringify(firewallRules));
            console.log("writing to " + fileName);
          });
          return res.status(200).send({ message: "Success burn firewall configuration with id " + value.id });
        });
        status = true;
      }
    });

    if (status == false) {
      return res.status(404).send({ message: "Firewall configuration not Found" });
    }
  });
};
