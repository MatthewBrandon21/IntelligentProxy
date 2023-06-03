const CRABService = require("../services/CRABService");

const dem = require("../services/DemocracyService");

const crabService = new CRABService("myModel2");

const fs = require("fs");
const fileName = "FirewallRulesClone.json";
let firewallRules = require("../FirewallRulesClone.json");

exports.allAccess = (req, res) => {
  res.status(200).send("Public Content.");
};

exports.getAllData = (req, res) => {
  res.status(200).send("Data firewall retrieved.");
};

exports.create = function (req, res) {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.ipAddress) {
    res.status(400).send({ message: "ip address is required" });
  }
  if (!req.body.source) {
    res.status(400).send({ message: "source is required" });
  }

  var date = new Date();

  const metadata = {
    ipAddress: req.body.ipAddress,
    source: req.body.source,
    timestamp: date.toGMTString(),
  };

  const userKeypair = req.body.keypair;
  // Verify payload received and then process it further
  crabService.createAsset(userKeypair, metadata).then((value) => {
    dem.publish("firewall-channel", value.id);
    res.json(value);
  });
};

exports.findAll = function (req, res) {
  // Verify payload received and then process it further
  crabService.retrieveAllAssets().then((value) => {
    // res.json(value);
    res.json(value.map((asset) => asset.data));
    console.log(firewallRules.ListOfBannedIpAddr);
    console.log(firewallRules.ListOfBannedIpAddr.map((ip) => ip));
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
        // fs.writeFileSync("../new.json", JSON.stringify(firewallRules));
      }
    });
    // console.log(firewallRules.ListOfBannedIpAddr);
    // console.log(firewallRules.ListOfBannedIpAddr.map((ip) => ip));
    // value.map((asset) => {
    //   if (firewallRules.ListOfBannedIpAddr.includes(asset.data.ip) == false) {
    //     console.log("adding ip " + asset.data.ip + " to FirewallRules.json");
    //     firewallRules.ListOfBannedIpAddr.push(asset.data.ip);
    //     fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
    //       if (err) return console.log(err);
    //       console.log(JSON.stringify(firewallRules));
    //       console.log("writing to " + fileName);
    //     });
    //     // fs.writeFileSync("../new.json", JSON.stringify(firewallRules));
    //   }
    // });
  });
};

exports.findOne = function (req, res) {
  // Verify payload received and then process it further

  const ipAddress = req.params.ipAddress;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.ipAddress === ipAddress) {
        assetId = asset.id;
        crabService.retrieveAsset(assetId).then((value) => {
          // dem.publish("firewall-channel", value[0].id);
          res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      res.status(404).send({ message: "IP Address Not Found" });
    }
  });
};

exports.update = function (req, res) {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.newIpAddress) {
    res.status(400).send({ message: "newIpAddress is required" });
  }
  if (!req.body.topublickey) {
    res.status(400).send({ message: "topublickey is required" });
  }

  const userKeypair = req.body.keypair;
  const topublickey = req.body.topublickey;
  const ipAddress = req.params.ipAddress;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.ipAddress === ipAddress) {
        assetId = asset.id;

        var date = new Date();

        const metadata = {
          ipAddress: req.body.newIpAddress,
          source: asset.data.source,
          timestamp: date.toGMTString(),
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      res.status(404).send({ message: "IP Address Not Found" });
    }
  });
};

exports.delete = function (req, res) {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }

  const userKeypair = req.body.keypair;
  const ipAddress = req.params.ipAddress;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.ipAddress === ipAddress) {
        assetId = asset.id;
        crabService.burnAsset(assetId, userKeypair).then((value) => {
          res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      res.status(404).send({ message: "IP Address Not Found" });
    }
  });
};
