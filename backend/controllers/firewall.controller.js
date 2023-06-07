// BigchainDB ORM
const CRABService = require("../services/CRABService");
const crabService = new CRABService("intelligentProxy");

// Democracy JS
const dem = require("../services/DemocracyService");

// Firewall rules configuration
const fs = require("fs");
// Change to real firewall rules file
const fileName = "FirewallRulesClone.json";
let firewallRules = require("../../proxy/FirewallRulesClone.json");

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

  const userKeypair = req.body.keypair;
  const topublickey = req.body.keypair.publicKey;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    var date = new Date();

    value.map((asset) => {
      if (asset.data.type === "firewall" && asset.data.status != "BURNED") {
        status = true;

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
          // Publish to consensus channel
          dem.publish("firewall-channel", "A new firewall data has been created, id : " + value.id);

          // Update the firewall rules file
          let firewallConfiguration = [];
          value.data.data.map((asset) => {
            firewallConfiguration.push(asset.ipAddress);
          });
          console.log("updating firewall rules to FirewallRules.json");
          firewallRules.ListOfBannedIpAddr = firewallConfiguration;
          fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
            if (err) return console.log(err);
            // console.log(JSON.stringify(firewallRules));
            // console.log("writing to " + fileName);
          });

          return res.json(value);
        });
      }
    });

    if (status == false) {
      // Create new blockchain

      // Create new firewall data
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

      crabService.createAsset(userKeypair, metadata).then((value) => {
        // Publish to consensus channel
        dem.publish("firewall-channel", "A new firewall data has been created, id : " + value.id);

        let firewallConfiguration = [];
        value.data.data.map((asset) => {
          firewallConfiguration.push(asset.ipAddress);
        });
        console.log("updating firewall rules to FirewallRules.json");
        firewallRules.ListOfBannedIpAddr = firewallConfiguration;
        fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
          if (err) return console.log(err);
          // console.log(JSON.stringify(firewallRules));
          // console.log("writing to " + fileName);
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
        status = true;

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
            // console.log(JSON.stringify(firewallRules));
            // console.log("writing to " + fileName);
          });

          return res.json(value);
        });
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
        status = true;

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

        return res.json(asset);
      }
    });
    if (status == false) {
      // If firewall blockchain deleted

      let firewallConfiguration = [];
      console.log("updating firewall rules to FirewallRules.json");
      firewallRules.ListOfBannedIpAddr = firewallConfiguration;
      fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
        if (err) return console.log(err);
        // console.log(JSON.stringify(firewallRules));
        // console.log("writing to " + fileName);
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
        status = true;

        assetId = asset.id;

        crabService.burnAsset(assetId, userKeypair).then((value) => {
          let firewallConfiguration = [];
          console.log("updating firewall rules to FirewallRules.json");
          firewallRules.ListOfBannedIpAddr = firewallConfiguration;
          fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
            if (err) return console.log(err);
            // console.log(JSON.stringify(firewallRules));
            // console.log("writing to " + fileName);
          });

          return res.status(200).send({ message: "Success burn firewall configuration with id " + value.id });
        });
      }
    });

    if (status == false) {
      return res.status(404).send({ message: "Firewall configuration not Found" });
    }
  });
};

// exports.findAll = function (req, res) {
//   // Verify payload received and then process it further
//   crabService.retrieveAllAssets().then((value) => {
//     // res.json(value);
//     res.json(value.map((asset) => asset.data));
//     console.log(firewallRules.ListOfBannedIpAddr);
//     console.log(firewallRules.ListOfBannedIpAddr.map((ip) => ip));
//     value.map((asset) => {
//       if (firewallRules.ListOfBannedIpAddr.includes(asset.data.ipAddress) == false) {
//         if (asset.data.status != "BURNED") {
//           console.log("adding ip " + asset.data.ipAddress + " to FirewallRules.json");
//           firewallRules.ListOfBannedIpAddr.push(asset.data.ipAddress);
//           fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
//             if (err) return console.log(err);
//             console.log(JSON.stringify(firewallRules));
//             console.log("writing to " + fileName);
//           });
//         }
//         // fs.writeFileSync("../new.json", JSON.stringify(firewallRules));
//       }
//     });
//     // console.log(firewallRules.ListOfBannedIpAddr);
//     // console.log(firewallRules.ListOfBannedIpAddr.map((ip) => ip));
//     // value.map((asset) => {
//     //   if (firewallRules.ListOfBannedIpAddr.includes(asset.data.ip) == false) {
//     //     console.log("adding ip " + asset.data.ip + " to FirewallRules.json");
//     //     firewallRules.ListOfBannedIpAddr.push(asset.data.ip);
//     //     fs.writeFile(fileName, JSON.stringify(firewallRules), function writeJSON(err) {
//     //       if (err) return console.log(err);
//     //       console.log(JSON.stringify(firewallRules));
//     //       console.log("writing to " + fileName);
//     //     });
//     //     // fs.writeFileSync("../new.json", JSON.stringify(firewallRules));
//     //   }
//     // });
//   });
// };

// exports.findOne = function (req, res) {
//   // Verify payload received and then process it further

//   const ipAddress = req.params.ipAddress;
//   let assetId = null;

//   crabService.retrieveAllAssets().then((value) => {
//     let status = false;

//     value.map((asset) => {
//       if (asset.data.ipAddress === ipAddress) {
//         assetId = asset.id;
//         crabService.retrieveAsset(assetId).then((value) => {
//           // dem.publish("firewall-channel", value[0].id);
//           res.json(value);
//         });
//         status = true;
//       }
//     });

//     if (status == false) {
//       res.status(404).send({ message: "IP Address Not Found" });
//     }
//   });
// };

// exports.update = function (req, res) {
//   if (!req.body.keypair) {
//     res.status(400).send({ message: "keypair is required" });
//   }
//   if (!req.body.newIpAddress) {
//     res.status(400).send({ message: "newIpAddress is required" });
//   }
//   if (!req.body.topublickey) {
//     res.status(400).send({ message: "topublickey is required" });
//   }

//   const userKeypair = req.body.keypair;
//   const topublickey = req.body.topublickey;
//   const ipAddress = req.params.ipAddress;
//   let assetId = null;

//   crabService.retrieveAllAssets().then((value) => {
//     let status = false;

//     value.map((asset) => {
//       if (asset.data.ipAddress === ipAddress) {
//         assetId = asset.id;

//         var date = new Date();

//         const metadata = {
//           ipAddress: req.body.newIpAddress,
//           source: asset.data.source,
//           timestamp: date.toGMTString(),
//         };

//         crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
//           res.json(value);
//         });
//         status = true;
//       }
//     });

//     if (status == false) {
//       res.status(404).send({ message: "IP Address Not Found" });
//     }
//   });
// };
