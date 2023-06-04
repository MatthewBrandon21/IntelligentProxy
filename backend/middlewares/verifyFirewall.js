const CRABService = require("../services/CRABService");

const crabService = new CRABService("intelligentProxy");

checkDuplicateIpAddress = (req, res, next) => {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    value.map((asset) => {
      if (asset.data.type === "firewall" && asset.data.status != "BURNED") {
        if (asset.data.data.find((e) => e.ipAddress === req.body.ipAddress)) {
          status = true;
          return res.status(404).send({ message: "Failed! Ip address already in blockchain" });
        }
      }
    });
    if (status == false) {
      next();
    }
  });
};

checkExistingIpAddress = (req, res, next) => {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    value.map((asset) => {
      if (asset.data.type === "firewall" && asset.data.status != "BURNED") {
        if (!asset.data.data.find((e) => e.ipAddress === req.params.ipAddress)) {
          status = true;
          return res.status(404).send({ message: "Failed! Ip address not exist in blockchain" });
        }
      }
    });
    if (status == false) {
      next();
    }
  });
};

const verifyFirewall = {
  checkDuplicateIpAddress,
  checkExistingIpAddress,
};

module.exports = verifyFirewall;
