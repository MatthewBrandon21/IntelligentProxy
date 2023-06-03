const CRABService = require("../services/CRABService");

const crabService = new CRABService("myModel2");

checkDuplicateIpAddress = (req, res, next) => {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    value.map((asset) => {
      if (asset.data.ipAddress === req.body.ipAddress) {
        status = true;
        return res.status(404).send({ message: "Failed! Ip address already in blockchain" });
      }
    });
    if (status == false) {
      next();
    }
  });
};

const verifyFirewall = {
  checkDuplicateIpAddress,
};

module.exports = verifyFirewall;
