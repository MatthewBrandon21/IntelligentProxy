const CRABService = require("../services/CRABService");

const crabService = new CRABService("intelligentProxy");

exports.create = function (req, res) {
  if (!req.body.keypair) {
    return res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.message) {
    res.status(400).send({ message: "message is required" });
  }
  if (!req.body.nodeName) {
    res.status(400).send({ message: "nodeName is required" });
  }

  const userKeypair = req.body.keypair;
  const topublickey = req.body.keypair.publicKey;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    var date = new Date();

    value.map((asset) => {
      if (asset.data.type === "log" && asset.data.status != "BURNED") {
        // Use existing blockchain
        assetId = asset.id;
        let newData = {
          nodeName: req.body.nodeName,
          message: req.body.message,
          timestamp: date.toGMTString(),
        };

        asset.data.data.push(newData);
        let dataLog = asset.data.data;

        const metadata = {
          type: "log",
          data: dataLog,
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          return res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      // Create new blockchain
      const metadata = {
        type: "log",
        data: [
          {
            nodeName: req.body.nodeName,
            message: req.body.message,
            timestamp: date.toGMTString(),
          },
        ],
      };
      crabService.createAsset(userKeypair, metadata).then((value) => {
        return res.json(value);
      });
    }
  });
};

exports.findAll = function (req, res) {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    value.map((asset) => {
      if (asset.data.type == "log" && asset.data.status != "BURNED") {
        status = true;
        return res.json(asset);
      }
    });
    if (status == false) {
      return res.status(404).send({ message: "Log data not Found" });
    }
  });
};
