const CRABService = require("../services/CRABService");

const crabService = new CRABService("myModel3");

exports.allAccess = (req, res) => {
  res.status(200).send("Public Content.");
};

exports.getAllData = (req, res) => {
  res.status(200).send("Data log retrieved.");
};

exports.create = function (req, res) {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.message) {
    res.status(400).send({ message: "message is required" });
  }
  if (!req.body.nodeName) {
    res.status(400).send({ message: "nodeName is required" });
  }

  var date = new Date();

  const metadata = {
    nodeName: req.body.nodeName,
    message: req.body.message,
    timestamp: date.toGMTString(),
  };

  const userKeypair = req.body.keypair;
  // Verify payload received and then process it further
  crabService.createAsset(userKeypair, metadata).then((value) => {
    res.json(value);
  });
};

exports.findAll = function (req, res) {
  // Verify payload received and then process it further
  crabService.retrieveAllAssets().then((value) => {
    // res.json(value);
    res.json(value.map((asset) => asset.data));
  });
};
