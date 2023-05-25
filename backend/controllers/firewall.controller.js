const CRABService = require("../services/CRABService");

const dem = require("../services/DemocracyService");

const crabService = new CRABService("firewall");

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
  if (!req.body.metadata) {
    res.status(400).send({ message: "metadata is required" });
  }

  const userKeypair = req.body.keypair;
  const metadata = req.body.metadata;
  // Verify payload received and then process it further
  crabService.createAsset(userKeypair, metadata).then((value) => {
    dem.publish("firewall-channel", value.id);
    res.json(value);
  });
};

exports.findAll = function (req, res) {
  // Verify payload received and then process it further
  crabService.retrieveAllAssets().then((value) => {
    res.json(value);
  });
};

exports.findOne = function (req, res) {
  const assetid = req.params.assetId;
  // Verify payload received and then process it further
  crabService.retrieveAsset(assetid).then((value) => {
    dem.publish("firewall-channel", value[0].id);
    res.json(value);
  });
};

exports.update = function (req, res) {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.metadata) {
    res.status(400).send({ message: "metadata is required" });
  }
  if (!req.body.topublickey) {
    res.status(400).send({ message: "topublickey is required" });
  }

  const userKeypair = req.body.keypair;
  const metadata = req.body.metadata;
  const topublickey = req.body.topublickey;
  const assetid = req.params.assetid;
  crabService.appendAsset(assetid, userKeypair, topublickey, metadata).then((value) => {
    res.json(value);
  });
};

exports.delete = function (req, res) {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }

  const userKeypair = req.body.keypair;
  const assetid = req.params.assetid;
  crabService.burnAsset(assetid, userKeypair).then((value) => {
    res.json(value);
  });
};
