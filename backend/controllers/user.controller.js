var Orm = require("bigchaindb-orm").default;

const bdbConfig = require("../configs/bigchaindb.config.json");
const URL = `${bdbConfig.host}${bdbConfig.api}`;
const bdbOrm = new Orm(URL, {
  app_id: bdbConfig.auth.app_id,
  app_key: bdbConfig.auth.app_key,
});

const config = require("../config/auth.config");

const CRABService = require("../services/CRABService");

const crabService = new CRABService("myModel");

var bcrypt = require("bcryptjs");

exports.allAccess = (req, res) => {
  res.status(200).send("Public Content.");
};

exports.getAllData = (req, res) => {
  res.status(200).send("Data firewall retrieved.");
};

exports.create = function (req, res) {
  if (!req.body.username) {
    res.status(400).send({ message: "username is required" });
  }
  if (!req.body.email) {
    res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    res.status(400).send({ message: "password is required" });
  }

  const userKeypair = new bdbOrm.driver.Ed25519Keypair();

  const metadata = {
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8),
    publicKey: userKeypair.publicKey,
    privateKey: userKeypair.privateKey,
  };

  // Verify payload received and then process it further
  crabService.createAsset(userKeypair, metadata).then((value) => {
    result = {
      username: value.data.username,
      email: value.data.email,
      publicKey: value.data.publicKey,
      privateKey: value.data.privateKey,
    };
    res.json(result);
  });
};

exports.findAll = function (req, res) {
  // Verify payload received and then process it further
  crabService.retrieveAllAssets().then((value) => {
    // res.json(value);
    res.json(value.map((asset) => asset.data));
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

  const username = req.params.username;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.username === username) {
        assetId = asset.id;
        crabService.retrieveAsset(assetId).then((value) => {
          // dem.publish("firewall-channel", value[0].id);
          res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      res.status(404).send({ message: "username Not Found" });
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
  const username = req.params.username;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.username === username) {
        assetId = asset.id;
        crabService.burnAsset(assetId, userKeypair).then((value) => {
          res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      res.status(404).send({ message: "username Not Found" });
    }
  });
};
