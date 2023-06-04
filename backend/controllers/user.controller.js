var Orm = require("bigchaindb-orm").default;

const bdbConfig = require("../configs/bigchaindb.config.json");
const URL = `${bdbConfig.host}${bdbConfig.api}`;
const bdbOrm = new Orm(URL, {
  app_id: bdbConfig.auth.app_id,
  app_key: bdbConfig.auth.app_key,
});

const config = require("../config/auth.config");

const CRABService = require("../services/CRABService");

const crabService = new CRABService("intelligentProxy");

var bcrypt = require("bcryptjs");

exports.create = function (req, res) {
  if (!req.body.username) {
    return res.status(400).send({ message: "username is required" });
  }
  if (!req.body.email) {
    return res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    return res.status(400).send({ message: "password is required" });
  }

  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        // Use existing blockchain

        status = true;
        if (!req.body.keypair) {
          return res.status(400).send({ message: "keypair is required" });
        }

        const userKeypair = req.body.keypair;
        const topublickey = req.body.keypair.publicKey;

        assetId = asset.id;

        const newUserKeypair = new bdbOrm.driver.Ed25519Keypair();

        let newData = {
          username: req.body.username,
          email: req.body.email,
          password: bcrypt.hashSync(req.body.password, 8),
          publicKey: newUserKeypair.publicKey,
          privateKey: newUserKeypair.privateKey,
        };

        asset.data.data.push(newData);
        let dataFirewall = asset.data.data;

        const metadata = {
          type: "user",
          data: dataFirewall,
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          return res.json(value);
        });
      }
    });

    if (status == false) {
      // Create new blockchain

      const userKeypair = new bdbOrm.driver.Ed25519Keypair();

      const metadata = {
        type: "user",
        data: [
          {
            username: req.body.username,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8),
            publicKey: userKeypair.publicKey,
            privateKey: userKeypair.privateKey,
          },
        ],
      };
      crabService.createAsset(userKeypair, metadata).then((value) => {
        result = {
          username: value.data.data[0].username,
          email: value.data.data[0].email,
          publicKey: value.data.data[0].publicKey,
          privateKey: value.data.data[0].privateKey,
        };
        return res.json(value);
      });
    }
  });
};

exports.deleteUsername = function (req, res) {
  if (!req.body.keypair) {
    return res.status(400).send({ message: "keypair is required" });
  }

  const userKeypair = req.body.keypair;
  const topublickey = req.body.keypair.publicKey;
  const username = req.params.username;
  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        assetId = asset.id;

        var filteredArray = asset.data.data.filter(function (e) {
          return e.username !== username;
        });

        const metadata = {
          type: "user",
          data: filteredArray,
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          return res.json(value);
        });
        status = true;
      }
    });

    if (status == false) {
      return res.status(404).send({ message: "User data not found" });
    }
  });
};

exports.findAll = function (req, res) {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    value.map((asset) => {
      if (asset.data.type == "user" && asset.data.status != "BURNED") {
        status = true;
        return res.json(asset);
      }
    });
    if (status == false) {
      return res.status(404).send({ message: "User data not Found" });
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
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        assetId = asset.id;
        crabService.burnAsset(assetId, userKeypair).then((value) => {
          return res.status(200).send({ message: "Success burn user data with id " + value.id });
        });
        status = true;
      }
    });

    if (status == false) {
      return res.status(404).send({ message: "User data not Found" });
    }
  });
};
