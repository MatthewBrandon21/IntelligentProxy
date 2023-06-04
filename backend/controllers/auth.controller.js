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

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signInUser = function (req, res) {
  // Verify payload received and then process it further

  if (!req.body.email) {
    res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    res.status(400).send({ message: "password is required" });
  }

  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        asset.data.data.map((asset) => {
          if (asset.email === req.body.email) {
            status = true;
            var passwordIsValid = bcrypt.compareSync(req.body.password, asset.password);
            if (!passwordIsValid) {
              return res.status(401).send({
                accessToken: null,
                message: "Invalid Password!",
              });
            }

            var token = jwt.sign({ username: asset.username, email: asset.email }, config.secret, {
              expiresIn: 86400, // 24 hours
            });

            res.status(200).send({
              accessToken: token,
              username: asset.username,
              email: asset.email,
              keypair: {
                publicKey: asset.publicKey,
                privateKey: asset.privateKey,
              },
            });
          }
        });
      }
    });

    if (status == false) {
      res.status(404).send({ message: "email Not Found" });
    }
  });
};

exports.createUser = function (req, res) {
  if (!req.body.username) {
    res.status(400).send({ message: "username is required" });
  }
  if (!req.body.email) {
    res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    res.status(400).send({ message: "password is required" });
  }

  let assetId = null;

  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    var date = new Date();

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
        let dataUser = asset.data.data;

        const metadata = {
          type: "user",
          data: dataUser,
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
