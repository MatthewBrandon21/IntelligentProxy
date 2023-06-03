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

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
  if (!req.body.keypair) {
    res.status(400).send({ message: "keypair is required" });
  }
  if (!req.body.username) {
    res.status(400).send({ message: "username is required" });
  }
  if (!req.body.email) {
    res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    res.status(400).send({ message: "password is required" });
  }

  var data = { username: req.body.username, email: req.body.email, password: bcrypt.hashSync(req.body.password, 8) };

  const userKeypair = req.body.keypair;
  // Verify payload received and then process it further
  crabService.createAsset(userKeypair, data).then((value) => {
    res.json(value);
  });
};

exports.signin = (req, res) => {
  var userAll = crabService.retrieveAllAssets();

  for (let val of userAll) {
    var passwordIsValid = bcrypt.compareSync(req.body.password, val.data.password);

    if (!passwordIsValid) {
      return res.status(401).send({
        accessToken: null,
        message: "Invalid Password!",
      });
    }

    var token = jwt.sign({ id: val.id }, config.secret, {
      expiresIn: 86400, // 24 hours
    });

    res.status(200).send({
      accessToken: token,
    });
  }
};

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
      if (asset.data.email === req.body.email) {
        status = true;
        var passwordIsValid = bcrypt.compareSync(req.body.password, asset.data.password);
        if (!passwordIsValid) {
          return res.status(401).send({
            accessToken: null,
            message: "Invalid Password!",
          });
        }

        if (asset.data.status === "BURNED") {
          return res.status(401).send({
            accessToken: null,
            message: "User Deleted!",
          });
        }

        var token = jwt.sign({ id: asset.id, username: asset.data.username, email: asset.data.email }, config.secret, {
          expiresIn: 86400, // 24 hours
        });

        res.status(200).send({
          accessToken: token,
        });
      }
    });

    if (status == false) {
      res.status(404).send({ message: "username Not Found" });
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
