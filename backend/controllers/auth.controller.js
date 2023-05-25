const config = require("../config/auth.config");

const CRABService = require("../services/CRABService");

const crabService = new CRABService("user");

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
