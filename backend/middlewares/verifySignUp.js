const CRABService = require("../services/CRABService");

const crabService = new CRABService("myModel");

checkDuplicateUsernameOrEmail = (req, res, next) => {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;
    value.map((asset) => {
      if (asset.data.username === req.body.username) {
        status = true;
        return res.status(404).send({ message: "Failed! Username is already in use!" });
      }

      if (asset.data.email === req.body.email) {
        status = true;
        return res.status(404).send({ message: "Failed! Email is already in use!" });
      }
    });
    if (status == false) {
      next();
    }
  });
};

const verifySignUp = {
  checkDuplicateUsernameOrEmail,
};

module.exports = verifySignUp;
