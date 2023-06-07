const CRABService = require("../services/CRABService");
const crabService = new CRABService("intelligentProxy");

checkDuplicateUsernameOrEmail = (req, res, next) => {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        if (asset.data.data.find((e) => e.username === req.body.username)) {
          status = true;
          return res.status(404).send({ message: "Failed! Username already in blockchain" });
        }
        if (asset.data.data.find((e) => e.email === req.body.email)) {
          status = true;
          return res.status(404).send({ message: "Failed! Email already in blockchain" });
        }
      }
    });

    if (status == false) {
      next();
    }
  });
};

checkExistingUsername = (req, res, next) => {
  crabService.retrieveAllAssets().then((value) => {
    let status = false;

    value.map((asset) => {
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        if (!asset.data.data.find((e) => e.username === req.params.username)) {
          status = true;
          return res.status(404).send({ message: "Failed! username not exist in blockchain" });
        }
      }
    });

    if (status == false) {
      next();
    }
  });
};

const verifySignUp = {
  checkDuplicateUsernameOrEmail,
  checkExistingUsername,
};

module.exports = verifySignUp;
