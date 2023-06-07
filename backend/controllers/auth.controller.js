var Orm = require("bigchaindb-orm").default;

// ORM instance for generating new user keypair
const bdbConfig = require("../configs/bigchaindb.config.json");
const URL = `${bdbConfig.host}${bdbConfig.api}`;
const bdbOrm = new Orm(URL, {
  app_id: bdbConfig.auth.app_id,
  app_key: bdbConfig.auth.app_key,
});

// Get app key
const config = require("../config/auth.config");

// BigchainDB ORM
const CRABService = require("../services/CRABService");
const crabService = new CRABService("intelligentProxy");

// JWT import
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

// Login existing user
exports.signInUser = function (req, res) {
  // Check required payload
  if (!req.body.email) {
    return res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    return res.status(400).send({ message: "password is required" });
  }

  // Get all blockchain data from intelligentProxy schema
  crabService.retrieveAllAssets().then((value) => {
    // Monitor for user data exist
    let status = false;

    value.map((asset) => {
      // find blockchain asset that store users data and not deleted ones
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        // Iterate every users data to find target user
        asset.data.data.map((asset) => {
          if (asset.email === req.body.email) {
            status = true;

            // Password checking
            var passwordIsValid = bcrypt.compareSync(req.body.password, asset.password);
            if (!passwordIsValid) {
              return res.status(401).send({
                accessToken: null,
                message: "Invalid Password!",
              });
            }

            // Creating JWT
            var token = jwt.sign({ username: asset.username, email: asset.email }, config.secret, {
              expiresIn: 86400, // 24 hours
            });

            // Return the success response
            return res.status(200).send({
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

    // If target user data not found
    if (status == false) {
      return res.status(404).send({ message: "email Not Found" });
    }
  });
};

// Create new user
exports.createUser = function (req, res) {
  // Check required payload
  if (!req.body.username) {
    return res.status(400).send({ message: "username is required" });
  }
  if (!req.body.email) {
    return res.status(400).send({ message: "email is required" });
  }
  if (!req.body.password) {
    return res.status(400).send({ message: "password is required" });
  }

  // Store user's data blockchain id
  let assetId = null;

  // Get all blockchain data
  crabService.retrieveAllAssets().then((value) => {
    // Monitor users data blockchain
    let status = false;

    // Iterate every blockchain data
    value.map((asset) => {
      // If user data is exist
      if (asset.data.type === "user" && asset.data.status != "BURNED") {
        // Use existing blockchain
        status = true;

        // If blockchain already created, to able to change the data need main user keypair (first user)
        if (!req.body.keypair) {
          return res.status(400).send({ message: "keypair is required" });
        }

        // use first user keypair and transfer to same user (keep imutable)
        const userKeypair = req.body.keypair;
        const topublickey = req.body.keypair.publicKey;

        // save current blockchain id
        assetId = asset.id;

        // This is great for immutability because only first user that only change every data in this blockchain network, but need more development and schema change
        // const newUserKeypair = new bdbOrm.driver.Ed25519Keypair();

        // For sake of research, we use first user keypair also for the new user (so new user also create new ip address, datas, etc), but please do not use on production
        const newUserKeypair = userKeypair;

        // Create new user data with password hashing
        let newData = {
          username: req.body.username,
          email: req.body.email,
          password: bcrypt.hashSync(req.body.password, 8),
          publicKey: newUserKeypair.publicKey,
          privateKey: newUserKeypair.privateKey,
        };

        // Push new data to existing array
        asset.data.data.push(newData);
        let dataUser = asset.data.data;

        // New blockchain data to append the existing ones
        const metadata = {
          type: "user",
          data: dataUser,
        };

        crabService.appendAsset(assetId, userKeypair, topublickey, metadata).then((value) => {
          return res.json(value);
        });
      }
    });

    // If blockchain for store users data not exist
    if (status == false) {
      // Create new blockchain

      // Create new keypair
      const userKeypair = new bdbOrm.driver.Ed25519Keypair();

      // Create new user data with password hashing
      // FOR NOW THE USER PUBLIC KEY AND PRIVATE KEY STORES ON DATABASE, BUT THIS NOT GOOD FOR SECURITY, THE BEST SOLUTION IS TO KEEP THE PUBLICKEY AND PRIVATEKEY INTO SEPARATE FILE THAT ONLY USER KEEP
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

        // Response with user information (publicKey and privateKey is important to create another data)
        return res.json(value);
      });
    }
  });
};
