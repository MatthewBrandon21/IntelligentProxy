const dbConfig = require("./config/bigchain.config");

var Orm = require("bigchaindb-orm").default;

const bdbOrm = new Orm(dbConfig.HOST, {
  app_id: APP_ID,
  app_key: APP_KEY,
});

bdbOrm.define("myModel", "https://schema.org/v1/myModel");

const aliceKeypair = new bdbOrm.driver.Ed25519Keypair();

module.exports = {
  bdbOrm,
  aliceKeypair,
};
