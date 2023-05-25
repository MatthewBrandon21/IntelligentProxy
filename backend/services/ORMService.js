const Orm = require("bigchaindb-orm").default;
const bdbConfig = require("../configs/bigchaindb.config.json");
const assetConfig = require("../configs/asset.config.json");

let instance = null;

class ORMService {
  constructor() {
    if (!instance) {
      instance = this;
      this.assets = [];
      this.setupORM();
    }
    return instance;
  }

  setupORM() {
    const URL = `${bdbConfig.host}${bdbConfig.api}`;
    this.bdbORM = bdbConfig.auth.required
      ? new Orm(URL, {
          app_id: bdbConfig.auth.app_id,
          app_key: bdbConfig.auth.app_key,
        })
      : new Orm(URL);
    for (const asset of assetConfig.assets) {
      this.bdbORM.define(asset.name, asset.schema);
      this.assets.push(asset.name);
    }
  }

  getModel(assetName) {
    return this.bdbORM.models[assetName];
  }
}

module.exports = ORMService;
