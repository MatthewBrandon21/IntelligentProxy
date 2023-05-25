var connect = require("../../database/connect.bigchaindb.js");

connect.bdbOrm.models.myModel.retrieve("4a2ca33e:20a1dfb1-d9b9-4fe0-a4aa-012f5d34380a").then((assets) => {
  // assets is an array of myModel
  console.log(assets.map((asset) => asset.id));
});
