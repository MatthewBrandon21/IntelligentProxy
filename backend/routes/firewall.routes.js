const { authJwt } = require("../middlewares");
const controller = require("../controllers/firewall.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  app.get("/api/firewall/all", controller.allAccess);

  app.get("/api/firewall/data", [authJwt.verifyToken], controller.getAllData);

  app.post("/api/firewall", controller.create);

  app.get("/api/firewall", controller.findAll);

  app.get("/api/firewall/:assetId", controller.findOne);

  app.put("/api/firewall/:assetId", controller.update);

  app.delete("/api/firewall/:assetId", controller.delete);
};
