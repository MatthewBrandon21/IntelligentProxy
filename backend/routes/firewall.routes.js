const { authJwt } = require("../middlewares");
const { verifyFirewall } = require("../middlewares");
const controller = require("../controllers/firewall.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  app.get("/api/firewall/all", controller.allAccess);

  app.get("/api/firewall/data", [authJwt.verifyToken], controller.getAllData);

  app.post("/api/firewall", [verifyFirewall.checkDuplicateIpAddress], controller.create);

  app.post("/api/firewall/internal", [verifyFirewall.checkDuplicateIpAddress], controller.create);

  app.get("/api/firewall", controller.findAll);

  app.get("/api/firewall/:ipAddress", controller.findOne);

  app.put("/api/firewall/:ipAddress", controller.update);

  app.delete("/api/firewall/:ipAddress", controller.delete);
};
