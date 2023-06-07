const { authJwt } = require("../middlewares");
const { verifyFirewall } = require("../middlewares");
const controller = require("../controllers/firewall.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  // app.get("/api/firewall/data", [authJwt.verifyToken], controller.getAllData);

  // app.post("/api/firewall", [authJwt.verifyToken], [verifyFirewall.checkDuplicateIpAddress], controller.create);

  // app.post("/api/firewall/internal", [verifyFirewall.checkDuplicateIpAddress], controller.create);

  // app.post("/api/firewall/delete/:ipAddress", [authJwt.verifyToken], [verifyFirewall.checkExistingIpAddress], controller.deleteIpAddress);

  // app.get("/api/firewall", [authJwt.verifyToken], controller.findAll);

  // app.delete("/api/firewall", [authJwt.verifyToken], controller.delete);

  app.post("/api/firewall", [verifyFirewall.checkDuplicateIpAddress], controller.create);

  app.post("/api/firewall/internal", [verifyFirewall.checkDuplicateIpAddress], controller.create);

  app.post("/api/firewall/delete/:ipAddress", [verifyFirewall.checkExistingIpAddress], controller.deleteIpAddress);

  app.get("/api/firewall", controller.findAll);

  app.delete("/api/firewall", controller.delete);
};
