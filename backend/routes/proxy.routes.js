const { authJwt } = require("../middlewares");
const controller = require("../controllers/proxy.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  app.get("/api/proxy/all", controller.allAccess);

  app.get("/api/proxy/data", [authJwt.verifyToken], controller.getAllData);

  app.post("/api/proxy", controller.create);

  app.get("/api/proxy", controller.findAll);

  app.get("/api/proxy/:proxyId", controller.findOne);

  app.put("/api/proxy/:proxyId", controller.update);

  app.delete("/api/proxy/:proxyId", controller.delete);
};
