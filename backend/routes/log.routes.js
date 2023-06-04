const { authJwt } = require("../middlewares");
const controller = require("../controllers/log.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  // app.get("/api/log/data", [authJwt.verifyToken], controller.getAllData);

  app.post("/api/log", controller.create);

  app.get("/api/log", controller.findAll);
};
