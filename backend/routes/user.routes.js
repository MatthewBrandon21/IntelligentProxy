const { authJwt } = require("../middlewares");
const { verifySignUp } = require("../middlewares");
const controller = require("../controllers/user.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  app.get("/api/user/all", controller.allAccess);

  app.get("/api/user/data", [authJwt.verifyToken], controller.getAllData);

  app.post("/api/user", [verifySignUp.checkDuplicateUsernameOrEmail], controller.create);

  app.get("/api/user", controller.findAll);

  app.get("/api/user/:username", controller.findOne);

  app.put("/api/user/:username", controller.update);

  app.delete("/api/user/:username", controller.delete);
};
