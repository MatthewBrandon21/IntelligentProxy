const { authJwt } = require("../middlewares");
const { verifySignUp } = require("../middlewares");
const controller = require("../controllers/user.controller");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, Content-Type, Accept");
    next();
  });

  // app.get("/api/user/data", [authJwt.verifyToken], controller.getAllData);

  // app.post("/api/user", [authJwt.verifyToken], [verifySignUp.checkDuplicateUsernameOrEmail], controller.create);

  // app.post("/api/user/delete/:username", [authJwt.verifyToken], [verifySignUp.checkExistingUsername], controller.deleteUsername);

  // app.get("/api/user", [authJwt.verifyToken], controller.findAll);

  // app.delete("/api/user", [authJwt.verifyToken], controller.delete);

  app.post("/api/user", [verifySignUp.checkDuplicateUsernameOrEmail], controller.create);

  app.post("/api/user/delete/:username", [verifySignUp.checkExistingUsername], controller.deleteUsername);

  app.get("/api/user", controller.findAll);

  app.delete("/api/user", controller.delete);
};
