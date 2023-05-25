const express = require("express");
const cors = require("cors");
var bodyParser = require("body-parser");
const ORMService = require("./services/ORMService");

const dem = require("./services/DemocracyService");

const app = express();
const ormService = new ORMService();

var corsOptions = {
  origin: "http://localhost:3000",
};

app.use(cors(corsOptions));

// parse requests of content-type - application/json
app.use(express.json());

// parse requests of content-type - application/x-www-form-urlencoded
// app.use(express.urlencoded({ extended: true }));
// app.use(express.urlencoded({
//   extended: false
// }));
app.use(bodyParser.urlencoded({ extended: true }));

// parse application/json
app.use(bodyParser.json());

// simple route
app.get("/", (req, res) => {
  dem.publish("my-channel", { hello: "world" });
  res.json({ message: "Backend Intelligent Proxy Server" });
});

// routes
require("./routes/auth.routes")(app);
require("./routes/user.routes")(app);
require("./routes/firewall.routes")(app);
require("./routes/proxy.routes")(app);

// set port, listen for requests
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
