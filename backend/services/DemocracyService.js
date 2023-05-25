const CRABService = require("../services/CRABService");
var Democracy = require("democracy");

const crabService = new CRABService("firewall");

var dem = new Democracy({
  source: "0.0.0.0:5000",
  peers: ["0.0.0.0:5000", "0.0.0.0:5001", "0.0.0.0:5002"],
});

dem.on("added", function (data) {
  console.log("Added: ", data);
});

dem.on("removed", function (data) {
  console.log("Removed: ", data);
});

dem.on("elected", function (data) {
  console.log("You are elected leader!");
});

dem.on("leader", function (data) {
  console.log("New Leader: ", data);
});

// Support for custom events.
dem.on("ciao", (data) => {
  console.log(data.hello); // Logs 'world'
});

dem.send("ciao", { hello: "world" });

// Support for basic pub/sub.
dem.on("my-channel", (data) => {
  console.log(data.hello); // Logs 'world'
});

dem.subscribe("my-channel");
dem.publish("my-channel", { hello: "world" });

// Support for basic pub/sub.
dem.on("firewall-channel", (msg) => {
  console.log(msg); // Logs 'world'
  crabService.retrieveAsset(msg).then((value) => {
    console.log(value);
  });
});

dem.subscribe("firewall-channel");

module.exports = dem;
