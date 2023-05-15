import { faker } from "@faker-js/faker";

export const getRandomField = async (req, res) => {
  try {
    var responseMap = new Map();
    const arrayField = req.params.field.split(",");
    arrayField.forEach((field) => {
      responseMap.set(field, faker.string.alphanumeric(10));
    });
    res.json(Object.fromEntries(responseMap));
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

export const getRandomPostField = async (req, res) => {
  try {
    if (req.body.field == null) {
      return res.status(400).json({ message: "Request body not match" });
    }
    const dataResponse = new Array(req.body.count || 1).fill().map((e) => {
      let data = req.body.field.split(",").reduce(function (obj, str, index) {
        let value = faker.string.alphanumeric(10);
        if (str) {
          obj[str.replace(/\s+/g, "")] = value.trim();
        }
        return obj;
      }, {});
      return data;
    });
    res.json(dataResponse);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};
