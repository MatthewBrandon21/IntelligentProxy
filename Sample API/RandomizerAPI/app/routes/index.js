import express from "express";

import { getUsers, getRandomUsersCount } from "../controllers/user.js";
import { getArticle, getConstArticleCount, getRandomArticleCount } from "../controllers/article.js";
import { getRandomField, getRandomPostField } from "../controllers/random.js";

const router = express.Router();

router.get("/", (req, res) => {
  res.send("Randomizer API");
});

router.get("/api", (req, res) => {
  res.json({ message: "Success, welcome to RandomizerAPI", url: req.url });
});

router.get("/api/user", getRandomUsersCount);
router.get("/api/user/:count", getUsers);
router.get("/api/article", getRandomArticleCount);
router.get("/api/article/constant", getConstArticleCount);
router.get("/api/article/:count", getArticle);
router.post("/api/random", getRandomPostField);
router.get("/api/random/:field", getRandomField);

router.get("*", function (req, res) {
  res.status(404).json({ message: "Not Found" });
});

export default router;
