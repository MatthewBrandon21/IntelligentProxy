import { faker } from "@faker-js/faker";
import slugify from "slugify";

function createRandomArticle() {
  const categoryId = faker.number.int();
  const userId = faker.string.alphanumeric(10);
  const title = faker.word.words(faker.number.int({ max: 5 }));
  const slug = slugify(title);
  const image = faker.image.urlLoremFlickr({ category: "cats" });
  const excerpt = faker.lorem.text();
  const body = faker.lorem.paragraphs(faker.number.int({ max: 50 }), "<br/>\n");
  const isPublished = faker.helpers.arrayElement(["true", "false"]);
  const createdAt = faker.date.anytime();
  const updatedAt = faker.date.future({ refDate: createdAt });
  const publishedAt = faker.date.future({ refDate: updatedAt });

  return {
    categoryId,
    userId,
    title,
    slug,
    image,
    excerpt,
    body,
    isPublished,
    createdAt,
    updatedAt,
    publishedAt,
  };
}

function createConstArticle() {
  const categoryId = 1902011786199040;
  const userId = "RjvZbjq48A";
  const title = "scald since dwindle windscreen sustenance";
  const slug = "scald-since-dwindle-windscreen-sustenance";
  const image = "https://loremflickr.com/640/480/cats?lock=115432249884672";
  const excerpt = "Repudiandae magnam modi voluptatem maiores ad unde quo alias quia. Ea temporibus dolores. Expedita voluptates totam cum quod adipisci laborum error doloribus. Alias sint vel laboriosam odio voluptate.";
  const body = "Repudiandae magnam modi voluptatem maiores ad unde quo alias quia. Ea temporibus dolores. Expedita voluptates totam cum quod adipisci laborum error doloribus. Alias sint vel laboriosam odio voluptate.";
  const isPublished = "true";
  const createdAt = "2023-10-15T15:06:21.564Z";
  const updatedAt = "2024-10-12T18:40:29.855Z";
  const publishedAt = "2025-06-06T19:56:47.058Z";

  return {
    categoryId,
    userId,
    title,
    slug,
    image,
    excerpt,
    body,
    isPublished,
    createdAt,
    updatedAt,
    publishedAt,
  };
}

export const getArticle = async (req, res) => {
  try {
    const count = parseInt(req.params.count);
    const data = new Array(count || 1).fill().map((e) => createRandomArticle());
    res.json({
      data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

export const getRandomArticleCount = async (req, res) => {
  try {
    const count = faker.number.int({ max: 1000 });
    const data = new Array(count || 1).fill().map((e) => createRandomArticle());
    res.json({
      data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

export const getConstArticleCount = async (req, res) => {
  try {
    const data = new Array(1).fill().map((e) => createConstArticle());
    res.json({
      data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};
