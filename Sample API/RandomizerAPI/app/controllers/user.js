import { faker } from "@faker-js/faker";

function createRandomUser() {
  const sex = faker.person.sexType();
  const firstName = faker.person.firstName(sex);
  const lastName = faker.person.lastName();
  const email = faker.internet.email({ firstName, lastName });
  const zodiac = faker.person.zodiacSign();
  const job = faker.person.jobTitle();
  const bio = faker.person.bio();

  return {
    _id: faker.number.int(),
    avatar: faker.image.avatar(),
    birthday: faker.date.birthdate(),
    email,
    firstName,
    lastName,
    sex,
    subscriptionTier: faker.helpers.arrayElement(["free", "basic", "business"]),
    zodiac,
    job,
    bio,
  };
}

export const getUsers = async (req, res) => {
  try {
    const count = parseInt(req.params.count);
    const data = new Array(count || 1).fill().map((e) => createRandomUser());
    res.json({
      data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

export const getRandomUsersCount = async (req, res) => {
  try {
    const count = faker.number.int({ max: 1000 });
    const data = new Array(count || 1).fill().map((e) => createRandomUser());
    res.json({
      data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};
