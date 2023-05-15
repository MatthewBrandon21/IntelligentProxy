# Randomizer API

Random API response using faker and custom field.

## Features

- Generate sample user and article data
- Random data count (max 1000) or specify data count
- Custom data field with custom data count

## Used By

This project is used by Intelligent Proxy Server for generating normal network traffic scenario.

## Tech Stack

**Server:** NodeJS, Express, morgan, cors, slugify, @faker-js/faker

## Run Locally

Clone the project

Go to the project directory

Install dependencies

```bash
  npm install
```

Start the server

```bash
  npm run start
```

or for development start nodemon

```bash
  npm run dev
```

## API Reference

#### Get User with random data count (max 1000)

```http
  GET /api/user
```

#### Get User with specify data count

```http
  GET /api/user/${count}
```

| Parameter | Type  | Description                                     |
| :-------- | :---- | :---------------------------------------------- |
| `count`   | `int` | **Required**. count of data that will generated |

#### Get Article with random data count (max 1000)

```http
  GET /api/article
```

#### Get Article with fixed data

```http
  GET /api/article/constant
```

#### Get Article with specify data count

```http
  GET /api/article/${count}
```

| Parameter | Type  | Description                                     |
| :-------- | :---- | :---------------------------------------------- |
| `count`   | `int` | **Required**. count of data that will generated |

#### Get Random Field with specify data count

```http
  POST /api/random
```

| Parameter | Type     | Description                                     |
| :-------- | :------- | :---------------------------------------------- |
| `field`   | `string` | **Required**. separated with "," e.g. "id,name" |
| `count`   | `int`    | **Required**. count of data that will generated |

#### Get Random Field

```http
  GET /api/random/${field}
```

| Parameter | Type     | Description                                     |
| :-------- | :------- | :---------------------------------------------- |
| `field`   | `string` | **Required**. separated with "," e.g. "id,name" |

## Acknowledgements

- [FakerJS Documentation](https://fakerjs.dev/)
