const express = require("express");
const jwt = require("jsonwebtoken");
const {Pool} = require("pg");
const bcrypt = require("bcrypt");
const pool = new Pool({
  connectionString: "postgresql://neondb_owner:npg_KuyPWHbFi63N@ep-long-hill-ap5qj9vx-pooler.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
});

const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  //pass word hashing:
  const hashedPassword = await bcrypt.hash(password, 10);

// This is a very bad way to do SQL. This Is vulnerable to something called SQL injection.
  // await pool.query("INSERT INTO users (username, email, password) VALUES('" + username + "','" + email + "','" + password + "')");
// await pool.query(`INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`);

// const response = await pool.query(`INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')RETURNING id`);
// since above template is also vulnerable to SQL injection so we'll use template below
const response = await pool.query(`INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id:`, [username, email, hashedPassword]);
console.log(response);

  res.json({
    message: "signup done",
    id: response.rows[0].id
  })

});

app.post("/signin", async(req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const response = await pool.query(`SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`);
  // console.log(response);

  const userExists = response.rows[0];
  console.log(userExists);

  if(!userExists) {
      res.status(403).json({
      message: "incorrect credentials"
    })
  } else {
      const token = jwt.sign({
        userId: userExists.id
      }, "secret");

      res.json({
        token: token
    })
  }
});


app.listen(3000);