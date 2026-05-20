const express = require("express");
const jwt = require("jsonwebtoken");
const {Pool} = require("pg");
const bcrypt = require("bcrypt");
const z = require("zod");
const pool = new Pool({
  connectionString: "postgresql://neondb_owner:npg_KuyPWHbFi63N@ep-long-hill-ap5qj9vx-pooler.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
});

const app = express();
app.use(express.json());

const SignupSchema = z.object({
  username: z.string().min(3),
  email: z.email(),
  password: z.string().min(8)
})

app.post("/signup", async (req, res) => {
  const { data, success, error } = SignupSchema.safeParse(req.body);
  if(!success) {
    res.status(403).json({
      message: "incorrect inputs",
      error: JSON.parse(error)
    });
    return;
  }
  // if type check was a success then data will be equal to req.body object
  // hence we can replace the req.body with data
  // although we can keep the req.body but its a good practice to replace it with data
  const username = data.username;
  const email = data.email;
  const password = data.password;

  //pass word hashing:
  const hashedPassword = await bcrypt.hash(password, 10);

// This is a very bad way to do SQL. This Is vulnerable to something called SQL injection.
  // await pool.query("INSERT INTO users (username, email, password) VALUES('" + username + "','" + email + "','" + password + "')");
// await pool.query(`INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`);

// const response = await pool.query(`INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')RETURNING id`);
// since above template is also vulnerable to SQL injection so we'll use template below
const response = await pool.query(`INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id`, [username, email, hashedPassword]);
console.log(response);

  res.json({
    message: "signup done",
    id: response.rows[0].id
  })

});

app.post("/signin", async(req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // const response = await pool.query(`SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`);
  // removed password as the pass entered by the user here is different from one that is stored in the database (its a hashed version of the pass entered by the user)
  // Q. ham dobara se hashedPassword = await bcrypt.hash(password, 10) se hashed password kyun nahi bana rahe? 
  // A. eysa karne se hame wo hash string nahi millegi jo hame signup end point pr mill rahi thi, kyunki dono ka salt different hoga
  // isliye ham email ka use karke user ki details layenge fhir agar wo exist karta hoga to bcrypt ka use karke "password" ko "hashed password" se compare karenge
  const response = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]); 
  // console.log(response);
  const userExists = response.rows[0];
  console.log(userExists);

  if(!userExists) {
      res.status(403).json({
      message: "incorrect credentials"
    })
  } else {
      const correctPassword = await bcrypt.compare(password, userExists.password);
      // .compare returns a boolean
      if(correctPassword) {
        const token = jwt.sign({
          userId: userExists.id
        }, "secret");

        res.json({
          token: token
        })
      } else {
        res.json({
          message: "invalid credentials"
        })
      }
  }
});


app.listen(3000);