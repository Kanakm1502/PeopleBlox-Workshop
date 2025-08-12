import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "userdb",
  password: "root",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", async (req, res) => {
  res.render("index.ejs");
});

// REGISTER NEW USER
app.post("/api/register", async (req, res) => {
  const username = req.body["username"];
  const password = req.body["password"];

  //Encrypting the password  
  const saltRounds = 10;

  const salt = await bcrypt.genSalt(saltRounds, (err, salt) => {
    if (err) {
      console.log("Error in salt generation.");
      return;
    }
  });

  const hash = await bcrypt.hash(password, salt, (err, hash) => {
    if (err) {
      console.log("Error in hashing password!")
      return;
    }
  });

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  //Checking if user is new or not, if not registering
  const result = await db.query(
    "SELECT uid FROM user_data WHERE uid = $1",
    [username]
  );

  if (result.rows.length === 0) {

    await db.query("INSERT INTO user_data (UID , pwd) VALUES ($1 , $2)", [username, hashedPassword]);
    res.sendStatus(200);
  } else {
    console.log("User already exists.")
  }
});


//LOGIN USER
app.post("/api/login", async (req, res) => {
  const username = req.body["username"];
  const password = req.body["password"];

  //Check if user is registered.
  const users = await db.query(
    "SELECT * FROM user_data WHERE uid = $1",
    [username]
  );

  if (users.rows.length !== 0) {
    const data = users.rows[0];
    const username = data.uid;
    const storedHashedPassword = data.pwd;
    const last_login = data.last_login;

    //Compare the hashed password with the user enterd password
    const result = await bcrypt.compare(password, storedHashedPassword, (err, result) => {
      if (err) {
        console.error('Error comparing passwords:', err);
        return;
      }

      if (result) {
        console.log('Passwords match! User authenticated.');
        const date = new Date();
        var hours = Math.abs(date - last_) / 36e5;
        if(!last_login){
          console.log(date-last_login);
          db.query("UPDATE user_data SET last_login = $1 WHERE uid = $2",[date,username])
        }
      } else {
        console.log('Passwords do not match! Authentication failed.');
      }
    });
  } else {
    console.log("User not found!")
  }
  res.sendStatus(200);
});

//TIMEOUT 



app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
