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

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    //Checking if user is new or not, if not registering
    const result = await db.query(
      "SELECT uid FROM user_data WHERE uid = $1",
      [username]
    );

    if (result.rows.length === 0) {

      await db.query("INSERT INTO user_data (uid , pwd) VALUES ($1 , $2)", [username, hashedPassword]);
      res.sendStatus(200);
    } else {
      console.log("User already exists.")
      res.sendStatus(200);
    }
  }
  catch (err) {
    console.error("Error registering user:", err);
    res.sendStatus(500);
  }
});


//LOGIN USER
app.post("/api/login", async (req, res) => {
  const username = req.body["username"];
  const password = req.body["password"];

  //Check if user is registered.
  try {
    const users = await db.query(
      "SELECT * FROM user_data WHERE uid = $1",
      [username]
    );

    if (users.rows.length !== 0) {
      const data = users.rows[0];
      const username = data.uid;
      const storedHashedPassword = data.pwd;
      const status = data.status;

      //Compare the hashed password with the user enterd password
      const result = await bcrypt.compare(password, storedHashedPassword)

      const date = new Date();

      // If password is correct:
      if (result) {
        if (status == "open") {
          console.log('Passwords match! User authenticated.');
        }
        else {
          // Checking if account lock has exceeded 24 hours
          const time_served_result = await db.query("SELECT count(uid) AS ts FROM user_data WHERE uid = $1 AND $2 - lock_time > INTERVAL '24 hours'",[username,date]);
          const time_served = parseInt(time_served_result.rows[0].ts, 10);
          // If yes -> open the account and authenticate the user.
          if(time_served == 1){
            await db.query("UPDATE user_data SET status = 'open' WHERE uid = $1", [username]);
            console.log('Passwords match! User authenticated.');
          }else{
            console.log("ACCOUNT IS LOCKED TRY AGAIN IN 24 HRS!")
          }
        }
      } else {
        // Logging the user login activity
        if (status == "open") {
          console.log('Passwords do not match! Authentication failed.');
          await db.query("INSERT INTO user_logs (login_time,uid) VALUES ($1,$2)", [date, username]);
        }
        // Getting the no. of failed attempts in the last 12 hrs.
        const failed_result = await db.query("SELECT COUNT(logid) AS fail_count FROM public.user_logs WHERE uid = $1 AND $2 - login_time < INTERVAL '12 hours' GROUP BY uid", [username, date]);
        const failed_count = parseInt(failed_result.rows[0].fail_count, 10)
        if (failed_count == 5) {
          console.log("ACCOUNT BLOCKED, TRY AGAIN IN 24 HRS!!")
          await db.query("UPDATE user_data SET status = 'locked' WHERE uid = $1", [username]);
          await db.query("UPDATE user_data SET lock_time = $1 WHERE uid = $2", [date,username]);
        } else {
          console.log("Failed Attempts: ", failed_count);
        }
      }

    } else {
      console.log("User not found!")
    }
    res.sendStatus(200);
  }
  catch (err) {
    console.error("Error during login:", err);
    res.sendStatus(500);
  }

});


app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
