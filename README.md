STEPS FOR EXECUTION

1. install node modules
2. create database 'userdb' on postgreSQL using provided schema. (change password in index.js file)
3. start the node server (node index.js)
4. populate the tables and test the functionalities using postman.


FUNCTIONALITIES

1. User can register.
   - Duplicate users are not allowed.
   - Passwords are hashed and stored in the database.
2. Users can login.
   - Username and Password is verified.
   - More than 5 invalid login attempts in 12 hours result in the blocking of the account for the next 24 hours.
   - Account is unblocked again after 24 hours. 
