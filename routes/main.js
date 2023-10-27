const bcrypt = require('bcrypt');

module.exports = function(app, shopData) {
    const redirectLogin = (req, res, next) => {
        if (!req.session.userId ) {
          res.redirect('./login')
        } else { next (); }
    }

    // Handle our routes
    app.get('/',function(req,res){
        res.render('index.ejs', shopData)
    });
    app.get('/about',function(req,res){
        res.render('about.ejs', shopData);
    });
    app.get('/search',function(req,res){
        res.render("search.ejs", shopData);
    });
    app.get('/search-result', function (req, res) {
        //searching in the database
        //res.send("You searched for: " + req.query.keyword);

        let sqlquery = "SELECT * FROM books WHERE name LIKE '%" + req.query.keyword + "%'"; // query database to get all the books
        // execute sql query
        db.query(sqlquery, (err, result) => {
            if (err) {
                res.redirect('./');
            }
            let newData = Object.assign({}, shopData, {availableBooks:result});
            console.log(newData)
            res.render("list.ejs", newData)
         });
    });
    app.get('/register', function (req,res) {
        res.render('register.ejs', shopData);
    });
    app.post('/registered', function (req,res) {
        const saltRounds = 10;
        const plainPassword = req.body.password;
        // Hash the password before saving it
        bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
            if (err) {
                // Handle error appropriately
                return res.status(500).send('Error hashing password.');
            }
            // Create SQL query to insert user data into the users table
            let sqlquery = "INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?,?,?,?,?)";
            // Prepare the record to be inserted
            let newrecord = [req.body.username, req.body.first, req.body.last, req.body.email, hashedPassword];
            // Execute the SQL query
            db.query(sqlquery, newrecord, (err, result) => {
                if (err) {
                    // Handle the error appropriately
                    return res.status(500).send('Error registering user.');
                }
                // Inform the user of successful registration
                let responseText = 'Hello '+ req.body.first + ' '+ req.body.last +' you are now registered!  We will send an email to you at ' + req.body.email;
                responseText += ' Your password is: '+ plainPassword +' and your hashed password is: '+ hashedPassword;
                res.send(responseText);
            });
        });
    });
    app.get('/listusers', redirectLogin, function(req, res) {
        let sqlquery = "SELECT username, first_name, last_name, email FROM users"; // query database to get all the users without passwords
        // execute sql query
        db.query(sqlquery, (err, result) => {
            if (err) {
                res.redirect('./');
            }
            let userData = Object.assign({}, shopData, { users: result });
            console.log(userData)
            res.render("listusers.ejs", userData)
        });
    });
    app.get('/login', function(req, res) {
        res.render('login.ejs', shopData);
    });
    app.post('/loggedin', function(req, res) {
        let sqlquery = "SELECT hashedPassword FROM users WHERE username = ?";
        let username = req.body.username;
        // Query the database to find the hashed password associated with the username
        db.query(sqlquery, [username], (err, result) => {
            if (err) {
                return res.status(500).send('Error during login.');
            }
            if (result.length === 0) { // No user found
                return res.send('No such user found.');
            }
            // Compare the input password with the stored hashed password using bcrypt
            bcrypt.compare(req.body.password, result[0].hashedPassword, function(err, isMatch) {
                if (err) {
                    return res.status(500).send('Error during password comparison.');
                }
                if (isMatch) {
                    // Save user session here, when login is successful
                    req.session.userId = req.body.username;
                    res.send('Login successful! <a href=' + './' + '>Home</a>');
                } else {
                    res.send('Wrong username or password.');
                }
            });
        });
    });
    app.get('/deleteuser', redirectLogin, function (req, res) {
        res.render('deleteuser.ejs', shopData);
    });
    app.post('/userdeleted', function (req, res) {
        let username = req.body.username;
        let sqlquery = "DELETE FROM users WHERE username = ?";
        db.query(sqlquery, [username], (err, result) => {
            if (err) {
                return res.status(500).send('Error deleting user.');
            }
            if (result.affectedRows === 0) { // No user found
                return res.send('No such user found.');
            } else {
                res.send('User ' + username + ' deleted successfully.');
            }
        });
    });
    app.get('/logout', redirectLogin, (req,res) => {
        req.session.destroy(err => {
        if (err) {
          return res.redirect('./')
        }
        res.send('you are now logged out. <a href='+'./'+'>Home</a>');
        });
    });
}
