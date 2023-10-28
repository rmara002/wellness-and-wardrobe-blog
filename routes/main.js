const bcrypt = require('bcrypt');

module.exports = function(app, blogData) {
    const redirectLogin = (req, res, next) => {
        if (!req.session.userId ) {
          res.redirect('./login')
        } else { next (); }
    }

    // Handle our routes
    // app.get('/', function(req, res) {
    //     let data = Object.assign({}, blogData, { message: '', username: req.session.userId });
    //     res.render('index.ejs', data);
    // });
    app.get('/', function(req, res) {
        let message = req.query.message || '';  
        let data = Object.assign({}, blogData, { message: message, username: req.session.userId, newUser: req.session.newUser });
        res.render('index.ejs', data);
        req.session.newUser = null; // Clear the newUser variable after rendering the page
        req.session.save(); // Make sure to save the session after modifying it
    });
    app.get('/about',function(req,res){
        let data = Object.assign({}, blogData, {username: req.session.userId });
        res.render('about.ejs', data);
    });
    app.get('/search', function(req, res) {
        let data = Object.assign({}, blogData, { username: req.session.userId });
        res.render("search.ejs", data);
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
            let newData = Object.assign({}, blogData, {availableBooks:result});
            console.log(newData)
            res.render("list.ejs", newData)
         });
    });
    app.get('/register', function (req,res) {
        let data = Object.assign({}, blogData, { username: req.session.userId });
        res.render('register.ejs', data);
    });
    app.post('/registered', function (req, res) {
        const saltRounds = 10;
        const plainPassword = req.body.password;
        // Hash the password before saving it
        bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
            if (err) {
                // Handle error appropriately
                const errorMessage = encodeURIComponent('Error hashing password.');
                return res.redirect(`/?message=${errorMessage}`);
            }
            // Create SQL query to insert user data into the users table
            let sqlquery = "INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?,?,?,?,?)";
            // Prepare the record to be inserted
            let newrecord = [req.body.username, req.body.first, req.body.last, req.body.email, hashedPassword];
            // Execute the SQL query
            db.query(sqlquery, newrecord, (err, result) => {
                if (err) {
                    // Handle the error appropriately
                    const errorMessage = encodeURIComponent('Error registering user.');
                    return res.redirect(`/?message=${errorMessage}`);
                }
                // Set session variable for new user
                req.session.newUser = `${req.body.first} ${req.body.last}`;
                // Inform the user of successful registration
                const successMessage = encodeURIComponent('Registration successful! Login to start blogging.');
                res.redirect(`/?message=${successMessage}`);
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
            let userData = Object.assign({}, blogData, { users: result });
            console.log(userData)
            res.render("listusers.ejs", userData)
        });
    });
    app.get('/login', function(req, res) {
        let data = Object.assign({}, blogData, { username: req.session.userId });
        res.render('login.ejs', data);
    });
    app.post('/loggedin', function(req, res) {
        let sqlquery = "SELECT hashedPassword FROM users WHERE username = ?";
        let username = req.body.username;
        db.query(sqlquery, [username], (err, result) => {
            if (err) {
                return res.render('index', { siteName: blogData.siteName, message: "Error during login.", username: req.session.userId });
            }
            if (result.length === 0) {
                return res.render('index', { siteName: blogData.siteName, message: "No such user found.", username: req.session.userId });
            }
            bcrypt.compare(req.body.password, result[0].hashedPassword, function(err, isMatch) {
                if (err) {
                    return res.render('index', { siteName: blogData.siteName, message: "Error during password comparison.", username: req.session.userId });
                }
                if (isMatch) {
                    req.session.userId = req.body.username;
                    res.render('index', { siteName: blogData.siteName, username: req.session.userId, message: `Login successful! Welcome to ${blogData.siteName}.` });
                } else {
                    res.render('index', { siteName: blogData.siteName, message: "Wrong username or password.", username: req.session.userId });
                }
            });
        });
    });
    app.get('/deleteuser', redirectLogin, function (req, res) {
        res.render('deleteuser.ejs', blogData);
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
    app.get('/logout', redirectLogin, (req, res) => {
        req.session.destroy(err => {
            if (err) {
                return res.redirect('./');
            }
            res.redirect('/?message=You are now logged out.');
        });
    });
}
