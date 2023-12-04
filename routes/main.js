const bcrypt = require('bcrypt');

module.exports = function(app, blogData) {
    const redirectLogin = (req, res, next) => {
        if (!req.session.userId) {
          res.redirect('./login')
        } else { next (); }
    }

    //Handle our routes
    const fetchCategories = (req, res, next) => {
        let categoryQuery = "SELECT * FROM categories";
        db.query(categoryQuery, (err, categories) => {
            if (err) {
                // Handle the error appropriately
                console.error("Error fetching categories:", err);
                return next(err);
            }
            res.locals.categories = categories;
            next();
        });
    };
    
        app.get('/', fetchCategories, function(req, res) {
        let message = req.query.message || '';
        let data = Object.assign({}, blogData, { message: message, username: req.session.username, newUser: req.session.newUser });
    
        req.session.newUser = null; // Clear the newUser variable after rendering the page
        req.session.save(); // Make sure to save the session after modifying it
    
        // Fetch categories
        let categoryQuery = "SELECT * FROM categories";
        db.query(categoryQuery, (err, categories) => {
            if (err) throw err;
            data.categories = categories; // Assign categories to the data object
            res.render('index.ejs', data); // Render the template with the categories data
        });
    });
    
    app.get('/about', fetchCategories, function(req,res){
        let data = Object.assign({}, blogData, {username: req.session.username });
        res.render('about.ejs', data);
    });
    app.get('/search', fetchCategories, function(req, res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render("search.ejs", data);
    });
    app.get('/search-result', fetchCategories, function (req, res) {
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
    app.get('/register', fetchCategories, function (req,res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render('register.ejs', data);
    });
    app.post('/registered', fetchCategories, function (req, res) {
        const saltRounds = 10;
        const plainPassword = req.body.password;
        // Hash the password before saving it
        bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
            if (err) {
                // Handle error appropriately
                const errorMessage = 'Error hashing password.';
                return res.render('register', { message: errorMessage });
            }
            // Create SQL query to insert user data into the users table
            let sqlquery = "INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?,?,?,?,?)";
            let newrecord = [req.body.username, req.body.first, req.body.last, req.body.email, hashedPassword];
            // Execute the SQL query
            db.query(sqlquery, newrecord, (err, result) => {
                if (err) {
                    if (err.code == 'ER_DUP_ENTRY') {
                        // Duplicate entry error
                        let errorMessage = 'Username or email already exists. Please choose another.';
                        return res.render('register', { message: errorMessage, siteName: blogData.siteName, username: req.session.username });
                    } else {
                        // Handle other errors
                        let errorMessage = 'Error registering user.';
                        return res.render('register', { message: errorMessage });
                    }
                }
                // Set session variable for new user
                req.session.newUser = `${req.body.first} ${req.body.last}`;
                // Inform the user of successful registration
                const successMessage = 'Registration successful! Login to start blogging.';
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
    app.get('/login', fetchCategories, function(req, res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render('login.ejs', data);
    });
    app.post('/loggedin', fetchCategories, function(req, res) {
        let sqlquery = "SELECT id, hashedPassword FROM users WHERE username = ?";
        let username = req.body.username;

        db.query(sqlquery, [username], (err, result) => {
            if (err) {
                return res.render('index', { siteName: blogData.siteName, message: "Error during login.", username: req.session.username });
            }
            if (result.length === 0) {
                return res.render('index', { siteName: blogData.siteName, message: "No such user found.", username: req.session.username });
            }
            bcrypt.compare(req.body.password, result[0].hashedPassword, function(err, isMatch) {
                if (err) {
                    return res.render('index', { siteName: blogData.siteName, message: "Error during password comparison.", username: req.session.username });
                }
                if (isMatch) {
                    req.session.userId = result[0].id; // Store user ID
                    req.session.username = username;   // Store username

                // Render the index page with the username for display
                res.render('index', { siteName: blogData.siteName, username: username, message: `Login successful! Welcome to ${blogData.siteName}.` });
                } else {
                    res.render('index', { siteName: blogData.siteName, message: "Wrong username or password.", username: req.session.username });
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
    app.get('/logout', fetchCategories, redirectLogin, (req, res) => {
        req.session.destroy(err => {
            if (err) {
                return res.redirect('./');
            }
            res.redirect('/?message=You are now logged out.');
        });
    });

app.get('/blog', fetchCategories, function(req, res) {
    let category = req.query.category || null;
    // Initialize categoryName here to ensure it's in the right scope
    let categoryName = 'All Blog Posts'; // Default title for no specific category

    let sqlQuery = `
        SELECT p.id, p.title, p.content, p.created_at, u.username, GROUP_CONCAT(t.name SEPARATOR ', ') AS tags
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN post_tags pt ON p.id = pt.post_id
        LEFT JOIN tags t ON pt.tag_id = t.id
        LEFT JOIN categories c ON p.category_id = c.id
    `;

    if (category) {
        sqlQuery += " WHERE c.id = ?";
        // Update categoryName based on the category ID
        if (category === '1') {
            categoryName = 'Fashion Blogs';
        } else if (category === '2') {
            categoryName = 'Health and Wellness Blogs';
        }
    }

    sqlQuery += " GROUP BY p.id";

    const queryParams = category ? [category] : [];

    db.query(sqlQuery, queryParams, (err, posts) => {
        if (err) {
            console.error(err);
            return res.redirect('/error-page'); // Handle the error as per your error handling strategy
        }

        let data = Object.assign({}, blogData, {
            posts: posts,
            username: req.session.username,
            categoryName: categoryName // Pass categoryName to the EJS template
        });
        res.render('blog.ejs', data);
    });
});


app.get('/blog/:id', fetchCategories, function(req, res) {
    const postId = req.params.id;

    let sqlQuery = `
        SELECT p.id, p.title, p.content, p.created_at, u.username, GROUP_CONCAT(t.name SEPARATOR ', ') AS tags
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN post_tags pt ON p.id = pt.post_id
        LEFT JOIN tags t ON pt.tag_id = t.id
        WHERE p.id = ?
        GROUP BY p.id
    `;

    db.query(sqlQuery, [postId], (err, posts) => {
        if (err) {
            console.error(err);
            return res.redirect('/error-page'); // Redirect to an error page or handle error
        }

        if (posts.length > 0) {
            let data = Object.assign({}, blogData, { post: posts[0], username: req.session.username });
            res.render('post.ejs', data); // Render a template for the full post
        } else {
            res.render('post-not-found.ejs'); // Render a 'post not found' template or similar
        }
    });
});





app.get('/create-blog', fetchCategories, function(req, res) {
    if (!req.session.username) {
        res.redirect('/login'); // Redirect to login if not logged in
    } else {
        // Include 'siteName' when rendering the view
        let data = Object.assign({}, blogData, {username: req.session.username});
        res.render('create-blog.ejs', data);
    }
});


app.post('/submit-blog', redirectLogin, function(req, res) {
    const { title, content, category_id, tags } = req.body;
    const user_id = req.session.userId;

    // Insert the blog post first
    let sqlQuery = "INSERT INTO posts (user_id, category_id, title, content) VALUES (?, ?, ?, ?)";
    db.query(sqlQuery, [user_id, category_id, title, content], (err, result) => {
        if (err) {
            // handle error
            return res.redirect('/create-blog');
        }

        const postId = result.insertId;
        // Process tags
        const tagArray = tags.split(',').map(tag => tag.trim());
        tagArray.forEach(tag => {
            // Check if tag exists and insert if not, then link to post
            // This will require additional queries
        });

        res.redirect('/blog');
    });
});

}
