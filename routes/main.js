const bcrypt = require('bcrypt');
const { check, validationResult } = require('express-validator');

module.exports = function (app, blogData) {
    const redirectLogin = (req, res, next) => {
        if (!req.session.userId) {
            res.redirect('./login')
        } else { next(); }
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

    // Homepage Route
    app.get('/', fetchCategories, function (req, res) {
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

    // Route for the Blog's About Section
    app.get('/about', fetchCategories, function (req, res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render('about.ejs', data);
    });

    // Route for the Blog's Search
    app.get('/search', fetchCategories, function (req, res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render("search.ejs", data);
    });

    // Route for the Blog's Search-result
    app.get('/search-result', fetchCategories, function (req, res) {
        // Sanitize the search keyword to prevent SQL injection
        let keyword = req.sanitize(req.query.keyword);
        let returnCategory = '';

        let sqlQuery = `
        SELECT posts.*, users.username, categories.name AS categoryName, categories.id AS categoryId,
               GROUP_CONCAT(DISTINCT tags.name SEPARATOR ', ') AS tags
        FROM posts
        INNER JOIN users ON posts.user_id = users.id
        LEFT JOIN categories ON posts.category_id = categories.id
        LEFT JOIN post_tags ON posts.id = post_tags.post_id
        LEFT JOIN tags ON post_tags.tag_id = tags.id
        WHERE posts.title LIKE '%${keyword}%' OR posts.content LIKE '%${keyword}%'
           OR categories.name LIKE '%${keyword}%' OR tags.name LIKE '%${keyword}%'
        GROUP BY posts.id
        `;

        // Execute the SQL query
        db.query(sqlQuery, (err, posts) => {
            if (err) {
                console.error(err);
                res.render("search-result.ejs", { errorMessage: "An error occurred while processing your request. Please try again later." });
            } else {
                let isAdmin = req.session.username === 'admin'; // Check if the user is 'admin'
                let data = Object.assign({}, blogData, {
                    username: req.session.username,
                    currentUserId: req.session.userId,
                    isAdmin: isAdmin,
                    searchResults: posts,
                    searchKeyword: keyword,
                    returnCategory: returnCategory
                });
                res.render("search-results.ejs", data);
            }
        });
    });

    // Route for the Blog's Search by Tag
    app.get('/search-by-tag/:tagName', fetchCategories, function (req, res) {
        const tagName = req.params.tagName;
        let returnCategory = '';

        let sqlQuery = `
    SELECT posts.*, users.username, categories.name as categoryName, GROUP_CONCAT(DISTINCT tags.name SEPARATOR ', ') AS tags
    FROM posts
    INNER JOIN users ON posts.user_id = users.id
    INNER JOIN categories ON posts.category_id = categories.id
    INNER JOIN post_tags ON posts.id = post_tags.post_id
    INNER JOIN tags ON post_tags.tag_id = tags.id
    WHERE tags.name = ?
    GROUP BY posts.id
    `;

        db.query(sqlQuery, [tagName], (err, posts) => {
            if (err) {
                console.error(err);
                res.render("search-result.ejs", { errorMessage: "An error occurred while processing your request. Please try again later." });
            }

            let isAdmin = req.session.username === 'admin'; // Check if the user is 'admin'
            let data = Object.assign({}, blogData, {
                username: req.session.username,
                currentUserId: req.session.userId,
                isAdmin: isAdmin,
                searchResults: posts,
                searchKeyword: tagName,
                returnCategory: returnCategory
            });

            res.render("search-results.ejs", data);
        });
    });

    // Blog User Registration Route
    app.get('/register', fetchCategories, function (req, res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render('register.ejs', data);
    });
    const registrationValidationRules = [
        check('first').not().isEmpty().withMessage('First name is required'),
        check('last').not().isEmpty().withMessage('Last name is required'),
        check('email').isEmail().withMessage('Email is invalid'),
        check('username').not().isEmpty().withMessage('Username is required'),
        check('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long')
            .matches(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W])/)
            .withMessage('Password must contain at least one number, one uppercase and lowercase letter, one special character'),
        check('confirm-password').custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Password confirmation does not match password');
            }
            return true;
        }),
    ];

    // Blog User Registered Route
    app.post('/registered', fetchCategories, registrationValidationRules, function (req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('register', { errors: errors.array() });
        }
        else {
            // Sanitize all input fields
            const firstName = req.sanitize(req.body.first);
            const lastName = req.sanitize(req.body.last);
            const email = req.sanitize(req.body.email);
            const username = req.sanitize(req.body.username);
            const plainPassword = req.sanitize(req.body.password);
            const saltRounds = 10;

            // Hash the password before saving it
            bcrypt.hash(plainPassword, saltRounds, function (err, hashedPassword) {
                if (err) {
                    const errorMessage = 'Error hashing password.';
                    return res.render('register', { message: errorMessage });
                }
                // Create SQL query to insert user data into the users table
                let sqlquery = "INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?,?,?,?,?)";
                let newrecord = [username, firstName, lastName, email, hashedPassword];

                // Execute the SQL query
                db.query(sqlquery, newrecord, (err, result) => {
                    if (err) {
                        if (err.code == 'ER_DUP_ENTRY') {
                            // Duplicate entry error
                            let errorMessage = 'Username or email already exists. Please choose another.';
                            return res.render('register', { message: errorMessage, siteName: blogData.siteName, username: req.session.username });
                        } else {
                            // Other errors
                            let errorMessage = 'Error registering user.';
                            return res.render('register', { message: errorMessage });
                        }
                    }
                    // Set session variable for new user
                    req.session.newUser = `${firstName} ${lastName}`;

                    // Inform the user of successful registration
                    let successMessage = `Hello ${firstName} ${lastName}! Registration successful! Login to start blogging. We will send an email to you at ${email}`;
                    //successMessage += ` Your password is: ${plainPassword} and your hashed password is: ${hashedPassword}`;

                    // Encode the message for URL
                    const encodedMessage = encodeURIComponent(successMessage);

                    // Redirect to the homepage with the message
                    res.redirect(`/?message=${encodedMessage}`);

                });
            });
        }
    });

    // Route for the Blog's List of Users
    app.get('/listusers', redirectLogin, fetchCategories, function (req, res) {
        if (req.session.username !== 'admin') {
            return res.status(403).send('Access denied');
        }
        let sqlquery = "SELECT username, first_name, last_name, email FROM users";
        // execute sql query
        db.query(sqlquery, (err, result) => {
            if (err) {
                res.redirect('./');
            }
            let userData = Object.assign({}, blogData, { users: result, username: req.session.username });
            console.log(userData)
            res.render("listusers.ejs", userData)
        });
    });

    // Login Route
    app.get('/login', fetchCategories, function (req, res) {
        let data = Object.assign({}, blogData, { username: req.session.username });
        res.render('login.ejs', data);
    });

    // Logged In Route
    app.post('/loggedin', fetchCategories, function (req, res) {
        let sqlquery = "SELECT id, hashedPassword FROM users WHERE username = ?";
        let username = req.sanitize(req.body.username);
        let password = req.sanitize(req.body.password);

        db.query(sqlquery, [username], (err, result) => {
            if (err) {
                return res.render('login', { siteName: blogData.siteName, message: "Error during login.", username: req.session.username });
            }
            if (result.length === 0) {
                return res.render('login', { siteName: blogData.siteName, message: "No such user found.", username: req.session.username });
            }
            bcrypt.compare(req.body.password, result[0].hashedPassword, function (err, isMatch) {
                if (err) {
                    return res.render('login', { siteName: blogData.siteName, message: "Error during password comparison.", username: req.session.username });
                }
                if (isMatch) {
                    req.session.userId = result[0].id; // Store user ID
                    req.session.username = username;   // Store username

                    // Renders the index page with the username for display
                    res.render('index', { siteName: blogData.siteName, username: username, message: `Login successful! Welcome to ${blogData.siteName}.` });
                } else {
                    res.render('login', { siteName: blogData.siteName, message: "Wrong username or password.", username: req.session.username });
                }
            });
        });
    });

    // User Deletion Route
    app.get('/deleteuser', redirectLogin, fetchCategories, function (req, res) {
        if (req.session.username !== 'admin') {
            return res.status(403).send('Access denied');
        }
        let message = req.query.message || '';
        let data = Object.assign({}, blogData, { username: req.session.username, message: message });
        res.render('deleteuser.ejs', data);
    });

    // User Deleted Route
    app.post('/userdeleted', function (req, res) {
        if (req.session.username !== 'admin') {
            return res.status(403).send('Access denied');
        }
        let username = req.sanitize(req.body.username);
        let sqlquery = "DELETE FROM users WHERE username = ?";
        db.query(sqlquery, [username], (err, result) => {
            if (err) {
                return res.status(500).send('Error deleting user.');
            }
            if (result.affectedRows === 0) { // No user found
                res.redirect('/deleteuser?message=No such user found.');
            } else {
                res.redirect('/deleteuser?message=User ' + encodeURIComponent(username) + ' deleted successfully.');
            }
        });
    });

    // Logout Route
    app.get('/logout', fetchCategories, redirectLogin, (req, res) => {
        req.session.destroy(err => {
            if (err) {
                return res.redirect('./');
            }
            res.redirect('/?message=You are now logged out.');
        });
    });

    // List of Blog Posts Route
    app.get('/blog', fetchCategories, function (req, res) {
        let categoryFilter = req.query.category;
        let categoryName = 'All Blog Posts'; // Default title for no specific category
        let messageBlogDeleted = req.query.messageBlogDeleted;
        let currentUserId = req.session.userId; // currentUserId is obtained from the session

        const isAdmin = req.session.username === 'admin'; // Check if the logged-in user is 'admin'

        let sqlQuery = `
            SELECT p.id, p.user_id, p.title, p.content, p.created_at, p.last_updated_at, 
                   u.username, c.name AS categoryName, c.id AS categoryId,
                   GROUP_CONCAT(t.name SEPARATOR ', ') AS tags
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN post_tags pt ON p.id = pt.post_id
            LEFT JOIN tags t ON pt.tag_id = t.id
            `;

        if (categoryFilter) {
            sqlQuery += " WHERE c.id = ?";
            if (categoryFilter === '1') {
                categoryName = 'Fashion Blogs';
            } else if (categoryFilter === '2') {
                categoryName = 'Health and Wellness Blogs';
            }
        }

        sqlQuery += " GROUP BY p.id, p.user_id, p.title, p.content, p.created_at, p.last_updated_at, u.username, c.name, c.id";
        sqlQuery += " ORDER BY p.created_at DESC";

        const queryParams = categoryFilter ? [categoryFilter] : [];

        db.query(sqlQuery, queryParams, (err, posts) => {
            if (err) {
                console.error(err);
                res.render("blog.ejs", { errorMessage: "An error occurred while processing your request. Please try again later." });
            }

            let data = Object.assign({}, blogData, {
                posts: posts,
                categories: res.locals.categories,
                username: req.session.username,
                currentUserId: currentUserId,
                categoryName: categoryName,
                category: categoryFilter,
                messageBlogDeleted: messageBlogDeleted,
                returnCategory: categoryFilter,
                isAdmin: isAdmin
            });

            res.render('blog.ejs', data);
        });
    });

    // Blog Post's ID Route
    app.get('/blog/:id', fetchCategories, function (req, res) {
        const postId = req.params.id;
        const currentUserId = req.session.userId; // Get the current user ID from the session
        const isAdmin = req.session.username === 'admin'; // Check if the logged-in user is 'admin'

        let sqlQuery = `
        SELECT p.id, p.title, p.content, p.created_at, p.last_updated_at, p.user_id, 
               u.username, c.name as categoryName, c.id as categoryId,
               GROUP_CONCAT(t.name SEPARATOR ', ') AS tags
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN categories c ON p.category_id = c.id
        LEFT JOIN post_tags pt ON p.id = pt.post_id
        LEFT JOIN tags t ON pt.tag_id = t.id
        WHERE p.id = ?
        GROUP BY p.id
        `;

        db.query(sqlQuery, [postId], (err, posts) => {
            if (err) {
                console.error(err);
                res.render("blog.ejs", { errorMessage: "An error occurred while processing your request. Please try again later." });
                return;
            }

            if (posts.length > 0) {
                // Fetch comments for the post
                let fetchCommentsQuery = 'SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ? ORDER BY created_at DESC';

                db.query(fetchCommentsQuery, [postId], (err, comments) => {
                    if (err) {
                        console.error('Error fetching comments:', err);
                        return res.status(500).render('post.ejs', { errorMessage: "An error occurred while fetching comments." });
                    }

                    // Fetch the average rating for the post
                    let avgRatingQuery = 'SELECT AVG(rating) AS averageRating FROM ratings WHERE post_id = ?';
                    db.query(avgRatingQuery, [postId], (avgErr, avgResult) => {
                        if (avgErr) {
                            console.error('Error fetching average rating:', avgErr);
                            return res.status(500).render('post.ejs', { errorMessage: "An error occurred while fetching average rating." });
                        }

                        let averageRating = avgResult[0].averageRating || 'Not rated yet';

                        let data = Object.assign({}, blogData, {
                            post: posts[0],
                            comments: comments,
                            username: req.session.username,
                            currentUserId: currentUserId,
                            isAdmin: isAdmin,
                            returnCategory: req.query.returnCategory || 'all',
                            averageRating: averageRating // Add the average rating
                        });

                        res.render('post.ejs', data);
                    });
                });
            } else {
                return res.render('blog', { message: "Post not found." });
            }
        });
    });

    // Route for Creating a Blog
    app.get('/create-blog', fetchCategories, function (req, res) {
        if (!req.session.username) {
            res.redirect('/login'); // Redirect to login if not logged in
        } else {
            let data = Object.assign({}, blogData, { username: req.session.username });
            res.render('create-blog.ejs', data);
        }
    });

    // Route for Submitting and Publishing a Blog
    app.post('/submit-blog', redirectLogin, function (req, res) {
        const user_id = req.session.userId;
        const title = req.sanitize(req.body.title);
        const content = req.sanitize(req.body.content);
        const category_id = req.sanitize(req.body.category_id);
        let tags = req.sanitize(req.body.tags);

        if (typeof tags !== 'string') {
            tags = '';
        }

        let sqlQuery = "INSERT INTO posts (user_id, category_id, title, content) VALUES (?, ?, ?, ?)";
        db.query(sqlQuery, [user_id, category_id, title, content], (err, result) => {
            if (err) {
                console.error(err);
                return res.render('create-blog.ejs', { message: 'Error creating blog post. Please try again.' });
            }

            const postId = result.insertId;
            const tagArray = tags.split(',').map(tag => tag.trim());

            tagArray.forEach(tag => {
                let tagSql = "INSERT INTO tags (name) VALUES (?) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), name=?";
                db.query(tagSql, [tag, tag], (tagErr, tagResult) => {
                    if (tagErr) {
                        console.error(tagErr);
                        return res.render('create-blog.ejs', { message: 'Error inserting tag. Please try again.' });
                    }

                    let tagId = tagResult.insertId;
                    let postTagSql = "INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)";
                    db.query(postTagSql, [postId, tagId], (postTagErr, postTagResult) => {
                        if (postTagErr) {
                            console.error(postTagErr);
                            return res.render('create-blog.ejs', { message: 'Error with linking tag to post. Please try again.' });
                        }
                    });
                });
            });

            res.redirect(`/blog/${postId}`);
        });
    });

    // Route for Editing a Blog Post
    app.get('/edit-blog/:id', redirectLogin, fetchCategories, function (req, res) {
        const postId = req.params.id;
        const userId = req.session.userId;
        const isAdmin = req.session.username === 'admin'; // Check if the user is an admin
        const category = req.query.category;
        const returnCategory = req.query.returnCategory || 'all';

        let sqlQuery = "SELECT * FROM posts WHERE id = ?";
        db.query(sqlQuery, [postId], (err, result) => {
            if (err) {
                console.error(err);
                return res.render('edit-blog.ejs', { message: 'Error editing blog post. Please try again.' });
            }

            if (result.length > 0) {
                const post = result[0];

                // Check if the user is the owner of the post or an admin who created the post
                if (post.user_id === userId || (isAdmin && post.created_by_admin)) {
                    res.render('edit-blog.ejs', {
                        post: post,
                        username: req.session.username,
                        siteName: blogData.siteName,
                        category: category,
                        returnCategory: returnCategory
                    });
                } else {
                    // Post not found or user not authorized
                    res.status(403).send("Unauthorized access: You cannot edit this post.");
                }
            } else {
                // Post not found
                res.status(404).send("Post not found.");
            }
        });
    });

    // Route for Updating a Blog Post After Editing
    app.post('/update-blog/:id', redirectLogin, function (req, res) {
        const postId = req.params.id;
        const userId = req.session.userId;
        const title = req.sanitize(req.body.title);
        const content = req.sanitize(req.body.content);
        const category_id = req.sanitize(req.body.category_id);
        let tags = req.sanitize(req.body.tags);
        const returnCategory = req.body.returnCategory || 'all';


        let updateSqlQuery = "UPDATE posts SET title = ?, content = ?, category_id = ? WHERE id = ? AND user_id = ?";
        db.query(updateSqlQuery, [title, content, category_id, postId, userId], (err, result) => {
            if (err) {
                console.error(err);
                return res.render('blog.ejs', { message: 'Error updating blog post. Please try again.' });
            }

            // Delete old tags
            let deleteOldTagsSql = "DELETE FROM post_tags WHERE post_id = ?";
            db.query(deleteOldTagsSql, [postId], (deleteErr, deleteResult) => {
                if (deleteErr) {
                    console.error(deleteErr);
                    return res.render('blog.ejs', { message: 'Error with the tag. Please try again.' });
                }

                // Insert new tags
                if (typeof tags !== 'string') {
                    tags = '';
                }

                const tagArray = tags.split(',').map(tag => tag.trim());
                tagArray.forEach(tag => {
                    let tagSql = "INSERT INTO tags (name) VALUES (?) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), name=?";
                    db.query(tagSql, [tag, tag], (tagErr, tagResult) => {
                        if (tagErr) {
                            console.error(tagErr);
                            return res.render('blog.ejs', { message: 'Error with the tag. Please try again.' });
                        }

                        let tagId = tagResult.insertId;
                        let postTagSql = "INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)";
                        db.query(postTagSql, [postId, tagId], (postTagErr, postTagResult) => {
                            if (postTagErr) {
                                console.error(postTagErr);
                                return res.render('blog.ejs', { message: 'Error with the tag. Please try again.' });
                            }
                        });
                    });
                });
                res.redirect(`/blog/${postId}?returnCategory=${returnCategory}`);
            });
        });
    });

    // Route for Deleting a Blog Post
    app.get('/delete-blog/:id', redirectLogin, fetchCategories, function (req, res) {
        const postId = req.params.id;
        const userId = req.session.userId;
        const isAdmin = req.session.username === 'admin'; // Check if the user is an admin

        // Determine the SQL query based on whether the user is an admin
        let deletePostSql;
        if (isAdmin) {
            // Admin can delete any post
            deletePostSql = "DELETE FROM posts WHERE id = ?";
        } else {
            // Regular users can only delete their own posts
            deletePostSql = "DELETE FROM posts WHERE id = ? AND user_id = ?";
        }

        // Prepare the query parameters
        let queryParams = isAdmin ? [postId] : [postId, userId];

        // First, delete references in post_tags
        let deletePostTagsSql = "DELETE FROM post_tags WHERE post_id = ?";
        db.query(deletePostTagsSql, [postId], (err, result) => {
            if (err) {
                console.error(err);
                return res.render('blog.ejs', { message: 'Error deleting post. Please try again.' });
            }

            // Then, delete the post
            db.query(deletePostSql, queryParams, (err, result) => {
                if (err) {
                    console.error(err);
                    return res.render('blog.ejs', { message: 'Error deleting post. Please try again.' });
                }

                if (result.affectedRows > 0) {
                    res.redirect('/blog?messageBlogDeleted=Post deleted successfully.');
                } else {
                    res.status(403).send('Unable to delete post. You may not have the required permissions.');
                }
            });
        });
    });

    // Route to Post a Comment
    app.post('/blog/:postId/comment', redirectLogin, function (req, res) {
        const userId = req.session.userId;
        const postId = req.params.postId;
        const content = req.sanitize(req.body.content);

        let insertCommentQuery = 'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)';

        db.query(insertCommentQuery, [postId, userId, content], (err, result) => {
            if (err) {
                console.error('Error inserting comment:', err);
                return res.status(500).send('Error posting comment.');
            }
            res.redirect(`/blog/${postId}`);
        });
    });

    // Route to Delete a Comment
    app.post('/comment/:commentId/delete', redirectLogin, function (req, res) {
        const userId = req.session.userId;
        const commentId = req.params.commentId;

        let deleteCommentQuery = 'DELETE FROM comments WHERE id = ? AND user_id = ?';

        db.query(deleteCommentQuery, [commentId, userId], (err, result) => {
            if (err) {
                console.error('Error deleting comment:', err);
                return res.status(500).json({ success: false, message: 'Error deleting comment.' });
            }
            res.json({ success: true, message: 'Comment deleted successfully.', commentId: commentId });
        });
    });

    // Route to Edit a Comment
    app.post('/comment/:commentId/edit', redirectLogin, function (req, res) {
        const userId = req.session.userId;
        const commentId = req.params.commentId;
        const content = req.sanitize(req.body.content);

        const updateCommentQuery = 'UPDATE comments SET content = ?, updated_at = NOW() WHERE id = ? AND user_id = ?';

        db.query(updateCommentQuery, [content, commentId, userId], (err, result) => {
            if (err) {
                console.error('Error updating comment:', err);
                return res.status(500).send('Error updating comment.');
            }
            res.redirect('back');
        });
    });

    // Route to Rate a Blog Post
    app.post('/rate/:postId/:rating', redirectLogin, (req, res) => {
        const postId = req.params.postId;
        const rating = parseInt(req.params.rating);
        const userId = req.session.userId;

        if (rating < 1 || rating > 5) {
            return res.status(400).json({ success: false, message: 'Invalid rating' });
        }

        // Insert or update the rating in the database
        let sqlQuery = 'REPLACE INTO ratings (post_id, user_id, rating) VALUES (?, ?, ?)';
        db.query(sqlQuery, [postId, userId, rating], (err, result) => {
            if (err) {
                console.error('Error updating rating:', err);
                return res.status(500).json({ success: false, message: 'Error updating rating' });
            }

            // Retrieve the new average rating
            let avgQuery = 'SELECT AVG(rating) AS averageRating FROM ratings WHERE post_id = ?';
            db.query(avgQuery, [postId], (avgErr, avgResult) => {
                if (avgErr) {
                    console.error('Error fetching average rating:', avgErr);
                    return res.status(500).json({ success: false, message: 'Error fetching average rating' });
                }

                res.json({ success: true, averageRating: avgResult[0].averageRating });
            });
        });
    });


    // Weather Route
    app.get('/weather', fetchCategories, function (req, res) {
        res.render('weather.ejs', {
            weather: null,
            error: null,
            siteName: blogData.siteName,
            username: req.session.username
        });
    });

    // Weather Route
    app.post('/weather', fetchCategories, function (req, res) {
        const apiKey = 'ed6e8759e90f6acfdf8b32a9155c71dd';
        const city = req.body.city;
        const url = `http://api.openweathermap.org/data/2.5/weather?q=${city}&units=metric&appid=${apiKey}`;

        const request = require('request');

        request(url, function (err, response, body) {
            if (err) {
                res.render('weather.ejs', {
                    weather: null,
                    error: 'Error, please try again',
                    siteName: blogData.siteName,
                    username: req.session.username
                });
            } else {
                try {
                    const weather = JSON.parse(body);
                    if (response.statusCode === 200 && weather.main) {
                        const weatherMessage = {
                            city: weather.name,
                            description: weather.weather[0].description,
                            temperature: `Temperature: ${weather.main.temp}°C`,
                            feels_like: `Feels Like: ${weather.main.feels_like}°C`,
                            temp_min: `Minimum Temperature: ${weather.main.temp_min}°C`,
                            temp_max: `Maximum Temperature: ${weather.main.temp_max}°C`,
                            pressure: `Pressure: ${weather.main.pressure} hPa`,
                            humidity: `Humidity: ${weather.main.humidity}%`,
                            wind: `Wind Speed: ${weather.wind.speed} m/s, Direction: ${weather.wind.deg}°`,
                            clouds: `Cloudiness: ${weather.clouds.all}%`,
                            rain: weather.rain ? `Rain: ${weather.rain['1h']} mm/h` : 'Rain: None',
                        };
                        res.render('weather.ejs', {
                            weather: weatherMessage,
                            error: null,
                            siteName: blogData.siteName,
                            username: req.session.username
                        });
                    } else {
                        res.render('weather.ejs', {
                            weather: null,
                            error: 'Unable to find the weather for the specified city.',
                            siteName: blogData.siteName,
                            username: req.session.username
                        });
                    }
                } catch (parseError) {
                    res.render('weather.ejs', {
                        weather: null,
                        error: 'Error processing the weather information.',
                        siteName: blogData.siteName,
                        username: req.session.username
                    });
                }
            }
        });
    });

    // My Blog's API Route
    app.get('/api', function (req, res) {
        let keyword = req.query.keyword;
        let sqlQuery = "SELECT * FROM posts";
        let queryParams = [];

        if (keyword) {
            sqlQuery += " WHERE title LIKE ? OR content LIKE ?";
            keyword = '%' + keyword + '%';
            queryParams = [keyword, keyword];
        }

        db.query(sqlQuery, queryParams, (err, result) => {
            if (err) {
                console.error('Error fetching posts:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (!result || result.length === 0) {
                return res.status(404).json({ error: 'No posts found' });
            }

            res.json(result);
        });
    });

    // My Blog's API Route
    app.get('/api-view', fetchCategories, function (req, res) {
        let keyword = req.query.keyword;
        let sqlQuery = "SELECT * FROM posts";
        let queryParams = [];

        if (keyword) {
            sqlQuery += " WHERE title LIKE ? OR content LIKE ?";
            keyword = '%' + keyword + '%';
            queryParams = [keyword, keyword];
        }

        db.query(sqlQuery, queryParams, (err, result) => {
            if (err) {
                console.error('Error fetching posts:', err);
                return res.render('api.ejs', {
                    error: 'Internal server error',
                    siteName: blogData.siteName,
                    username: req.session.username
                });
            }

            if (!result || result.length === 0) {
                return res.render('api.ejs', {
                    error: 'No posts found',
                    siteName: blogData.siteName,
                    username: req.session.username
                });
            }

            res.render('api.ejs', {
                posts: result,
                siteName: blogData.siteName,
                username: req.session.username
            });
        });
    });

    // TV-Show Route
    app.get('/tv-shows', fetchCategories, function (req, res) {
        res.render('tv-shows.ejs', { shows: null, error: null, siteName: blogData.siteName, username: req.session.username });
    });

    const request = require('request');

    // Async function to fetch episode count for each show
    async function fetchEpisodeCount(showId) {
        return new Promise((resolve, reject) => {
            request(`https://api.tvmaze.com/shows/${showId}/episodes`, { json: true }, (err, response, body) => {
                if (err || response.statusCode !== 200) {
                    reject('Error fetching episodes');
                    return;
                }
                resolve(body.length); // Resolve with episode count
            });
        });
    }

    // Search TV-Show Route
    app.get('/search-shows', fetchCategories, function (req, res) {
        const request = require('request');
        const query = req.query.search;

        if (!query) {
            return res.render('tv-shows.ejs', {
                shows: null,
                error: 'Please enter a search term.',
                siteName: blogData.siteName,
                username: req.session.username
            });
        }

        const url = `https://api.tvmaze.com/search/shows?q=${encodeURIComponent(query)}`;

        request(url, { json: true }, async (err, response, body) => {
            if (err || response.statusCode !== 200) {
                console.error('API error:', err || response.statusCode);
                return res.render('tv-shows.ejs', {
                    shows: null,
                    error: 'Error retrieving data from TVMaze API.',
                    siteName: blogData.siteName,
                    username: req.session.username
                });
            }

            if (!body || body.length === 0) {
                return res.render('tv-shows.ejs', {
                    shows: null,
                    error: 'No TV shows found matching your search term.',
                    siteName: blogData.siteName,
                    username: req.session.username
                });
            }

            // Add episode count to each show
            const showsWithEpisodes = await Promise.all(body.map(async (showItem) => {
                try {
                    const episodeCount = await fetchEpisodeCount(showItem.show.id);
                    return { ...showItem, show: { ...showItem.show, episodeCount } };
                } catch (error) {
                    console.error('Failed to fetch episode count for show:', showItem.show.name, error);
                    return showItem; // Return the show item without episode count
                }
            }));

            res.render('tv-shows.ejs', {
                shows: showsWithEpisodes,
                error: null,
                siteName: blogData.siteName,
                username: req.session.username
            });
        });
    });

}

