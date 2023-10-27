// Import the modules we need
var express = require('express');
var ejs = require('ejs');
var bodyParser = require('body-parser');
const mysql = require('mysql');
var session = require('express-session');

// Create the express application object
const app = express();
const port = 8000;
app.use(bodyParser.urlencoded({ extended: true }));

// Set up CSS and other static assets
app.use(express.static(__dirname + '/public'));

// Create a session
app.use(session({
    secret: 'somerandomstuff',
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 600000
    }
}));

// Define the database connection
// Update the database name and credentials as needed
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'ichize',
    database: 'myBlog'
});

// Connect to the database
db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('Connected to database');
});

global.db = db;

// Set the directory where Express will pick up HTML files
app.set('views', __dirname + '/views');

// Tell Express that we want to use EJS as the templating engine
app.set('view engine', 'ejs');

// Tells Express how we should process html files
app.engine('html', ejs.renderFile);

// Update the data model as needed
var blogData = { siteName: "Wellness and Wardrobe Blog" };

// Requires the routes file, passing in the Express app and data as arguments
// You will need to create this file and define your routes and views
require("./routes/main")(app, blogData);

// Start the web app listening
app.listen(port, () => console.log(`Blog app listening on port ${port}!`));
