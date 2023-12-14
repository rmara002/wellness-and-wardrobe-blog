-- Create a new database
CREATE DATABASE myBlog;
USE myBlog;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE,
    hashedPassword VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    bio TEXT,
    profile_picture VARCHAR(255),
    PRIMARY KEY(id)
);

-- Categories table
CREATE TABLE categories (
    id INT AUTO_INCREMENT,
    name VARCHAR(50),
    PRIMARY KEY(id)
);

-- Insert default categories
INSERT INTO categories (name) VALUES ('Fashion'), ('Health & Wellness');

-- Tags table
CREATE TABLE tags (
    id INT AUTO_INCREMENT,
    name VARCHAR(50),
    PRIMARY KEY(id)
);

-- Blog posts table
CREATE TABLE posts (
    id INT AUTO_INCREMENT,
    user_id INT,
    category_id INT,
    title VARCHAR(255),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(category_id) REFERENCES categories(id)
);

-- Blog post tags relationship table
CREATE TABLE post_tags (
    post_id INT,
    tag_id INT,
    PRIMARY KEY(post_id, tag_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY(tag_id) REFERENCES tags(id)
);

-- Comments table
CREATE TABLE comments (
    id INT AUTO_INCREMENT,
    post_id INT,
    user_id INT,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY(id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- User ratings table
CREATE TABLE ratings (
    post_id INT,
    user_id INT,
    rating INT,
    PRIMARY KEY(post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK(rating BETWEEN 1 AND 5)
);


-- Update user creation and privileges
CREATE USER 'appuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'blog2027';
GRANT ALL PRIVILEGES ON myBlog.* TO 'appuser'@'localhost';
