const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const multer = require("multer");
const path = require("path");

//  Database connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "shopping_cart"
});

//  Middleware to protect admin routes
function requireAdmin(req, res, next) {
    if (req.session.isAdmin) return next();
    res.redirect("/admin/login");
}

//  Multer setup for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/uploads/");
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});
const upload = multer({ storage });

//  GET: Admin Sign-Up Form
router.get("/signup", (req, res) => {
    res.render("admin_signup", { error: null });
});

//  POST: Handle Admin Sign-Up
router.post("/signup", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.render("admin_signup", { error: "Email and password are required" });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("Hashing error:", err);
            return res.render("admin_signup", { error: "Internal error during signup" });
        }

        const sql = `INSERT INTO admin_users (email, password) VALUES (?, ?)`;
        db.query(sql, [email, hashedPassword], (err2) => {
            if (err2) {
                console.error("Signup error:", err2);
                const msg = err2.code === "ER_DUP_ENTRY"
                    ? "Email already registered"
                    : "Signup failed";
                return res.render("admin_signup", { error: msg });
            }

            res.redirect("/admin/login");
        });
    });
});

//  GET: Admin Login Form
router.get("/login", (req, res) => {
    res.render("admin_login", { error: null });
});

//  POST: Handle Admin Login
router.post("/login", (req, res) => {
    const { email, password } = req.body;

    const sql = `SELECT * FROM admin_users WHERE email = ?`;
    db.query(sql, [email], (err, results) => {
        if (err) {
            console.error("Login query error:", err);
            return res.render("admin_login", { error: "Login failed" });
        }

        if (results.length === 0) {
            return res.render("admin_login", { error: "Invalid email" });
        }

        const admin = results[0];
        bcrypt.compare(password, admin.password, (err2, match) => {
            if (err2) {
                console.error("Password compare error:", err2);
                return res.render("admin_login", { error: "Login failed" });
            }

            if (match) {
                req.session.isAdmin = true;
                req.session.adminEmail = admin.email;
                res.redirect("/admin/dashboard");
            } else {
                res.render("admin_login", { error: "Incorrect password" });
            }
        });
    });
});

//  GET: Admin Dashboard (fetch products)
router.get("/dashboard", requireAdmin, (req, res) => {
    db.query("SELECT * FROM product", (err, products) => {
        if (err) {
            console.error("Dashboard query error:", err);
            return res.render("admin_dashboard", { email: req.session.adminEmail, products: [] });
        }
        res.render("admin_dashboard", { email: req.session.adminEmail, products });
    });
});

// POST: Delete Product (safe delete to avoid FK errors)
router.post("/delete/:id", requireAdmin, (req, res) => {
    const productId = req.params.id;

    // 1. Delete from order_items
    db.query("DELETE FROM order_items WHERE product_id = ?", [productId], (err) => {
        if (err) {
            console.error("Delete from order_items error:", err);
            return res.redirect("/admin/dashboard");
        }

        // 2. Delete from cart_items (correct table name)
        db.query("DELETE FROM cart_items WHERE product_id = ?", [productId], (err2) => {
            if (err2) {
                console.error("Delete from cart_items error:", err2);
                return res.redirect("/admin/dashboard");
            }

            // 3. Delete from product
            db.query("DELETE FROM product WHERE product_id = ?", [productId], (err3) => {
                if (err3) {
                    console.error("Delete product error:", err3);
                }
                res.redirect("/admin/dashboard");
            });
        });
    });
});

//  POST: Increase or Decrease Stock
router.post("/stock/:id", requireAdmin, (req, res) => {
    const productId = req.params.id;
    const action = req.body.action;

    let sql;
    if (action === "increase") {
        sql = "UPDATE product SET stock = stock + 1 WHERE product_id = ?";
    } else if (action === "decrease") {
        sql = "UPDATE product SET stock = GREATEST(stock - 1, 0) WHERE product_id = ?";
    } else {
        return res.redirect("/admin/dashboard");
    }

    db.query(sql, [productId], (err) => {
        if (err) {
            console.error("Stock update error:", err);
        }
        res.redirect("/admin/dashboard");
    });
});

//  GET: Admin Logout
router.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/admin/login"));
});

//  GET: Product Upload Form
router.get("/upload_product", requireAdmin, (req, res) => {
    res.render("upload", { error: null }); // uses your existing upload.ejs
});

//  POST: Handle Product Upload
router.post("/upload_product", requireAdmin, upload.single("product_image"), (req, res) => {
    const { product_name, product_price } = req.body;
    const imagePath = req.file ? "/uploads/" + req.file.filename : null;

    if (!product_name || !product_price || !imagePath) {
        return res.render("upload", { error: "All fields are required" });
    }

    const sql = `INSERT INTO product (product_name, product_price, product_image) VALUES (?, ?, ?)`;
    db.query(sql, [product_name, product_price, imagePath], (err) => {
        if (err) {
            console.error("Product upload error:", err);
            return res.render("upload", { error: "Failed to upload product" });
        }
        res.redirect("/admin/dashboard");
    });
});

module.exports = router;
