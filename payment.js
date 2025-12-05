const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const mysql = require("mysql2");

//  DB connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root", // or your DB user
    password: "", // your DB password
    database: "shopping_cart"
});

//  POST /payment-success
router.post("/payment-success", (req, res) => {
    const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
        user_order_number,
        user_id
    } = req.body;

    // 1️ Verify Razorpay signature
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
        .createHmac("sha256", "P8EAdTqUDljOvMDHv5Zfwd7D")
        .update(body.toString())
        .digest("hex");

    if (expectedSignature !== razorpay_signature) {
        console.error("❌ Payment verification failed");
        return res.status(400).send("Payment verification failed");
    }

    console.log("✅ Payment verified:", razorpay_payment_id);

    // 2️ Update order status
    const updateOrderSql = `
        UPDATE orders
        SET payment_status = 'Paid', payment_id = ?
        WHERE user_order_number = ?
    `;
    db.query(updateOrderSql, [razorpay_payment_id, user_order_number], (err) => {
        if (err) {
            console.error("DB update error:", err);
            return res.status(500).send("Order update failed");
        }

        // 3️ Fetch purchased items from cart
        const getItemsSql = `
            SELECT p.product_name, p.product_price, ci.quantity
            FROM cart_items ci
            JOIN product p ON ci.product_id = p.product_id
            WHERE ci.user_id = ?
        `;
        db.query(getItemsSql, [user_id], (err2, items) => {
            if (err2) {
                console.error("Fetch items error:", err2);
                return res.status(500).send("Could not fetch purchased items");
            }

            // 4️ Reduce stock
            items.forEach(item => {
                db.query(
                    `UPDATE product SET stock = stock - ? WHERE product_name = ?`,
                    [item.quantity, item.product_name]
                );
            });

            // 5️ Clear the cart
            db.query(`DELETE FROM cart_items WHERE user_id = ?`, [user_id], (err3) => {
                if (err3) {
                    console.error("Cart clear error:", err3);
                    return res.status(500).send("Cart clear failed");
                }

                // 6️ Render success page immediately
                res.render("payment_success", {
                    payment_id: razorpay_payment_id,
                    order_number: user_order_number,
                    items
                });
            });
        });
    });
});

module.exports = router;
