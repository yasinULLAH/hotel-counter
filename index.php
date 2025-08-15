<?php
session_start();

// Database configuration
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root'); // Your MySQL username
define('DB_PASSWORD', 'root');     // Your MySQL password
define('DB_NAME', 'restaurant_pos'); // Your database name

// Include the PHP QR Code library
// Make sure qrlib.php is in the same directory or adjust the path
require_once 'qrlib.php';

// Database Connection
function get_db_connection()
{
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}

// Initialize Database Tables and Default Data
function initialize_db()
{
    $conn = get_db_connection();

    // Create users table
    $conn->query("
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('admin', 'verifier') NOT NULL DEFAULT 'verifier'
        )
    ");

    // Create menu table
    $conn->query("
        CREATE TABLE IF NOT EXISTS menu (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            price DECIMAL(10, 2) NOT NULL,
            category VARCHAR(100),
            shortcut VARCHAR(10) UNIQUE
        )
    ");

    // Create orders table
    $conn->query("
        CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_number VARCHAR(50) NOT NULL UNIQUE,
            order_date DATETIME NOT NULL,
            items JSON NOT NULL,
            total DECIMAL(10, 2) NOT NULL,
            payment_method VARCHAR(50),
            is_verified BOOLEAN DEFAULT FALSE,
            verified_by_user_id INT NULL,
            verified_at DATETIME NULL,
            FOREIGN KEY (verified_by_user_id) REFERENCES users(id)
        )
    ");

    // Create settings table
    $conn->query("
        CREATE TABLE IF NOT EXISTS settings (
            s_key VARCHAR(50) PRIMARY KEY,
            s_value TEXT NOT NULL
        )
    ");

    // Add default admin user if not exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = 'admin'");
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows === 0) {
        $password_hash = password_hash('admin123', PASSWORD_BCRYPT); // Default admin password
        $stmt_insert = $conn->prepare("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')");
        $stmt_insert->bind_param("s", $password_hash);
        $stmt_insert->execute();
        $stmt_insert->close();
    }
    $stmt->close();

    // Add default verifier user if not exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = 'verifier'");
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows === 0) {
        $password_hash = password_hash('verifier123', PASSWORD_BCRYPT); // Default verifier password
        $stmt_insert = $conn->prepare("INSERT INTO users (username, password_hash, role) VALUES ('verifier', ?, 'verifier')");
        $stmt_insert->bind_param("s", $password_hash);
        $stmt_insert->execute();
        $stmt_insert->close();
    }
    $stmt->close();

    // Add default menu items if table is empty
    $stmt = $conn->prepare("SELECT COUNT(*) FROM menu");
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    if ($count == 0) {
        $default_items = [
            ["چکن پلاو سنگل (1 پیس 2 کباب)", 510, "چاول"],
            ["چکن پلاو سنگل چائنیز (1 پیس 2 کباب)", 520, "چاول"],
            ["چکن پلاو سنگل بغیر کباب (1 پیس)", 430, "چاول"],
            ["چکن پلاو اسپیشل (2 پیس 2 کباب)", 660, "چاول"],
            ["چکن پلاو اسپیشل چائنیز (2 پیس 2 کباب)", 670, "چاول"],
            ["چکن پلاو اسپیشل بغیر کباب (2 پیس)", 570, "چاول"],
            ["سادہ پلاو (2 کباب)", 360, "چاول"],
            ["سادہ پلاو (بغیر کباب)", 270, "چاول"],
            ["سنگل لچ کس (1 چکن پیس 2 کباب)", 540, "مین کورس"],
            ["اسپیشل لچ کس (2 چکن پیس 2 کباب)", 680, "مین کورس"],
            ["سادہ پلاو لچ کس (2 کباب)", 390, "چاول"],
            ["چکن سٹیم روسٹ (فل)", 1400, "مین کورس"],
            ["چکن سٹیم روسٹ (ہاف)", 750, "مین کورس"],
            ["چکن سٹیم 1/4 پیس", 370, "مین کورس"],
            ["چکن سٹیم 1/8 پیس", 180, "مین کورس"],
            ["شاہی کباب فی درجن", 600, "مین کورس"],
            ["زردہ", 180, "ڈیزرٹ"],
            ["کھیر فی کلو", 660, "ڈیزرٹ"],
            ["رائتہ/سلاد", 60, "اپیٹائزر"],
            ["کولڈ ڈرنک", 80, "مشروبات"]
        ];
        $shortcut_counter = 0;
        $stmt_insert = $conn->prepare("INSERT INTO menu (name, price, category, shortcut) VALUES (?, ?, ?, ?)");
        foreach ($default_items as $item) {
            $shortcut = chr(97 + $shortcut_counter); // 'a', 'b', ...
            $stmt_insert->bind_param("sdss", $item[0], $item[1], $item[2], $shortcut);
            $stmt_insert->execute();
            $shortcut_counter++;
        }
        $stmt_insert->close();
    }

    // Add sample orders if table is empty
    $stmt = $conn->prepare("SELECT COUNT(*) FROM orders");
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    if ($count == 0) {
        $sample_orders = [
            [
                'order_number' => 'ORD001',
                'order_date' => date('Y-m-d H:i:s', strtotime('-2 days')),
                'items' => json_encode([
                    ['id' => 1, 'name' => 'چکن پلاو سنگل (1 پیس 2 کباب)', 'price' => 510, 'quantity' => 2],
                    ['id' => 20, 'name' => 'کولڈ ڈرنک', 'price' => 80, 'quantity' => 3]
                ]),
                'total' => 1260,
                'payment_method' => 'نقد',
                'is_verified' => FALSE,
                'verified_by_user_id' => NULL,
                'verified_at' => NULL
            ],
            [
                'order_number' => 'ORD002',
                'order_date' => date('Y-m-d H:i:s', strtotime('-1 day')),
                'items' => json_encode([
                    ['id' => 12, 'name' => 'چکن سٹیم روسٹ (فل)', 'price' => 1400, 'quantity' => 1],
                    ['id' => 19, 'name' => 'رائتہ/سلاد', 'price' => 60, 'quantity' => 2]
                ]),
                'total' => 1520,
                'payment_method' => 'کارڈ',
                'is_verified' => TRUE,
                'verified_by_user_id' => 2, // Assuming verifier user has ID 2
                'verified_at' => date('Y-m-d H:i:s', strtotime('-1 day + 30 minutes'))
            ],
            [
                'order_number' => 'ORD003',
                'order_date' => date('Y-m-d H:i:s', strtotime('-8 hours')),
                'items' => json_encode([
                    ['id' => 4, 'name' => 'چکن پلاو اسپیشل (2 پیس 2 کباب)', 'price' => 660, 'quantity' => 1],
                    ['id' => 17, 'name' => 'زردہ', 'price' => 180, 'quantity' => 1]
                ]),
                'total' => 840,
                'payment_method' => 'موبائل بینکنگ',
                'is_verified' => FALSE,
                'verified_by_user_id' => NULL,
                'verified_at' => NULL
            ],
            [
                'order_number' => 'ORD004',
                'order_date' => date('Y-m-d H:i:s', strtotime('-3 hours')),
                'items' => json_encode([
                    ['id' => 9, 'name' => 'سنگل لچ کس (1 چکن پیس 2 کباب)', 'price' => 540, 'quantity' => 2],
                    ['id' => 13, 'name' => 'چکن سٹیم روسٹ (ہاف)', 'price' => 750, 'quantity' => 1]
                ]),
                'total' => 1830,
                'payment_method' => 'نقد',
                'is_verified' => FALSE,
                'verified_by_user_id' => NULL,
                'verified_at' => NULL
            ]
        ];
        $stmt_insert = $conn->prepare("INSERT INTO orders (order_number, order_date, items, total, payment_method, is_verified, verified_by_user_id, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        foreach ($sample_orders as $order) {
            $stmt_insert->bind_param("sssdissi", $order['order_number'], $order['order_date'], $order['items'], $order['total'], $order['payment_method'], $order['is_verified'], $order['verified_by_user_id'], $order['verified_at']);
            $stmt_insert->execute();
        }
        $stmt_insert->close();
    }

    // Set default settings
    $stmt = $conn->prepare("SELECT COUNT(*) FROM settings");
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    if ($count == 0) {
        $stmt_insert = $conn->prepare("INSERT INTO settings (s_key, s_value) VALUES (?, ?)");
        $restaurant_name = "بسم اللہ ریستوران";
        $restaurant_address = "123 مین سٹریٹ، لاہور، پاکستان";
        $restaurant_phone = "+92-300-1234567";
        $stmt_insert->bind_param("ss", $key, $value);

        $key = 'restaurantName';
        $value = $restaurant_name;
        $stmt_insert->execute();
        $key = 'restaurantAddress';
        $value = $restaurant_address;
        $stmt_insert->execute();
        $key = 'restaurantPhone';
        $value = $restaurant_phone;
        $stmt_insert->execute();
        $stmt_insert->close();
    }

    $conn->close();
}

// Call initialization function
initialize_db();

// Function to check user role
function is_admin()
{
    return isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin';
}

function is_verifier()
{
    return isset($_SESSION['user_role']) && ($_SESSION['user_role'] === 'verifier' || $_SESSION['user_role'] === 'admin');
}

// Handle AJAX requests
if (isset($_POST['action'])) {
    header('Content-Type: application/json');
    $conn = get_db_connection();

    switch ($_POST['action']) {
        case 'login':
            $username = $_POST['username'];
            $password = $_POST['password'];

            $stmt = $conn->prepare("SELECT id, password_hash, role FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt->bind_result($user_id, $password_hash, $role);
            $stmt->fetch();
            $stmt->close();

            if ($password_hash && password_verify($password, $password_hash)) {
                $_SESSION['user_id'] = $user_id;
                $_SESSION['username'] = $username;
                $_SESSION['user_role'] = $role;
                echo json_encode(['status' => 'success', 'message' => 'Login successful!', 'role' => $role]);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'غلط یوزرنیم یا پاس ورڈ!']);
            }
            break;

        case 'logout':
            session_unset();
            session_destroy();
            echo json_encode(['status' => 'success', 'message' => 'Logged out successfully!']);
            break;

        case 'get_menu_items':
            $searchTerm = '%' . ($_POST['searchTerm'] ?? '') . '%';
            $stmt = $conn->prepare("SELECT id, name, price, category, shortcut FROM menu WHERE name LIKE ? OR shortcut LIKE ? ORDER BY name");
            $stmt->bind_param("ss", $searchTerm, $searchTerm);
            $stmt->execute();
            $result = $stmt->get_result();
            $items = [];
            while ($row = $result->fetch_assoc()) {
                $items[] = $row;
            }
            echo json_encode(['status' => 'success', 'data' => $items]);
            $stmt->close();
            break;

        case 'add_menu_item':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $name = $_POST['name'];
            $price = floatval($_POST['price']);
            $category = $_POST['category'];
            $shortcut = $_POST['shortcut'];

            $stmt = $conn->prepare("INSERT INTO menu (name, price, category, shortcut) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("sdss", $name, $price, $category, $shortcut);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'آئٹم کامیابی سے شامل کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'آئٹم شامل کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'update_menu_item':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $id = intval($_POST['id']);
            $name = $_POST['name'];
            $price = floatval($_POST['price']);
            $category = $_POST['category'];
            $shortcut = $_POST['shortcut'];

            $stmt = $conn->prepare("UPDATE menu SET name = ?, price = ?, category = ?, shortcut = ? WHERE id = ?");
            $stmt->bind_param("sdssi", $name, $price, $category, $shortcut, $id);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'آئٹم کامیابی سے اپڈیٹ کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'آئٹم اپڈیٹ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'delete_menu_item':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $id = intval($_POST['id']);

            $stmt = $conn->prepare("DELETE FROM menu WHERE id = ?");
            $stmt->bind_param("i", $id);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'آئٹم کامیابی سے ڈیلیٹ کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'آئٹم ڈیلیٹ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'get_menu_item_by_id':
            $id = intval($_POST['id']);
            $stmt = $conn->prepare("SELECT id, name, price, category, shortcut FROM menu WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();
            $item = $result->fetch_assoc();
            echo json_encode(['status' => 'success', 'data' => $item]);
            $stmt->close();
            break;

        case 'save_order':
            if (!isset($_SESSION['user_id'])) {
                echo json_encode(['status' => 'error', 'message' => 'براہ کرم لاگ ان کریں۔']);
                break;
            }
            $order_number = $_POST['order_number'];
            $order_date = $_POST['order_date'];
            $items_json = $_POST['items'];
            $total = floatval($_POST['total']);
            $payment_method = $_POST['payment_method'];

            $stmt = $conn->prepare("INSERT INTO orders (order_number, order_date, items, total, payment_method) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssds", $order_number, $order_date, $items_json, $total, $payment_method);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'آرڈر کامیابی سے محفوظ کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'آرڈر محفوظ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'get_all_orders':
            $stmt = $conn->prepare("SELECT id, order_number, order_date, items, total, payment_method, is_verified, verified_by_user_id, verified_at FROM orders ORDER BY order_date DESC");
            $stmt->execute();
            $result = $stmt->get_result();
            $orders = [];
            while ($row = $result->fetch_assoc()) {
                $row['items'] = json_decode($row['items'], true);
                $orders[] = $row;
            }
            echo json_encode(['status' => 'success', 'data' => $orders]);
            $stmt->close();
            break;

        case 'delete_order':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $id = intval($_POST['id']);

            $stmt = $conn->prepare("DELETE FROM orders WHERE id = ?");
            $stmt->bind_param("i", $id);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'آرڈر کامیابی سے ڈیلیٹ کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'آرڈر ڈیلیٹ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'get_order_by_id':
            $id = intval($_POST['id']);
            $stmt = $conn->prepare("SELECT id, order_number, order_date, items, total, payment_method, is_verified, verified_by_user_id, verified_at FROM orders WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();
            $order = $result->fetch_assoc();
            if ($order) {
                $order['items'] = json_decode($order['items'], true);
                echo json_encode(['status' => 'success', 'data' => $order]);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'آرڈر نہیں ملا']);
            }
            $stmt->close();
            break;

        case 'verify_order_qr':
            if (!is_verifier()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $qr_data = json_decode($_POST['qrData'], true);
            $order_number = $qr_data['orderNumber'];
            $total = $qr_data['total'];
            $date = $qr_data['date'];
            $hash = $qr_data['hash'];

            // Re-generate hash on server side to verify
            $expected_hash = md5($order_number . $total . $date); // Simple hash for this example

            if ($hash !== $expected_hash) {
                echo json_encode(['status' => 'error', 'message' => 'غلط QR کوڈ یا ہیش مطابقت نہیں رکھتا', 'data' => null]);
                break;
            }

            $stmt = $conn->prepare("SELECT id, is_verified, verified_by_user_id FROM orders WHERE order_number = ? AND total = ? AND order_date = ?");
            $stmt->bind_param("sds", $order_number, $total, $date);
            $stmt->execute();
            $result = $stmt->get_result();
            $order = $result->fetch_assoc();
            $stmt->close();

            if ($order) {
                if ($order['is_verified']) {
                    $verifier_stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
                    $verifier_stmt->bind_param("i", $order['verified_by_user_id']);
                    $verifier_stmt->execute();
                    $verifier_result = $verifier_stmt->get_result();
                    $verifier_name = $verifier_result->fetch_assoc()['username'] ?? 'نامعلوم';
                    $verifier_stmt->close();
                    echo json_encode(['status' => 'warning', 'message' => 'یہ رسید پہلے ہی تصدیق ہو چکی ہے۔', 'data' => ['is_verified' => true, 'verified_by' => $verifier_name, 'verified_at' => $order['verified_at']]]);
                } else {
                    $user_id = $_SESSION['user_id'];
                    $verified_at = date('Y-m-d H:i:s');
                    $update_stmt = $conn->prepare("UPDATE orders SET is_verified = TRUE, verified_by_user_id = ?, verified_at = ? WHERE id = ?");
                    $update_stmt->bind_param("isi", $user_id, $verified_at, $order['id']);
                    if ($update_stmt->execute()) {
                        echo json_encode(['status' => 'success', 'message' => 'رسید کامیابی سے تصدیق ہو گئی!', 'data' => ['is_verified' => true, 'verified_by' => $_SESSION['username'], 'verified_at' => $verified_at]]);
                    } else {
                        echo json_encode(['status' => 'error', 'message' => 'رسید تصدیق کرنے میں خرابی: ' . $update_stmt->error]);
                    }
                    $update_stmt->close();
                }
            } else {
                echo json_encode(['status' => 'error', 'message' => 'رسید نہیں ملی! ڈیٹا مطابقت نہیں رکھتا۔', 'data' => null]);
            }
            break;

        case 'get_admin_stats':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $today = date('Y-m-d 00:00:00');
            $stats = [
                'todaySales' => 0,
                'todayOrders' => 0,
                'totalRevenue' => 0,
                'totalItems' => 0
            ];

            // Today's Sales and Orders
            $stmt = $conn->prepare("SELECT SUM(total), COUNT(id) FROM orders WHERE order_date >= ?");
            $stmt->bind_param("s", $today);
            $stmt->execute();
            $stmt->bind_result($sales, $orders_count);
            $stmt->fetch();
            $stats['todaySales'] = $sales ?? 0;
            $stats['todayOrders'] = $orders_count ?? 0;
            $stmt->close();

            // Total Revenue
            $stmt = $conn->prepare("SELECT SUM(total) FROM orders");
            $stmt->execute();
            $stmt->bind_result($total_revenue);
            $stmt->fetch();
            $stats['totalRevenue'] = $total_revenue ?? 0;
            $stmt->close();

            // Total Menu Items
            $stmt = $conn->prepare("SELECT COUNT(id) FROM menu");
            $stmt->execute();
            $stmt->bind_result($total_items);
            $stmt->fetch();
            $stats['totalItems'] = $total_items ?? 0;
            $stmt->close();

            echo json_encode(['status' => 'success', 'data' => $stats]);
            break;

        case 'generate_report':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $report_type = $_POST['type'];
            $start_date = null;

            switch ($report_type) {
                case 'daily':
                    $start_date = date('Y-m-d 00:00:00');
                    break;
                case 'weekly':
                    $start_date = date('Y-m-d 00:00:00', strtotime('-7 days'));
                    break;
                case 'monthly':
                    $start_date = date('Y-m-d 00:00:00', strtotime('-1 month'));
                    break;
            }

            $query = "SELECT order_number, order_date, items, total, payment_method FROM orders";
            $params = [];
            $types = "";

            if ($start_date) {
                $query .= " WHERE order_date >= ?";
                $params[] = $start_date;
                $types .= "s";
            }
            $query .= " ORDER BY order_date ASC";

            $stmt = $conn->prepare($query);
            if ($params) {
                $stmt->bind_param($types, ...$params);
            }
            $stmt->execute();
            $result = $stmt->get_result();
            $filtered_orders = [];
            while ($row = $result->fetch_assoc()) {
                $row['items'] = json_decode($row['items'], true);
                $filtered_orders[] = $row;
            }
            echo json_encode(['status' => 'success', 'data' => $filtered_orders]);
            $stmt->close();
            break;

        case 'get_settings':
            $stmt = $conn->prepare("SELECT s_key, s_value FROM settings");
            $stmt->execute();
            $result = $stmt->get_result();
            $settings = [];
            while ($row = $result->fetch_assoc()) {
                $settings[$row['s_key']] = $row['s_value'];
            }
            echo json_encode(['status' => 'success', 'data' => $settings]);
            $stmt->close();
            break;

        case 'save_settings':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $settings_data = json_decode($_POST['settings'], true);

            $stmt = $conn->prepare("REPLACE INTO settings (s_key, s_value) VALUES (?, ?)");
            $stmt->bind_param("ss", $key, $value);
            foreach ($settings_data as $key => $value) {
                $stmt->execute();
            }
            $stmt->close();
            echo json_encode(['status' => 'success', 'message' => 'سیٹنگز کامیابی سے محفوظ ہو گئیں']);
            break;

        case 'get_users':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $stmt = $conn->prepare("SELECT id, username, role FROM users");
            $stmt->execute();
            $result = $stmt->get_result();
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $users[] = $row;
            }
            echo json_encode(['status' => 'success', 'data' => $users]);
            $stmt->close();
            break;

        case 'add_user':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $username = $_POST['username'];
            $password = $_POST['password'];
            $role = $_POST['role'];

            $password_hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $password_hash, $role);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'یوزر کامیابی سے شامل کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'یوزر شامل کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'delete_user':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $id = intval($_POST['id']);
            if ($id == $_SESSION['user_id']) { // Prevent deleting self
                echo json_encode(['status' => 'error', 'message' => 'آپ اپنے اکاؤنٹ کو ڈیلیٹ نہیں کر سکتے۔']);
                break;
            }
            // Disallow deleting admin if it's the only admin
            $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
            $stmt->execute();
            $stmt->bind_result($admin_count);
            $stmt->fetch();
            $stmt->close();

            $stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $stmt->bind_result($user_role_to_delete);
            $stmt->fetch();
            $stmt->close();

            if ($user_role_to_delete == 'admin' && $admin_count <= 1) {
                echo json_encode(['status' => 'error', 'message' => 'آپ آخری ایڈمن یوزر کو ڈیلیٹ نہیں کر سکتے۔']);
                break;
            }

            $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param("i", $id);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'یوزر کامیابی سے ڈیلیٹ کر دیا گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'یوزر ڈیلیٹ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'update_user_password':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $id = intval($_POST['id']);
            $new_password = $_POST['new_password'];
            if (empty($new_password)) {
                echo json_encode(['status' => 'error', 'message' => 'پاس ورڈ خالی نہیں ہو سکتا۔']);
                break;
            }
            $password_hash = password_hash($new_password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
            $stmt->bind_param("si", $password_hash, $id);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'یوزر کا پاس ورڈ کامیابی سے اپڈیٹ ہو گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'یوزر کا پاس ورڈ اپڈیٹ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'update_user_role':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $id = intval($_POST['id']);
            $role = $_POST['role'];

            // Prevent changing own role or demoting last admin
            if ($id == $_SESSION['user_id'] && $role != $_SESSION['user_role']) {
                echo json_encode(['status' => 'error', 'message' => 'آپ اپنا کردار تبدیل نہیں کر سکتے۔']);
                break;
            }

            $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
            $stmt->execute();
            $stmt->bind_result($admin_count);
            $stmt->fetch();
            $stmt->close();

            $stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $stmt->bind_result($current_role);
            $stmt->fetch();
            $stmt->close();

            if ($current_role == 'admin' && $role != 'admin' && $admin_count <= 1) {
                echo json_encode(['status' => 'error', 'message' => 'آخری ایڈمن کا کردار تبدیل نہیں کر سکتے۔']);
                break;
            }

            $stmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ?");
            $stmt->bind_param("si", $role, $id);
            if ($stmt->execute()) {
                echo json_encode(['status' => 'success', 'message' => 'یوزر کا کردار کامیابی سے اپڈیٹ ہو گیا']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'یوزر کا کردار اپڈیٹ کرنے میں خرابی: ' . $stmt->error]);
            }
            $stmt->close();
            break;

        case 'export_data':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $menu_items = [];
            $orders = [];
            $settings_data = [];
            $users_data = [];

            $result = $conn->query("SELECT id, name, price, category, shortcut FROM menu");
            while ($row = $result->fetch_assoc()) {
                $menu_items[] = $row;
            }

            $result = $conn->query("SELECT id, order_number, order_date, items, total, payment_method, is_verified, verified_by_user_id, verified_at FROM orders");
            while ($row = $result->fetch_assoc()) {
                $row['items'] = json_decode($row['items']);
                $orders[] = $row;
            }

            $result = $conn->query("SELECT s_key, s_value FROM settings");
            while ($row = $result->fetch_assoc()) {
                $settings_data[$row['s_key']] = $row['s_value'];
            }

            $result = $conn->query("SELECT id, username, role FROM users");
            while ($row = $result->fetch_assoc()) {
                $users_data[] = $row;
            }

            $export_data = [
                'menuItems' => $menu_items,
                'orders' => $orders,
                'settings' => $settings_data,
                'users' => $users_data,
                'exportDate' => date('Y-m-d H:i:s'),
                'version' => '1.0-php-mysql'
            ];
            echo json_encode(['status' => 'success', 'data' => $export_data]);
            break;

        case 'import_data':
            if (!is_admin()) {
                echo json_encode(['status' => 'error', 'message' => 'اجازت نہیں']);
                break;
            }
            $imported_data = json_decode($_POST['data'], true);

            $conn->begin_transaction();
            try {
                // Clear existing data
                $conn->query("DELETE FROM menu");
                $conn->query("ALTER TABLE menu AUTO_INCREMENT = 1");
                $conn->query("DELETE FROM orders");
                $conn->query("ALTER TABLE orders AUTO_INCREMENT = 1");
                $conn->query("DELETE FROM settings");
                // Don't clear users, only add if not existing or update if necessary

                // Import menu items
                if (isset($imported_data['menuItems']) && is_array($imported_data['menuItems'])) {
                    $stmt_insert_menu = $conn->prepare("INSERT INTO menu (name, price, category, shortcut) VALUES (?, ?, ?, ?)");
                    foreach ($imported_data['menuItems'] as $item) {
                        $name = $item['name'] ?? '';
                        $price = $item['price'] ?? 0.0;
                        $category = $item['category'] ?? '';
                        $shortcut = $item['shortcut'] ?? NULL;
                        $stmt_insert_menu->bind_param("sdss", $name, $price, $category, $shortcut);
                        $stmt_insert_menu->execute();
                    }
                    $stmt_insert_menu->close();
                }

                // Import orders
                if (isset($imported_data['orders']) && is_array($imported_data['orders'])) {
                    $stmt_insert_order = $conn->prepare("INSERT INTO orders (order_number, order_date, items, total, payment_method, is_verified, verified_by_user_id, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    foreach ($imported_data['orders'] as $order) {
                        $order_number = $order['order_number'] ?? '';
                        $order_date = $order['order_date'] ?? date('Y-m-d H:i:s');
                        $items_json = json_encode($order['items'] ?? []);
                        $total = $order['total'] ?? 0.0;
                        $payment_method = $order['payment_method'] ?? '';
                        $is_verified = $order['is_verified'] ?? FALSE;
                        $verified_by_user_id = $order['verified_by_user_id'] ?? NULL;
                        $verified_at = $order['verified_at'] ?? NULL;

                        $stmt_insert_order->bind_param("sssdissi", $order_number, $order_date, $items_json, $total, $payment_method, $is_verified, $verified_by_user_id, $verified_at);
                        $stmt_insert_order->execute();
                    }
                    $stmt_insert_order->close();
                }

                // Import settings
                if (isset($imported_data['settings']) && is_array($imported_data['settings'])) {
                    $stmt_insert_setting = $conn->prepare("REPLACE INTO settings (s_key, s_value) VALUES (?, ?)");
                    foreach ($imported_data['settings'] as $key => $value) {
                        $stmt_insert_setting->bind_param("ss", $key, $value);
                        $stmt_insert_setting->execute();
                    }
                    $stmt_insert_setting->close();
                }

                // Users are handled by the initialize_db and separate user management

                $conn->commit();
                echo json_encode(['status' => 'success', 'message' => 'ڈیٹا کامیابی سے امپورٹ ہو گیا!']);
            } catch (Exception $e) {
                $conn->rollback();
                echo json_encode(['status' => 'error', 'message' => 'ڈیٹا امپورٹ کرنے میں خرابی: ' . $e->getMessage()]);
            }
            break;

        default:
            echo json_encode(['status' => 'error', 'message' => 'نامعلوم ایکشن']);
            break;
    }
    $conn->close();
    exit();
}

// Check if user is logged in
$is_logged_in = isset($_SESSION['user_id']);
$user_role = $_SESSION['user_role'] ?? 'guest';
$username = $_SESSION['username'] ?? 'مہمان';

?>
<!DOCTYPE html>
<html dir="rtl" lang="ur">

<head>
    <meta charset="utf-8" />
    <meta content="width=device-width, initial-scale=1.0" name="viewport" />
    <meta content="Yasin Ullah, Pakistan" name="author" />
    <meta content="مکمل آف لائن ریستوران POS سسٹم - تھرمل پرنٹنگ اور QR کوڈ ویریفیکیشن کے ساتھ" name="description" />
    <meta content="ریستوران، POS، پوائنٹ آف سیل، تھرمل پرنٹر، رسید، QR کوڈ، آف لائن، پاکستان" name="keywords" />
    <title>ریستوران POS سسٹم - پاکستان</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Nastaliq+Urdu:wght@400;700&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Noto Nastaliq Urdu', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            font-size: 14px;
            direction: rtl;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .container {
            margin: 0 auto;
            padding: 10px;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
        }

        .header {
            background: linear-gradient(135deg, #2c3e50, #3498db);
            color: white;
            padding: 15px;
            text-align: center;
            margin-bottom: 15px;
            border-radius: 10px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-size: 24px;
            margin-bottom: 5px;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
            flex-grow: 1;
        }

        .user-info {
            font-size: 14px;
            text-align: left;
            margin-left: 10px;
        }

        .nav-tabs {
            display: flex;
            justify-content: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 6px;
        }

        .nav-tab {
            background: linear-gradient(135deg, #34495e, #2c3e50);
            color: white;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-family: 'Noto Nastaliq Urdu', sans-serif;
            transition: all 0.3s ease;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            min-width: 80px;
        }

        .nav-tab.active,
        .nav-tab:hover {
            background: linear-gradient(135deg, #2980b9, #3498db);
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }

        .tab-content {
            display: none;
            flex-grow: 1;
            padding-bottom: 10px;
        }

        .tab-content.active {
            display: flex;
            flex-direction: column;
        }

        .grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 15px;
            margin: 15px 0;
            flex-grow: 1;
            height: 1px;
        }

        .grid>div {
            display: flex;
            flex-direction: column;
            height: 100%;
        }

        .menu-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            flex-grow: 1;
            overflow-y: auto;
            padding-right: 5px;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 15px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
            transition: all 0.3s ease;
            backdrop-filter: blur(8px);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.25);
        }

        .btn {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-family: 'Noto Nastaliq Urdu', sans-serif;
            margin: 4px;
            transition: all 0.3s ease;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            min-width: 70px;
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }

        .btn-success {
            background: linear-gradient(135deg, #27ae60, #229954);
        }

        .btn-danger {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }

        .btn-warning {
            background: linear-gradient(135deg, #f39c12, #e67e22);
        }

        .btn-large {
            padding: 15px 25px;
            font-size: 16px;
            min-width: 130px;
        }

        .form-group {
            margin: 10px 0;
        }

        .form-control {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            font-family: 'Noto Nastaliq Urdu', sans-serif;
            transition: all 0.3s ease;
        }

        .form-control:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 10px rgba(52, 152, 219, 0.3);
        }

        .menu-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border: 1px solid #ecf0f1;
            border-radius: 10px;
            margin: 6px 0;
            background: white;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .menu-item:hover {
            border-color: #3498db;
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.15);
        }

        .menu-item-info {
            flex: 1;
        }

        .menu-item-name {
            font-size: 16px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 3px;
        }

        .menu-item-price {
            font-size: 18px;
            font-weight: bold;
            color: #27ae60;
        }

        .menu-item-shortcut {
            font-size: 0.8em;
            color: #777;
            margin-right: 5px;
            padding: 2px 5px;
            border: 1px solid #ccc;
            border-radius: 3px;
            background-color: #f0f0f0;
        }

        .cart {
            background: rgba(255, 255, 255, 0.95);
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
            backdrop-filter: blur(8px);
            position: sticky;
            top: 10px;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }

        .cart-header {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #3498db;
            flex-shrink: 0;
        }

        #currentCart {
            overflow-y: auto;
            margin-bottom: 10px;
        }

        .cart-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #ecf0f1;
        }

        .cart-item:last-child {
            border-bottom: none;
        }

        .quantity-controls {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .quantity-btn {
            width: 30px;
            font-size: 18px;
        }

        .cart-total {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 12px;
            border-radius: 8px;
            margin: 10px 0;
            text-align: center;
            flex-shrink: 0;
        }

        .total-amount {
            font-size: 20px;
            font-weight: bold;
        }

        .search-box {
            width: 100%;
            padding: 12px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 10px;
            font-size: 16px;
            font-family: 'Noto Nastaliq Urdu', sans-serif;
        }

        .search-box:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 10px rgba(52, 152, 219, 0.3);
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            z-index: 1000;
            backdrop-filter: blur(4px);
            overflow-y: auto;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background: white;
            margin: 20px auto;
            padding: 20px;
            width: 90%;
            max-width: 400px;
            border-radius: 10px;
            position: relative;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        }

        .close {
            position: absolute;
            left: 10px;
            top: 8px;
            font-size: 25px;
            cursor: pointer;
            color: #555;
        }

        .close:hover {
            color: #333;
        }

        .receipt {
            width: 78mm;
            background: white;
            padding: 8px;
            font-family: 'Courier New', monospace;
            font-size: 10px;
            line-height: 1.1;
            margin: 10px auto;
            border: 1px solid #333;
            border-radius: 5px;
            height: auto;
            min-height: 112mm;
            padding-top: 53px;
        }

        .receipt-header h3 {
            font-size: 14px;
        }

        .receipt-item {
            display: flex;
            justify-content: space-between;
            font-size: 9px;
            margin-bottom: 2px;
        }

        .receipt-total {
            font-size: 12px;
        }

        .qr-code-container {
            margin: 8px auto;
            text-align: center;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }

        .stat-card {
            padding: 20px;
            border-radius: 10px;
        }

        .stat-number {
            font-size: 30px;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 14px;
        }

        .order-item {
            margin: 10px 0;
            padding: 15px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.95);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .scanner-container {
            max-width: 450px;
            padding: 20px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.95);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
            margin: 0 auto;
        }

        #reader {
            border: 1px solid #3498db;
            border-radius: 10px;
            width: 100% !important;
            min-height: 200px;
        }

        .scan-result {
            margin-top: 15px;
            padding: 12px;
            border-radius: 10px;
            text-align: center;
            font-weight: bold;
        }

        .scan-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .scan-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .scan-warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }

        .report-section {
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
        }

        .report-controls {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin: 15px 0;
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background-color: #333;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            z-index: 10000;
            opacity: 0;
            transform: translateY(-20px);
            transition: all 0.4s ease-out;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            font-size: 14px;
        }

        .notification.show {
            opacity: 1;
            transform: translateY(0);
        }

        .notification.success {
            background-color: #28a745;
        }

        .notification.error {
            background-color: #dc3545;
        }

        .notification.info {
            background-color: #17a2b8;
        }

        @media (max-width: 768px) {
            body {
                font-size: 13px;
            }

            .container {
                padding: 8px;
            }

            .header {
                padding: 12px;
                margin-bottom: 12px;
            }

            .header h1 {
                font-size: 20px;
            }

            .nav-tab {
                padding: 8px 15px;
                font-size: 13px;
                min-width: 70px;
            }

            .grid {
                grid-template-columns: 1fr;
                gap: 10px;
                margin: 10px 0;
            }

            .menu-grid {
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 8px;
            }

            .card {
                padding: 12px;
            }

            .btn {
                padding: 8px 15px;
                font-size: 12px;
                min-width: 60px;
            }

            .btn-large {
                padding: 12px 20px;
                font-size: 14px;
                min-width: 100px;
            }

            .form-control {
                padding: 8px;
                font-size: 13px;
            }

            .menu-item {
                padding: 10px;
                gap: 8px;
            }

            .menu-item-name {
                font-size: 15px;
            }

            .menu-item-price {
                font-size: 17px;
            }

            .cart {
                padding: 12px;
                top: 8px;
            }

            .cart-header {
                font-size: 16px;
                margin-bottom: 8px;
            }

            #currentCart {
                margin-bottom: 8px;
            }

            .cart-item {
                padding: 6px 0;
            }

            .quantity-btn {
                width: 28px;
                height: 28px;
                font-size: 16px;
            }

            .total-amount {
                font-size: 18px;
            }

            .search-box {
                padding: 10px;
                font-size: 14px;
                margin-bottom: 12px;
            }

            .modal-content {
                margin: 15px auto;
                padding: 15px;
                max-width: 350px;
            }

            .close {
                font-size: 22px;
            }

            .receipt {
                width: 55mm !important;
                padding: 6px;
                font-size: 9px;
            }

            .receipt-header h3 {
                font-size: 12px;
            }

            .receipt-item {
                font-size: 8px;
            }

            .receipt-total {
                font-size: 10px;
            }

            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 10px;
            }

            .stat-card {
                padding: 15px;
            }

            .stat-number {
                font-size: 26px;
            }

            .stat-label {
                font-size: 13px;
            }

            .order-item {
                padding: 12px;
            }

            .scanner-container {
                max-width: 380px;
                padding: 15px;
            }

            .scan-result {
                padding: 10px;
            }

            .report-section {
                padding: 15px;
            }

            .report-controls {
                gap: 8px;
            }

            .notification {
                top: 10px;
                right: 10px;
                padding: 10px 15px;
                font-size: 13px;
            }
        }

        .card.newd {
            width: 100%;
            height: 90px;
        }

        #adminPanel {
            background: rgba(245, 247, 250, 0.6);
            border-radius: 12px;
            padding: 15px;
        }

        .stat-card {
            color: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            text-align: center;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 9px 25px rgba(0, 0, 0, 0.15);
        }

        .stat-card:nth-child(1) {
            background: linear-gradient(135deg, #667eea, #764ba2);
        }

        .stat-card:nth-child(2) {
            background: linear-gradient(135deg, #2af598, #009efd);
        }

        .stat-card:nth-child(3) {
            background: linear-gradient(135deg, #f83600, #f9d423);
        }

        .stat-card:nth-child(4) {
            background: linear-gradient(135deg, #4facfe, #00f2fe);
        }

        .stat-number {
            font-weight: 700;
        }

        .stat-label {
            opacity: 0.9;
        }

        .report-section {
            background: #ffffff;
            border: 1px solid #e9ecef;
        }

        .report-controls {
            border-bottom: 1px solid #e9ecef;
            padding-bottom: 15px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
        }

        #reportResults h4 {
            color: #34495e;
            margin: 25px 0 10px 0;
            font-size: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #3498db;
        }

        .report-list-container {
            border-radius: 8px;
            border: 1px solid #e9ecef;
            background: #f8f9fa;
            padding: 0 15px;
        }

        .report-list-item {
            display: flex;
            justify-content: space-between;
            padding: 12px 5px;
            font-size: 14px;
            border-bottom: 1px solid #dee2e6;
        }

        .report-list-item:last-child {
            border-bottom: none;
        }

        .report-list-item span:first-child {
            color: #495057;
        }

        .report-value {
            font-weight: bold;
        }

        .report-value.success {
            color: #27ae60;
        }

        .report-value.info {
            color: #3498db;
        }

        .users-list .user-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border: 1px solid #ecf0f1;
            border-radius: 10px;
            margin: 6px 0;
            background: white;
            transition: all 0.3s ease;
        }

        .users-list .user-item:hover {
            border-color: #3498db;
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.15);
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="header">
            <div style="text-align: right; flex-grow: 1;">
                <h1>🍽️ ریستوران POS سسٹم</h1>
                <p>مکمل پوائنٹ آف سیل حل - پاکستان</p>
            </div>
            <?php if ($is_logged_in): ?>
                <div class="user-info">
                    <p>یوزر: <?php echo htmlspecialchars($username); ?></p>
                    <p>رول: <?php echo htmlspecialchars($user_role === 'admin' ? 'ایڈمن' : 'ویریفائر'); ?></p>
                    <button class="btn btn-danger" onclick="pos.logout()">لاگ آؤٹ</button>
                </div>
            <?php endif; ?>
        </div>
        <?php if (!$is_logged_in): ?>
            <div class="tab-content active" id="login">
                <div class="card" id="loginPanel" style="max-width: 400px; margin: 50px auto;">
                    <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">🔐 لاگ ان
                    </h3>
                    <div class="form-group">
                        <input class="form-control" id="loginUsername" placeholder="یوزرنیم" type="text" />
                    </div>
                    <div class="form-group">
                        <input class="form-control" id="loginPassword" placeholder="پاس ورڈ" type="password" />
                    </div>
                    <button class="btn btn-large" onclick="pos.login()" style="width: 100%;">داخل ہوں</button>
                </div>
            </div>
        <?php else: ?>
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('pos')">🛒 POS</button>
                <?php if (is_admin()): ?>
                    <button class="nav-tab" onclick="showTab('menu')">📋 مینو منیجمنٹ</button>
                <?php endif; ?>
                <button class="nav-tab" onclick="showTab('orders')">📜 آرڈرز</button>
                <button class="nav-tab" onclick="showTab('scanner')">📱 QR اسکینر</button>
                <?php if (is_admin()): ?>
                    <button class="nav-tab" onclick="showTab('admin')">👤 ایڈمن</button>
                    <button class="nav-tab" onclick="showTab('users')">👥 یوزر منیجمنٹ</button>
                    <button class="nav-tab" onclick="showTab('settings')">⚙️ سیٹنگز</button>
                <?php endif; ?>
            </div>
            <div class="tab-content active" id="pos">
                <div class="card newd" style="flex-shrink: 0;">
                    <input autocomplete="off" class="search-box" id="menuSearch"
                        onfocus="this.removeAttribute('readonly');" placeholder="مینو آئٹم تلاش کریں..." type="text" />
                </div>
                <div class="grid">
                    <div>
                        <div class="card">
                            <h3
                                style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50; flex-shrink: 0;">
                                🍽️ مینو
                                آئٹمز</h3>
                            <div class="menu-grid" id="menuGrid"></div>
                        </div>
                    </div>
                    <div>
                        <div class="cart">
                            <div class="cart-header">🛒 موجودہ آرڈر</div>
                            <div id="currentCart"></div>
                            <div class="cart-total">
                                <div style="font-size: 16px; margin-bottom: 6px;">کل رقم:</div>
                                <div class="total-amount" id="cartTotal">Rs. 0</div>
                            </div>
                            <div style="margin-top: 15px; flex-shrink: 0;">
                                <select class="form-control" id="paymentMethod" style="margin-bottom: 10px;">
                                    <option value="نقد">💵 نقد</option>
                                    <option value="کارڈ">💳 کارڈ</option>
                                    <option value="موبائل بینکنگ">📱 موبائل بینکنگ</option>
                                </select>
                                <button class="btn btn-success btn-large" onclick="pos.checkout()"
                                    style="width: 100%;">✅ چیک
                                    آؤٹ اور پرنٹ</button>
                                <button class="btn btn-warning btn-large" onclick="pos.clearCart()"
                                    style="width: 100%; margin-top: 8px;">🗑️ کارٹ صاف کریں</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php if (is_admin()): ?>
                <div class="tab-content" id="menu">
                    <div class="card">
                        <div
                            style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 8px; flex-shrink: 0;">
                            <h3 style="font-size: 18px; color: #2c3e50;">📋 مینو منیجمنٹ</h3>
                            <button class="btn btn-success" onclick="openModal('addItemModal')">➕ نیا آئٹم شامل
                                کریں</button>
                        </div>
                        <div id="menuList" style="flex-grow: 1; overflow-y: auto;"></div>
                    </div>
                </div>
            <?php endif; ?>
            <div class="tab-content" id="orders">
                <div class="card">
                    <h3
                        style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50; flex-shrink: 0;">
                        📜
                        آرڈر تاریخ</h3>
                    <div id="ordersList" style="flex-grow: 1; overflow-y: auto;"></div>
                </div>
            </div>
            <div class="tab-content" id="scanner">
                <div class="scanner-container">
                    <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">📱 رسید
                        ویریفیکیشن
                        اسکینر</h3>
                    <div id="reader"></div>
                    <div id="scanResult"></div>
                </div>
            </div>
            <?php if (is_admin()): ?>
                <div class="tab-content" id="admin">
                    <div id="adminPanel" style="flex-direction: column; flex-grow: 1;">
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-number" id="todaySales">0</div>
                                <div class="stat-label">آج کی فروخت</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" id="todayOrders">0</div>
                                <div class="stat-label">آج کے آرڈرز</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" id="totalRevenue">0</div>
                                <div class="stat-label">کل آمدنی</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" id="totalItems">0</div>
                                <div class="stat-label">مینو آئٹمز</div>
                            </div>
                        </div>
                        <div class="report-section" style="flex-grow: 1; overflow-y: auto;">
                            <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">📊 رپورٹس
                            </h3>
                            <div class="report-controls">
                                <button class="btn" onclick="generateReport('daily')">📅 روزانہ رپورٹ</button>
                                <button class="btn" onclick="generateReport('weekly')">📈 ہفتہ وار رپورٹ</button>
                                <button class="btn" onclick="generateReport('monthly')">📆 ماہانہ رپورٹ</button>
                                <button class="btn btn-success" onclick="exportData()">💾 ڈیٹا ایکسپورٹ</button>
                                <button class="btn btn-warning" onclick="openModal('importModal')">📁 ڈیٹا امپورٹ</button>
                            </div>
                            <div id="reportResults"></div>
                        </div>
                    </div>
                </div>
                <div class="tab-content" id="users">
                    <div class="card">
                        <div
                            style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 8px; flex-shrink: 0;">
                            <h3 style="font-size: 18px; color: #2c3e50;">👥 یوزر منیجمنٹ</h3>
                            <button class="btn btn-success" onclick="openModal('addUserModal')">➕ نیا یوزر شامل کریں</button>
                        </div>
                        <div id="usersList" class="users-list" style="flex-grow: 1; overflow-y: auto;"></div>
                    </div>
                </div>
                <div class="tab-content" id="settings">
                    <div class="card">
                        <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">⚙️ ریستوران
                            سیٹنگز
                        </h3>
                        <div class="form-group">
                            <label style="font-size: 14px; font-weight: bold; margin-bottom: 5px; display: block;">ریستوران
                                کا
                                نام:</label>
                            <input class="form-control" id="restaurantName" type="text" />
                        </div>
                        <div class="form-group">
                            <label style="font-size: 14px; font-weight: bold; margin-bottom: 5px; display: block;">پتہ:</label>
                            <textarea class="form-control" id="restaurantAddress" rows="3"></textarea>
                        </div>
                        <div class="form-group">
                            <label style="font-size: 14px; font-weight: bold; margin-bottom: 5px; display: block;">فون
                                نمبر:</label>
                            <input class="form-control" id="restaurantPhone" type="text" />
                        </div>
                        <button class="btn btn-success btn-large" onclick="saveSettings()"
                            style="width: 100%;">💾 سیٹنگز محفوظ
                            کریں</button>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Modals -->
    <?php if ($is_logged_in && is_admin()): ?>
        <div class="modal" id="addItemModal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addItemModal')">×</span>
                <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">➕ نیا مینو آئٹم
                </h3>
                <div class="form-group">
                    <input class="form-control" id="itemName" placeholder="آئٹم کا نام" type="text" />
                </div>
                <div class="form-group">
                    <input class="form-control" id="itemPrice" placeholder="قیمت (Rs.)" type="number" />
                </div>
                <div class="form-group">
                    <select class="form-control" id="itemCategory">
                        <option value="مین کورس">مین کورس</option>
                        <option value="اپیٹائزر">اپیٹائزر</option>
                        <option value="ڈیزرٹ">ڈیزرٹ</option>
                        <option value="مشروبات">مشروبات</option>
                        <option value="چاول">چاول</option>
                        <option value="روٹی">روٹی</option>
                    </select>
                </div>
                <div class="form-group">
                    <input class="form-control" id="itemShortcut" placeholder="شارٹ کٹ (A-Z, 0-9)" type="text"
                        maxlength="1" />
                </div>
                <button class="btn btn-success btn-large" onclick="addMenuItem()" style="width: 100%;">✅ آئٹم شامل
                    کریں</button>
            </div>
        </div>
        <div class="modal" id="editItemModal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('editItemModal')">×</span>
                <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">✏️ آئٹم ایڈٹ کریں
                </h3>
                <input id="editItemId" type="hidden" />
                <div class="form-group">
                    <input class="form-control" id="editItemName" placeholder="آئٹم کا نام" type="text" />
                </div>
                <div class="form-group">
                    <input class="form-control" id="editItemPrice" placeholder="قیمت (Rs.)" type="number" />
                </div>
                <div class="form-group">
                    <select class="form-control" id="editItemCategory">
                        <option value="مین کورس">مین کورس</option>
                        <option value="اپیٹائزر">اپیٹائزر</option>
                        <option value="ڈیزرٹ">ڈیزرٹ</option>
                        <option value="مشروبات">مشروبات</option>
                        <option value="چاول">چاول</option>
                        <option value="روٹی">روٹی</option>
                    </select>
                </div>
                <div class="form-group">
                    <input class="form-control" id="editItemShortcut" placeholder="شارٹ کٹ (A-Z, 0-9)" type="text"
                        maxlength="1" />
                </div>
                <button class="btn btn-success btn-large" onclick="updateMenuItem()" style="width: 100%;">✅ اپڈیٹ
                    کریں</button>
            </div>
        </div>
        <div class="modal" id="addUserModal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addUserModal')">×</span>
                <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">➕ نیا یوزر</h3>
                <div class="form-group">
                    <input class="form-control" id="newUsername" placeholder="یوزرنیم" type="text" />
                </div>
                <div class="form-group">
                    <input class="form-control" id="newUserPassword" placeholder="پاس ورڈ" type="password" />
                </div>
                <div class="form-group">
                    <select class="form-control" id="newUserRole">
                        <option value="verifier">ویریفائر</option>
                        <option value="admin">ایڈمن</option>
                    </select>
                </div>
                <button class="btn btn-success btn-large" onclick="addUser()" style="width: 100%;">✅ یوزر شامل کریں</button>
            </div>
        </div>
        <div class="modal" id="editUserModal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('editUserModal')">×</span>
                <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">✏️ یوزر ایڈٹ کریں
                </h3>
                <input id="editUserId" type="hidden" />
                <div class="form-group">
                    <label>یوزرنیم:</label>
                    <input class="form-control" id="editUserUsername" type="text" disabled />
                </div>
                <div class="form-group">
                    <label>پاس ورڈ (تبدیل کرنے کے لیے نیا درج کریں):</label>
                    <input class="form-control" id="editUserNewPassword" placeholder="نیا پاس ورڈ" type="password" />
                </div>
                <div class="form-group">
                    <label>رول:</label>
                    <select class="form-control" id="editUserRole">
                        <option value="verifier">ویریفائر</option>
                        <option value="admin">ایڈمن</option>
                    </select>
                </div>
                <button class="btn btn-success btn-large" onclick="updateUser()" style="width: 100%;">✅ اپڈیٹ کریں</button>
            </div>
        </div>
    <?php endif; ?>

    <div class="modal" id="importModal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('importModal')">×</span>
            <h3 style="text-align: center; margin-bottom: 15px; font-size: 18px; color: #2c3e50;">📁 ڈیٹا امپورٹ</h3>
            <div class="form-group">
                <input accept=".json" class="form-control" id="importFile" type="file" />
            </div>
            <button class="btn btn-success btn-large" onclick="importData()" style="width: 100%;">📥 امپورٹ
                کریں</button>
        </div>
    </div>
    <div class="modal" id="receiptModal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('receiptModal')">×</span>
            <div id="receiptContent"></div>
            <div style="text-align: center; margin-top: 15px;">
                <button class="btn btn-success btn-large" onclick="downloadReceipt()">📥 بطور تصویر ڈاؤن لوڈ
                    کریں</button>
            </div>
        </div>
    </div>
    <script src="https://unpkg.com/qrious@4.0.2/dist/qrious.min.js"></script>
    <script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script>
        class RestaurantPOS {
            constructor() {
                this.currentCart = [];
                this.currentOrderId = null;
                this.scanner = null;
                this.shortcuts = {};
                this.userRole = "<?php echo $user_role; ?>";
                this.userId = "<?php echo $_SESSION['user_id'] ?? 'null'; ?>";
                this.loadInitialData();
            }

            async fetch(action, data = {}) {
                try {
                    const response = await fetch('index.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            action: action,
                            ...data
                        })
                    });
                    const result = await response.json();
                    if (result.status === 'error' && result.message === 'اجازت نہیں') {
                        this.showNotification('آپ کو اس کارروائی کی اجازت نہیں ہے۔', 'error');
                    }
                    return result;
                } catch (error) {
                    console.error('Fetch error:', error);
                    this.showNotification('نیٹ ورک یا سرور میں خرابی۔', 'error');
                    return {
                        status: 'error',
                        message: 'نیٹ ورک یا سرور میں خرابی۔'
                    };
                }
            }

            async loadInitialData() {
                if (this.userRole !== 'guest') {
                    this.renderMenu();
                    this.renderMenuManagement();
                    this.renderOrders();
                    this.loadSettings();
                    this.setupSearchListener();
                    this.updateCartDisplay();
                    if (this.userRole === 'admin') {
                        this.loadAdminStats();
                        this.renderUsers();
                    }
                }
            }

            setupSearchListener() {
                const searchBox = document.getElementById('menuSearch');
                if (searchBox) {
                    searchBox.addEventListener('input', () => {
                        this.renderMenu();
                    });
                }
            }

            async login() {
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;

                if (!username || !password) {
                    this.showNotification('براہ کرم یوزرنیم اور پاس ورڈ درج کریں۔', 'error');
                    return;
                }

                const result = await this.fetch('login', {
                    username,
                    password
                });
                if (result.status === 'success') {
                    this.showNotification(result.message, 'success');
                    // Reload the page to properly render based on session
                    window.location.reload();
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async logout() {
                const result = await this.fetch('logout');
                if (result.status === 'success') {
                    this.showNotification(result.message, 'success');
                    window.location.reload(); // Reload to show login screen
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async getMenuItems() {
                const searchTerm = document.getElementById('menuSearch')?.value || '';
                const result = await this.fetch('get_menu_items', {
                    searchTerm
                });
                return result.data || [];
            }

            async renderMenu() {
                const items = await this.getMenuItems();
                const grid = document.getElementById('menuGrid');
                if (!grid) return;
                grid.innerHTML = '';
                this.assignShortcuts(items);
                items.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'menu-item';
                    div.setAttribute('onclick', `pos.addToCart(${item.id}, '${item.name}', ${item.price})`);
                    div.innerHTML = `
                        <div class="menu-item-info">
                            <div class="menu-item-name">${item.name}</div>
                            <div style="color: #666; font-size: 12px; margin: 3px 0;">قسم: ${item.category}</div>
                            <div class="menu-item-price">Rs. ${item.price}</div>
                        </div>
                        ${item.shortcut ? `<span class="menu-item-shortcut" style="align-self: center;">${item.shortcut.toUpperCase()}</span>` : ''}
                    `;
                    grid.appendChild(div);
                });
                if (items.length === 0) {
                    grid.innerHTML = '<div style="text-align: center; padding: 25px; color: #666; font-size: 14px;">کوئی آئٹم نہیں ملا</div>';
                }
            }

            assignShortcuts(menuItems) {
                this.shortcuts = {};
                menuItems.forEach(item => {
                    if (item.shortcut) {
                        this.shortcuts[item.shortcut.toLowerCase()] = item.id;
                    }
                });
            }

            async renderMenuManagement() {
                if (this.userRole !== 'admin') return;
                const items = await this.getMenuItems();
                const list = document.getElementById('menuList');
                if (!list) return;
                list.innerHTML = '';
                items.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'menu-item';
                    div.innerHTML = `
                        <div class="menu-item-info">
                            <div class="menu-item-name">${item.name}</div>
                            <div style="color: #666; font-size: 12px; margin: 3px 0;">قسم: ${item.category} | قیمت: Rs. ${item.price}</div>
                        </div>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            ${item.shortcut ? `<span class="menu-item-shortcut">${item.shortcut.toUpperCase()}</span>` : ''}
                            <button class="btn btn-warning" onclick="pos.editMenuItem(${item.id})">✏️ ایڈٹ</button>
                            <button class="btn btn-danger" onclick="pos.deleteMenuItem(${item.id})">🗑️ ڈیلیٹ</button>
                        </div>
                    `;
                    list.appendChild(div);
                });
                if (items.length === 0) {
                    list.innerHTML = '<div style="text-align: center; padding: 25px; color: #666; font-size: 14px;">کوئی آئٹم موجود نہیں</div>';
                }
            }

            addToCart(id, name, price) {
                const existingItem = this.currentCart.find(item => item.id === id);
                if (existingItem) {
                    existingItem.quantity++;
                } else {
                    this.currentCart.push({
                        id,
                        name,
                        price,
                        quantity: 1
                    });
                }
                this.updateCartDisplay();
                this.showNotification('آئٹم کارٹ میں شامل کر دیا گیا', 'success');
            }

            removeFromCart(id) {
                this.currentCart = this.currentCart.filter(item => item.id !== id);
                this.updateCartDisplay();
                this.showNotification('آئٹم کارٹ سے ہٹا دیا گیا', 'warning');
            }

            updateQuantity(id, quantity) {
                const item = this.currentCart.find(item => item.id === id);
                if (item) {
                    item.quantity = Math.max(0, quantity);
                    if (item.quantity === 0) {
                        this.removeFromCart(id);
                        return;
                    }
                }
                this.updateCartDisplay();
            }

            updateCartDisplay() {
                const cart = document.getElementById('currentCart');
                const total = document.getElementById('cartTotal');
                if (!cart || !total) return;
                cart.innerHTML = '';
                let totalAmount = 0;
                this.currentCart.forEach(item => {
                    totalAmount += item.price * item.quantity;
                    const div = document.createElement('div');
                    div.className = 'cart-item';
                    div.innerHTML = `
                        <div style="flex: 1;">
                            <div style="font-weight: bold; font-size: 14px; margin-bottom: 3px;">${item.name}</div>
                            <div style="color: #666; font-size: 12px;">Rs. ${item.price} فی یونٹ</div>
                        </div>
                        <div class="quantity-controls">
                            <button class="btn quantity-btn btn-danger" onclick="pos.updateQuantity(${item.id}, ${item.quantity - 1})">-</button>
                            <span style="font-weight: bold; min-width: 25px; text-align: center; font-size: 14px;">${item.quantity}</span>
                            <button class="btn quantity-btn btn-success" onclick="pos.updateQuantity(${item.id}, ${item.quantity + 1})">+</button>
                            <button class="btn btn-danger" onclick="pos.removeFromCart(${item.id})" style="padding: 6px 10px; font-size: 12px;">❌</button>
                        </div>
                    `;
                    cart.appendChild(div);
                });
                if (this.currentCart.length === 0) {
                    cart.innerHTML = '<div style="text-align: center; padding: 15px; color: #666; font-size: 13px;">کارٹ خالی ہے</div>';
                }
                total.textContent = `Rs. ${totalAmount}`;
            }

            clearCart() {
                this.currentCart = [];
                this.updateCartDisplay();
                localStorage.removeItem('restaurant-pos-cart');
                this.showNotification('کارٹ صاف کر دیا گیا', 'success');
            }

            async checkout() {
                if (this.currentCart.length === 0) {
                    this.showNotification('کارٹ خالی ہے!', 'error');
                    return;
                }
                const orderNumber = Date.now().toString().slice(-8);
                const total = this.currentCart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
                const paymentMethod = document.getElementById('paymentMethod').value;
                const order = {
                    order_number: orderNumber,
                    order_date: new Date().toISOString().slice(0, 19).replace('T', ' '), // MySQL DATETIME format
                    items: JSON.stringify(this.currentCart),
                    total: total,
                    payment_method: paymentMethod
                };

                const result = await this.fetch('save_order', order);
                if (result.status === 'success') {
                    const orderForReceipt = {
                        orderNumber: order.order_number,
                        date: order.order_date,
                        items: this.currentCart,
                        total: order.total,
                        paymentMethod: order.payment_method
                    };
                    await this.generateReceipt(orderForReceipt);
                    this.clearCart();
                    this.renderOrders();
                    this.showNotification('آرڈر مکمل ہو گیا!', 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async generateReceipt(order) {
                const settingsResult = await this.fetch('get_settings');
                const settings = settingsResult.data || {};

                const receiptHtml = `
                    <div class="receipt">
                        <div class="receipt-header">
                            <h3>${settings.restaurantName || 'بسم اللہ ریستوران'}</h3>
                            <div style='margin: 6px 0;font-size: 9px;text-align: center;' dir='ltr'>
                                ${settings.restaurantAddress || '123 مین سٹریٹ، لاہور، پاکستان'}<br>
                                ${settings.restaurantPhone || '+92-300-1234567'}
                            </div>
                        </div>
                        <div style="border-bottom: 1px dashed #000; margin: 6px 0;"></div>
                        <div style="margin: 4px 0; font-size: 9px;"><strong>آرڈر نمبر:</strong> ${order.orderNumber}</div>
                        <div style="margin: 4px 0; font-size: 9px;"><strong>تاریخ:</strong> ${new Date(order.date).toLocaleString('ur-PK')}</div>
                        <div style="margin: 4px 0; font-size: 9px;"><strong>ادائیگی:</strong> ${order.paymentMethod}</div>
                        <div style="border-bottom: 1px dashed #000; margin: 6px 0;"></div>
                        ${order.items.map(item => `
                            <div class="receipt-item">
                                <div style="font-weight: bold;">${item.name}</div>
                            </div>
                            <div class="receipt-item">
                                <span>${item.quantity} x Rs.${item.price}</span>
                                <span>Rs.${item.quantity * item.price}</span>
                            </div>
                        `).join('')}
                        <div style="border-bottom: 1px dashed #000; margin: 6px 0;"></div>
                        <div class="receipt-total">
                            <div class="receipt-item">
                                <span>کل رقم:</span>
                                <span>Rs. ${order.total}</span>
                            </div>
                        </div>
                        <div class="qr-code-container" id="qrCode${order.orderNumber}"></div>
                        <div style="text-align: center; font-size: 8px; margin-top: 10px;">
                            آپ کی آمد کا شکریہ!<br>
                            رسید کی تصدیق کے لیے QR کوڈ اسکین کریں
                        </div>
                    </div>
                `;
                document.getElementById('receiptContent').innerHTML = receiptHtml;
                const qrData = JSON.stringify({
                    orderNumber: order.orderNumber,
                    total: order.total,
                    date: order.date,
                    hash: this.generateHash(order.orderNumber + order.total + order.date)
                });
                try {
                    const canvas = document.createElement('canvas');
                    new QRious({
                        element: canvas,
                        value: qrData,
                        size: 160,
                        padding: 1
                    });
                    document.getElementById(`qrCode${order.orderNumber}`).appendChild(canvas);
                } catch (error) {
                    console.error('QR Code generation failed:', error);
                    document.getElementById(`qrCode${order.orderNumber}`).innerHTML = '<div style="font-size: 8px;">QR کوڈ بن نہیں سکا</div>';
                }
                this.openModal('receiptModal');
            }

            generateHash(data) {
                let hash = 0;
                for (let i = 0; i < data.length; i++) {
                    const char = data.charCodeAt(i);
                    hash = ((hash << 5) - hash) + char;
                    hash = hash & hash;
                }
                return Math.abs(hash).toString(16);
            }

            async downloadReceipt() {
                const receiptElement = document.querySelector('#receiptContent .receipt');
                if (!receiptElement) {
                    this.showNotification('Receipt element not found!', 'error');
                    return;
                }
                try {
                    const canvas = await html2canvas(receiptElement, {
                        scale: 5,
                        useCORS: true,
                        backgroundColor: '#ffffff'
                    });
                    const link = document.createElement('a');
                    const orderNumberElement = receiptElement.querySelector('.receipt-item strong');
                    const orderNumber = orderNumberElement ? orderNumberElement.nextSibling.textContent.trim() : `receipt-${Date.now()}`;
                    link.download = `receipt-${orderNumber}.png`;
                    link.href = canvas.toDataURL('image/png');
                    link.click();
                    this.closeModal('receiptModal');
                    this.showNotification('Receipt downloaded as image!', 'success');
                } catch (error) {
                    console.error('Failed to download receipt:', error);
                    this.showNotification('Error downloading receipt', 'error');
                }
            }

            async addMenuItem() {
                const name = document.getElementById('itemName').value.trim();
                const price = parseFloat(document.getElementById('itemPrice').value);
                const category = document.getElementById('itemCategory').value;
                const shortcut = document.getElementById('itemShortcut').value.trim().toLowerCase();

                if (!name || !price || price <= 0) {
                    this.showNotification('براہ کرم تمام فیلڈز صحیح طریقے سے بھریں!', 'error');
                    return;
                }

                const result = await this.fetch('add_menu_item', {
                    name,
                    price,
                    category,
                    shortcut
                });
                if (result.status === 'success') {
                    this.renderMenu();
                    this.renderMenuManagement();
                    this.closeModal('addItemModal');
                    document.getElementById('itemName').value = '';
                    document.getElementById('itemPrice').value = '';
                    document.getElementById('itemCategory').value = 'مین کورس';
                    document.getElementById('itemShortcut').value = '';
                    this.showNotification('نیا آئٹم شامل کر دیا گیا', 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async editMenuItem(id) {
                const result = await this.fetch('get_menu_item_by_id', {
                    id
                });
                if (result.status === 'success' && result.data) {
                    const item = result.data;
                    document.getElementById('editItemId').value = item.id;
                    document.getElementById('editItemName').value = item.name;
                    document.getElementById('editItemPrice').value = item.price;
                    document.getElementById('editItemCategory').value = item.category;
                    document.getElementById('editItemShortcut').value = item.shortcut || '';
                    this.openModal('editItemModal');
                } else {
                    this.showNotification('آئٹم لوڈ کرنے میں خرابی', 'error');
                }
            }

            async updateMenuItem() {
                const id = parseInt(document.getElementById('editItemId').value);
                const name = document.getElementById('editItemName').value.trim();
                const price = parseFloat(document.getElementById('editItemPrice').value);
                const category = document.getElementById('editItemCategory').value;
                const shortcut = document.getElementById('editItemShortcut').value.trim().toLowerCase();

                if (!name || !price || price <= 0) {
                    this.showNotification('براہ کرم تمام فیلڈز صحیح طریقے سے بھریں!', 'error');
                    return;
                }

                const result = await this.fetch('update_menu_item', {
                    id,
                    name,
                    price,
                    category,
                    shortcut
                });
                if (result.status === 'success') {
                    this.renderMenu();
                    this.renderMenuManagement();
                    this.closeModal('editItemModal');
                    this.showNotification('آئٹم اپڈیٹ کر دیا گیا', 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async deleteMenuItem(id) {
                if (confirm('کیا آپ واقعی اس آئٹم کو ڈیلیٹ کرنا چاہتے ہیں؟')) {
                    const result = await this.fetch('delete_menu_item', {
                        id
                    });
                    if (result.status === 'success') {
                        this.renderMenu();
                        this.renderMenuManagement();
                        this.showNotification('آئٹم ڈیلیٹ کر دیا گیا', 'success');
                    } else {
                        this.showNotification(result.message, 'error');
                    }
                }
            }

            async renderOrders() {
                const result = await this.fetch('get_all_orders');
                const orders = result.data || [];
                const list = document.getElementById('ordersList');
                if (!list) return;
                list.innerHTML = '';
                orders.forEach(order => {
                    const itemsText = order.items.map(item => `${item.name} x${item.quantity}`).join(', ');
                    const verifiedStatus = order.is_verified ?
                        `<span style="color: green;">✓ تصدیق شدہ (یوزر: ${order.verified_by_user_id || 'نامعلوم'}, وقت: ${new Date(order.verified_at).toLocaleString('ur-PK')})</span>` :
                        `<span style="color: red;">✗ غیر تصدیق شدہ</span>`;
                    const div = document.createElement('div');
                    div.className = 'order-item';
                    div.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <div>
                                <div style="font-weight: bold; font-size: 16px; color: #2c3e50;">آرڈر #${order.order_number}</div>
                                <div style="color: #666; font-size: 12px; margin: 3px 0;">${new Date(order.order_date).toLocaleString('ur-PK')}</div>
                                <div style="color: #666; font-size: 12px;">ادائیگی: ${order.payment_method}</div>
                                <div style="color: #666; font-size: 12px;">حالت: ${verifiedStatus}</div>
                            </div>
                            <div style="text-align: left;">
                                <div style="font-size: 20px; font-weight: bold; color: #27ae60; margin-bottom: 6px;">Rs. ${order.total}</div>
                                <div style="display: flex; gap: 6px;">
                                    <button class="btn" onclick="pos.viewOrder(${order.id})">👁️ دیکھیں</button>
                                    ${this.userRole === 'admin' ? `<button class="btn btn-danger" onclick="pos.deleteOrder(${order.id})">🗑️ ڈیلیٹ</button>` : ''}
                                </div>
                            </div>
                        </div>
                        <div style="background: #f8f9fa; padding: 10px; border-radius: 6px; font-size: 12px;">
                            <strong>آئٹمز:</strong> ${itemsText}
                        </div>
                    `;
                    list.appendChild(div);
                });
                if (orders.length === 0) {
                    list.innerHTML = '<div style="text-align: center; padding: 25px; color: #666; font-size: 14px;">کوئی آرڈر موجود نہیں</div>';
                }
            }

            async deleteOrder(id) {
                if (confirm('کیا آپ واقعی اس آرڈر کو ڈیلیٹ کرنا چاہتے ہیں؟')) {
                    const result = await this.fetch('delete_order', {
                        id
                    });
                    if (result.status === 'success') {
                        this.renderOrders();
                        this.showNotification('آرڈر ڈیلیٹ کر دیا گیا', 'success');
                    } else {
                        this.showNotification(result.message, 'error');
                    }
                }
            }

            async viewOrder(id) {
                const result = await this.fetch('get_order_by_id', {
                    id
                });
                if (result.status === 'success' && result.data) {
                    const order = result.data;
                    const itemsList = order.items.map(item =>
                        `${item.name} x${item.quantity} = Rs.${item.price * item.quantity}`
                    ).join('\n');
                    const verifiedStatusText = order.is_verified ?
                        `تصدیق شدہ (یوزر: ${order.verified_by_user_id || 'نامعلوم'}, وقت: ${new Date(order.verified_at).toLocaleString('ur-PK')})` :
                        `غیر تصدیق شدہ`;
                    alert(`آرڈر #${order.order_number}\n\nتاریخ: ${new Date(order.order_date).toLocaleString('ur-PK')}\nادائیگی: ${order.payment_method}\nحالت: ${verifiedStatusText}\n\nآئٹمز:\n${itemsList}\n\nکل رقم: Rs.${order.total}`);
                } else {
                    this.showNotification('آرڈر لوڈ کرنے میں خرابی', 'error');
                }
            }

            initScanner() {
                if (!this.scanner) {
                    const qrboxConfig = (viewfinderWidth, viewfinderHeight) => {
                        let minEdgePercentage = 0.7;
                        let minEdgeSize = Math.min(viewfinderWidth, viewfinderHeight);
                        let qrboxSize = Math.floor(minEdgeSize * minEdgePercentage);
                        return {
                            width: qrboxSize,
                            height: qrboxSize
                        };
                    }
                    this.scanner = new Html5QrcodeScanner(
                        "reader", {
                            fps: 10,
                            qrbox: qrboxConfig,
                            aspectRatio: 1.0,
                            disableFlip: false
                        },
                        false
                    );
                    this.scanner.render((decodedText) => {
                        this.verifyReceipt(decodedText);
                        this.scanner.pause();
                    }, (error) => {
                        // console.warn('QR Scan Error:', error); // Log for debugging, but don't show to user
                    });
                }
            }

            async verifyReceipt(qrData) {
                try {
                    const data = JSON.parse(qrData);
                    const resultDiv = document.getElementById('scanResult');
                    if (!data.orderNumber || !data.total || !data.date || !data.hash) {
                        throw new Error('Invalid QR Data Structure');
                    }

                    const result = await this.fetch('verify_order_qr', {
                        qrData
                    });

                    if (result.status === 'success') {
                        resultDiv.innerHTML = `
                            <div class="scan-result scan-success">
                                <h4>✅ صحیح رسید</h4>
                                <p><strong>آرڈر:</strong> #${data.orderNumber}</p>
                                <p><strong>رقم:</strong> Rs. ${data.total}</p>
                                <p><strong>تاریخ:</strong> ${new Date(data.date).toLocaleString('ur-PK')}</p>
                                <p><strong>تصدیق:</strong> کامیابی سے تصدیق شدہ۔</p>
                            </div>
                        `;
                        this.showNotification('رسید کی تصدیق ہو گئی!', 'success');
                    } else if (result.status === 'warning') {
                        resultDiv.innerHTML = `
                            <div class="scan-result scan-warning">
                                <h4>⚠️ یہ رسید پہلے ہی تصدیق ہو چکی ہے!</h4>
                                <p><strong>آرڈر:</strong> #${data.orderNumber}</p>
                                <p><strong>رقم:</strong> Rs. ${data.total}</p>
                                <p><strong>تاریخ:</strong> ${new Date(data.date).toLocaleString('ur-PK')}</p>
                                <p><strong>پہلے تصدیق شدہ بذریعہ:</strong> ${result.data.verified_by || 'نامعلوم یوزر'}</p>
                                <p><strong>وقت:</strong> ${new Date(result.data.verified_at).toLocaleString('ur-PK')}</p>
                            </div>
                        `;
                        this.showNotification('یہ رسید پہلے ہی تصدیق ہو چکی ہے!', 'warning');
                    } else {
                        resultDiv.innerHTML = `
                            <div class="scan-result scan-error">
                                <h4>❌ غلط رسید</h4>
                                <p>${result.message}</p>
                            </div>
                        `;
                        this.showNotification(result.message, 'error');
                    }
                } catch (error) {
                    document.getElementById('scanResult').innerHTML = `
                        <div class="scan-result scan-error">
                            <h4>❌ غلط QR کوڈ</h4>
                            <p>یہ صحیح رسید کا QR کوڈ نہیں ہے یا ڈیٹا خراب ہے۔</p>
                        </div>
                    `;
                    this.showNotification('غلط QR کوڈ یا ڈیٹا خراب ہے۔', 'error');
                } finally {
                    setTimeout(() => {
                        document.getElementById('scanResult').innerHTML = '';
                        if (this.scanner && Html5QrcodeScanner.getState() !== Html5QrcodeScanner.Html5QrcodeScannerState.SCANNING) {
                            this.scanner.resume().catch(err => console.error("Error resuming scanner:", err));
                        }
                    }, 3000);
                }
            }

            async loadAdminStats() {
                if (this.userRole !== 'admin') return;
                const result = await this.fetch('get_admin_stats');
                if (result.status === 'success') {
                    const stats = result.data;
                    document.getElementById('todaySales').textContent = `Rs. ${stats.todaySales}`;
                    document.getElementById('todayOrders').textContent = stats.todayOrders;
                    document.getElementById('totalRevenue').textContent = `Rs. ${stats.totalRevenue}`;
                    document.getElementById('totalItems').textContent = stats.totalItems;
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async generateReport(type) {
                if (this.userRole !== 'admin') return;
                const result = await this.fetch('generate_report', {
                    type
                });
                if (result.status === 'success') {
                    const filteredOrders = result.data;
                    const totalSales = filteredOrders.reduce((sum, order) => sum + order.total, 0);
                    const totalOrders = filteredOrders.length;
                    const itemSales = {};
                    filteredOrders.forEach(order => {
                        order.items.forEach(item => {
                            if (itemSales[item.name]) {
                                itemSales[item.name] += item.quantity;
                            } else {
                                itemSales[item.name] = item.quantity;
                            }
                        });
                    });
                    const bestSelling = Object.entries(itemSales)
                        .sort(([, a], [, b]) => b - a)
                        .slice(0, 10);
                    const paymentMethods = {};
                    filteredOrders.forEach(order => {
                        if (paymentMethods[order.paymentMethod]) {
                            paymentMethods[order.paymentMethod]++;
                        } else {
                            paymentMethods[order.paymentMethod] = 1;
                        }
                    });

                    let reportTitle = '';
                    switch (type) {
                        case 'daily':
                            reportTitle = 'روزانہ رپورٹ';
                            break;
                        case 'weekly':
                            reportTitle = 'ہفتہ وار رپورٹ';
                            break;
                        case 'monthly':
                            reportTitle = 'ماہانہ رپورٹ';
                            break;
                    }

                    const reportHtml = `
                        <div class="report-section">
                            <h3 style="text-align: center; margin-bottom: 15px; color: #2c3e50; font-size: 18px;">${reportTitle}</h3>
                            <div class="stats-grid">
                                <div class="stat-card">
                                    <div class="stat-number">${totalOrders}</div>
                                    <div class="stat-label">کل آرڈرز</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-number">Rs. ${totalSales}</div>
                                    <div class="stat-label">کل فروخت</div>
                                </div>
                            </div>
                            <div style="margin: 20px 0;">
                                <h4 style="color: #2c3e50; margin-bottom: 10px; font-size: 16px;">🏆 سب سے زیادہ فروخت ہونے والے آئٹمز:</h4>
                                <div style="background: #f8f9fa; padding: 12px; border-radius: 6px;">
                                    ${bestSelling.length > 0 ?
                            bestSelling.map(([item, qty], index) => `
    <div class="report-list-item">
        <span>${index + 1}. ${item}</span>
        <span class="report-value success">${qty} فروخت</span>
    </div>
`).join('') :
                            '<div style="text-align: center; color: #666; font-size: 13px;">کوئی ڈیٹا دستیاب نہیں</div>'
                        }
                                </div>
                            </div>
                            <div style="margin: 20px 0;">
                                <h4 style="color: #2c3e50; margin-bottom: 10px; font-size: 16px;">💳 ادائیگی کے طریقے:</h4>
                                <div style="background: #f8f9fa; padding: 12px; border-radius: 6px;">
                                    ${Object.entries(paymentMethods).length > 0 ?
                            Object.entries(paymentMethods).map(([method, count]) => `
    <div class="report-list-item">
        <span>${method}</span>
        <span class="report-value info">${count} آرڈرز</span>
    </div>
`).join('') :
                            '<div style="text-align: center; color: #666; font-size: 13px;">کوئی ڈیٹا دستیاب نہیں</div>'
                        }
                                </div>
                            </div>
                            <div style="text-align: center; margin-top: 15px;">
                                <button class="btn btn-success" onclick="pos.exportReportCSV('${type}', ${JSON.stringify(filteredOrders).replace(/"/g, '&quot;')})">
                                    📊 CSV میں ایکسپورٹ کریں
                                </button>
                            </div>
                        </div>
                    `;
                    document.getElementById('reportResults').innerHTML = reportHtml;
                    this.showNotification(`${reportTitle} تیار ہو گئی`, 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            exportReportCSV(type, orders) {
                try {
                    let csv = 'آرڈر نمبر,تاریخ,ادائیگی کا طریقہ,کل رقم,آئٹمز,تصدیق شدہ,تصدیق شدہ یوزر,تصدیق کی تاریخ\n';
                    orders.forEach(order => {
                        const itemsText = order.items.map(item => `${item.name} x${item.quantity}`).join('; ');
                        const date = new Date(order.order_date).toLocaleDateString('ur-PK');
                        const verifiedStatus = order.is_verified ? 'ہاں' : 'نہیں';
                        const verifiedByUser = order.verified_by_user_id || '';
                        const verifiedAt = order.verified_at ? new Date(order.verified_at).toLocaleString('ur-PK') : '';
                        csv += `"${order.order_number}","${date}","${order.payment_method}",${order.total},"${itemsText}","${verifiedStatus}","${verifiedByUser}","${verifiedAt}"\n`;
                    });
                    const blob = new Blob([csv], {
                        type: 'text/csv;charset=utf-8'
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${type}-report-${new Date().toISOString().split('T')[0]}.csv`;
                    a.click();
                    URL.revokeObjectURL(url);
                    this.showNotification('رپورٹ ایکسپورٹ ہو گئی', 'success');
                } catch (error) {
                    console.error('Export CSV error:', error);
                    this.showNotification('ایکسپورٹ کرنے میں خرابی', 'error');
                }
            }

            async exportData() {
                if (this.userRole !== 'admin') return;
                const result = await this.fetch('export_data');
                if (result.status === 'success') {
                    const exportData = result.data;
                    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
                        type: 'application/json'
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `restaurant-pos-backup-${new Date().toISOString().split('T')[0]}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                    this.showNotification('ڈیٹا ایکسپورٹ ہو گیا', 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async importData() {
                if (this.userRole !== 'admin') return;
                const fileInput = document.getElementById('importFile');
                const file = fileInput.files[0];
                if (!file) {
                    this.showNotification('براہ کرم فائل منتخب کریں!', 'error');
                    return;
                }
                const reader = new FileReader();
                reader.onload = async (e) => {
                    try {
                        const data = JSON.parse(e.target.result);
                        if (confirm('یہ تمام موجودہ ڈیٹا کو تبدیل کر دے گا۔ کیا آپ واقعی جاری رکھنا چاہتے ہیں؟')) {
                            const result = await this.fetch('import_data', {
                                data: JSON.stringify(data)
                            });
                            if (result.status === 'success') {
                                this.renderMenu();
                                this.renderMenuManagement();
                                this.renderOrders();
                                this.loadSettings();
                                this.showNotification('ڈیٹا کامیابی سے امپورٹ ہو گیا!', 'success');
                                this.closeModal('importModal');
                                fileInput.value = '';
                                if (this.userRole === 'admin') {
                                    this.loadAdminStats();
                                    this.renderUsers();
                                }
                            } else {
                                this.showNotification(result.message, 'error');
                            }
                        }
                    } catch (error) {
                        console.error('Import error:', error);
                        this.showNotification('غلط فائل فارمیٹ یا ڈیٹا کرپٹ ہے!', 'error');
                    }
                };
                reader.readAsText(file);
            }

            async getSettings() {
                const result = await this.fetch('get_settings');
                return result.data || {};
            }

            async loadSettings() {
                const settings = await this.getSettings();
                document.getElementById('restaurantName').value = settings.restaurantName || '';
                document.getElementById('restaurantAddress').value = settings.restaurantAddress || '';
                document.getElementById('restaurantPhone').value = settings.restaurantPhone || '';
            }

            async saveCurrentSettings() {
                if (this.userRole !== 'admin') return;
                const settings = {
                    restaurantName: document.getElementById('restaurantName').value.trim(),
                    restaurantAddress: document.getElementById('restaurantAddress').value.trim(),
                    restaurantPhone: document.getElementById('restaurantPhone').value.trim()
                };
                if (!settings.restaurantName) {
                    this.showNotification('ریستوران کا نام ضروری ہے!', 'error');
                    return;
                }
                const result = await this.fetch('save_settings', {
                    settings: JSON.stringify(settings)
                });
                if (result.status === 'success') {
                    this.showNotification('سیٹنگز محفوظ ہو گئیں!', 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            async renderUsers() {
                if (this.userRole !== 'admin') return;
                const result = await this.fetch('get_users');
                const users = result.data || [];
                const list = document.getElementById('usersList');
                if (!list) return;
                list.innerHTML = '';
                users.forEach(user => {
                    const div = document.createElement('div');
                    div.className = 'user-item';
                    div.innerHTML = `
                        <div class="user-info-section">
                            <div style="font-weight: bold; font-size: 16px; color: #2c3e50;">${user.username}</div>
                            <div style="color: #666; font-size: 12px;">رول: ${user.role === 'admin' ? 'ایڈمن' : 'ویریفائر'}</div>
                        </div>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            <button class="btn btn-warning" onclick="pos.editUser(${user.id}, '${user.username}', '${user.role}')">✏️ ایڈٹ</button>
                            <button class="btn btn-danger" onclick="pos.deleteUser(${user.id})">🗑️ ڈیلیٹ</button>
                        </div>
                    `;
                    list.appendChild(div);
                });
                if (users.length === 0) {
                    list.innerHTML = '<div style="text-align: center; padding: 25px; color: #666; font-size: 14px;">کوئی یوزر موجود نہیں</div>';
                }
            }

            async addUser() {
                if (this.userRole !== 'admin') return;
                const username = document.getElementById('newUsername').value.trim();
                const password = document.getElementById('newUserPassword').value.trim();
                const role = document.getElementById('newUserRole').value;

                if (!username || !password) {
                    this.showNotification('براہ کرم یوزرنیم اور پاس ورڈ درج کریں۔', 'error');
                    return;
                }

                const result = await this.fetch('add_user', {
                    username,
                    password,
                    role
                });
                if (result.status === 'success') {
                    this.renderUsers();
                    this.closeModal('addUserModal');
                    document.getElementById('newUsername').value = '';
                    document.getElementById('newUserPassword').value = '';
                    document.getElementById('newUserRole').value = 'verifier';
                    this.showNotification('یوزر کامیابی سے شامل کر دیا گیا', 'success');
                } else {
                    this.showNotification(result.message, 'error');
                }
            }

            editUser(id, username, role) {
                if (this.userRole !== 'admin') return;
                document.getElementById('editUserId').value = id;
                document.getElementById('editUserUsername').value = username;
                document.getElementById('editUserNewPassword').value = '';
                document.getElementById('editUserRole').value = role;
                this.openModal('editUserModal');
            }

            async updateUser() {
                if (this.userRole !== 'admin') return;
                const id = parseInt(document.getElementById('editUserId').value);
                const newPassword = document.getElementById('editUserNewPassword').value.trim();
                const role = document.getElementById('editUserRole').value;

                if (newPassword) {
                    const result = await this.fetch('update_user_password', {
                        id,
                        new_password: newPassword
                    });
                    if (result.status !== 'success') {
                        this.showNotification(result.message, 'error');
                        return;
                    }
                }

                const resultRole = await this.fetch('update_user_role', {
                    id,
                    role
                });
                if (resultRole.status === 'success') {
                    this.renderUsers();
                    this.closeModal('editUserModal');
                    this.showNotification('یوزر کامیابی سے اپڈیٹ ہو گیا', 'success');
                } else {
                    this.showNotification(resultRole.message, 'error');
                }
            }

            async deleteUser(id) {
                if (this.userRole !== 'admin') return;
                if (confirm('کیا آپ واقعی اس یوزر کو ڈیلیٹ کرنا چاہتے ہیں؟')) {
                    const result = await this.fetch('delete_user', {
                        id
                    });
                    if (result.status === 'success') {
                        this.renderUsers();
                        this.showNotification('یوزر کامیابی سے ڈیلیٹ کر دیا گیا', 'success');
                    } else {
                        this.showNotification(result.message, 'error');
                    }
                }
            }

            openModal(modalId) {
                const modal = document.getElementById(modalId);
                if (modal) {
                    modal.style.display = 'flex';
                    document.body.style.overflow = 'hidden';
                }
            }

            closeModal(modalId) {
                const modal = document.getElementById(modalId);
                if (modal) {
                    modal.style.display = 'none';
                    document.body.style.overflow = 'auto';
                }
            }

            showNotification(message, type = 'info') {
                const existingNotification = document.querySelector('.notification');
                if (existingNotification) {
                    clearTimeout(existingNotification.hideTimeout);
                    existingNotification.remove();
                }
                const notification = document.createElement('div');
                notification.className = `notification ${type}`;
                notification.textContent = message;
                document.body.appendChild(notification);
                setTimeout(() => notification.classList.add('show'), 100);
                notification.hideTimeout = setTimeout(() => {
                    notification.classList.remove('show');
                    setTimeout(() => notification.remove(), 400);
                }, 3000);
            }
        }

        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            const clickedButton = document.querySelector(`.nav-tab[onclick="showTab('${tabId}')"]`);
            if (clickedButton) {
                clickedButton.classList.add('active');
            }
            if (tabId === 'scanner') {
                setTimeout(() => pos.initScanner(), 500);
            } else {
                if (pos.scanner) {
                    pos.scanner.clear().catch(err => console.error("Error clearing scanner on tab change:", err));
                    pos.scanner = null;
                }
            }
            if (tabId === 'admin') {
                pos.loadAdminStats();
            }
            if (tabId === 'users') {
                pos.renderUsers();
            }
        }

        function openModal(modalId) {
            pos.openModal(modalId);
        }

        function closeModal(modalId) {
            pos.closeModal(modalId);
        }

        function addMenuItem() {
            pos.addMenuItem();
        }

        function updateMenuItem() {
            pos.updateMenuItem();
        }

        function addUser() {
            pos.addUser();
        }

        function updateUser() {
            pos.updateUser();
        }

        function generateReport(type) {
            pos.generateReport(type);
        }

        function exportData() {
            pos.exportData();
        }

        function importData() {
            pos.importData();
        }

        function saveSettings() {
            pos.saveCurrentSettings();
        }

        function checkout() {
            pos.checkout();
        }

        function clearCart() {
            pos.clearCart();
        }

        function downloadReceipt() {
            pos.downloadReceipt();
        }

        const pos = new RestaurantPOS();

        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        };

        document.addEventListener('keydown', async function(e) {
            if (e.altKey) {
                switch (e.key) {
                    case '1':
                        showTab('pos');
                        break;
                    case '2':
                        if (pos.userRole === 'admin') showTab('menu');
                        break;
                    case '3':
                        showTab('orders');
                        break;
                    case '4':
                        showTab('scanner');
                        break;
                    case '5':
                        if (pos.userRole === 'admin') showTab('admin');
                        break;
                    case '6':
                        if (pos.userRole === 'admin') showTab('users');
                        break;
                    case '7':
                        if (pos.userRole === 'admin') showTab('settings');
                        break;
                }
            }
            if (e.key === 'Escape') {
                const modals = document.querySelectorAll('.modal');
                modals.forEach(modal => {
                    if (modal.style.display === 'flex') {
                        modal.style.display = 'none';
                        document.body.style.overflow = 'auto';
                    }
                });
            }
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                checkout();
            }
            const posTab = document.getElementById('pos');
            if (posTab && posTab.classList.contains('active') && !e.altKey && !e.ctrlKey && !e.shiftKey && pos.userRole !== 'guest') {
                if (!e.key) return;
                const key = e.key.toLowerCase();
                if (pos.shortcuts[key]) {
                    e.preventDefault();
                    const itemId = pos.shortcuts[key];
                    const items = await pos.getMenuItems();
                    const item = items.find(i => i.id === itemId);
                    if (item) {
                        pos.addToCart(item.id, item.name, item.price);
                    }
                }
            }
        });

        document.addEventListener('DOMContentLoaded', function() {
            if (pos.userRole !== 'guest') {
                pos.showNotification('🎉 ریستوران POS سسٹم تیار ہے!', 'success');
                const searchBox = document.getElementById('menuSearch');
                if (searchBox) {
                    searchBox.focus();
                    setTimeout(() => {
                        searchBox.value = '';
                    }, 900);
                }
            }
        });

        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                if (pos.scanner) {
                    pos.scanner.clear().catch(err => console.error("Error clearing scanner on visibility change:", err));
                    pos.scanner = null;
                }
            } else {
                const activeTab = document.querySelector('.tab-content.active');
                if (activeTab && activeTab.id === 'scanner') {
                    setTimeout(() => pos.initScanner(), 1000);
                }
            }
        });

        setInterval(() => {
            if (pos.currentCart.length > 0) {
                localStorage.setItem('restaurant-pos-cart', JSON.stringify({
                    cart: pos.currentCart,
                    timestamp: Date.now()
                }));
            } else {
                localStorage.removeItem('restaurant-pos-cart');
            }
        }, 10000);

        try {
            const savedCart = localStorage.getItem('restaurant-pos-cart');
            if (savedCart) {
                const cartData = JSON.parse(savedCart);
                const timeDiff = Date.now() - cartData.timestamp;
                if (timeDiff < 3600000 && cartData.cart.length > 0) {
                    pos.currentCart = cartData.cart;
                    pos.updateCartDisplay();
                    pos.showNotification('پچھلا کارٹ بحال کر دیا گیا', 'info');
                }
            }
        } catch (error) {
            console.error('Failed to restore cart:', error);
        }
    </script>
</body>

</html>