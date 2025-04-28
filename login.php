<?php
// Check if the form was submitted via POST method
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate that all required fields exist and are not empty
    $required_fields = ['username', 'password'];
    $errors = [];
    
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            $errors[] = ucfirst($field) . " is required";
        }
    }
    
    // If there are errors, display them and stop execution
    if (!empty($errors)) {
        die(implode("<br>", $errors));
    }
    
    // Sanitize and validate inputs
    $username = htmlspecialchars(trim($_POST['username']));
    $password = password_hash(trim($_POST['password']), PASSWORD_DEFAULT); // Hash the password

    
    // Database Connection
    $conn = new mysqli('localhost', 'root', '1234', 'ar_education102');
    if ($conn->connect_error) {
        die('Connection Failed: ' . $conn->connect_error);
    }
    
    try {
        // Prepare the statement
        $stmt = $conn->prepare("INSERT INTO login(username, password) VALUES ( ?, ?)");
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }
        
        // Bind parameters and execute
        $stmt->bind_param("ss", $username, $password);
        if (!$stmt->execute()) {
            throw new Exception("Execute failed: " . $stmt->error);
        }
        
        echo "Login Successful!";
    } catch (Exception $e) {
        die("Error: " . $e->getMessage());
    } finally {
        // Close connections
        if (isset($stmt)) $stmt->close();
        $conn->close();
    }
} else {
    die("Invalid request method. Please submit the form.");
}
?>






<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Augmented Reality Education</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f8ff;
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .register-container {
            max-width: 400px;
            width: 100%;
            padding: 30px;
            border: 1px solid #007BFF;
            border-radius: 8px;
            background-color: #ffffff;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .register-container h2 {
            text-align: center;
            color: #007BFF;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #007BFF;
            border-radius: 5px;
            box-sizing: border-box;
        }
        .error-message {
            color: red;
            margin-bottom: 15px;
            text-align: center;
        }
        .success-message {
            color: green;
            margin-bottom: 15px;
            text-align: center;
        }
        .submit-btn {
            width: 100%;
            padding: 12px;
            background-color: #007BFF;
            color: #ffffff;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        .submit-btn:hover {
            background-color: #0056b3;
        }
        .login-link {
            text-align: center;
            margin-top: 15px;
        }
        .login-link a {
            color: #007BFF;
            text-decoration: none;
        }
        .login-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h2>Create an Account</h2>
        
        <?php if (!empty($errors)): ?>
            <div class="error-message">
                <?php echo implode("<br>", $errors); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['success']) && $_GET['success'] == '1'): ?>
            <div class="success-message">
                Registration successful! You can now <a href="login.html">login</a>.
            </div>
        <?php endif; ?>
        
        <form action="register.php" method="POST" id="registration-form">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <div class="form-group">
                <label for="confirm-password">Confirm Password:</label>
                <input type="password" id="confirm-password" name="confirm_password" required>
            </div>
            
            <button type="submit" class="submit-btn">Register</button>
        </form>
    </div>

    <script>
        document.getElementById('registration-form').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            if (password !== confirmPassword) {
                e.preventDefault();
                alert('Passwords do not match!');
                return false;
            }
            
            if (password.length < 8) {
                e.preventDefault();
                alert('Password must be at least 8 characters long!');
                return false;
            }
            
            return true;
        });
    </script>
</body>
</html>