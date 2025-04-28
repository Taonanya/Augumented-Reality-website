<?php
// Check if the form was submitted via POST method
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate that all required fields exist and are not empty
    $required_fields = ['fullname', 'email', 'username', 'password'];
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
    $fullname = htmlspecialchars(trim($_POST['fullname']));
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $username = htmlspecialchars(trim($_POST['username']));
    $password = password_hash(trim($_POST['password']), PASSWORD_DEFAULT); // Hash the password
    
    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format");
    }
    
    // Database Connection
    $conn = new mysqli('localhost', 'root', '1234', 'ar_education102');
    if ($conn->connect_error) {
        die('Connection Failed: ' . $conn->connect_error);
    }
    
    try {
        // Prepare the statement
        $stmt = $conn->prepare("INSERT INTO registration(fullname, email, username, password) VALUES (?, ?, ?, ?)");
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }
        
        // Bind parameters and execute
        $stmt->bind_param("ssss", $fullname, $email, $username, $password);
        if (!$stmt->execute()) {
            throw new Exception("Execute failed: " . $stmt->error);
        }
        
        echo "Registration Successful!";
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