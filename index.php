<?php
session_start();
require_once 'db.php';

// Check if user is logged in
$currentUser = null;
$isLoggedIn = false;
if (isset($_SESSION['user_id'])) {
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $currentUser = $stmt->fetch();
    $isLoggedIn = true;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Augmented Reality Education</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #007BFF;
            --primary-dark: #0056b3;
            --primary-light: #e6f2ff;
            --white: #ffffff;
            --light-gray: #f8f9fa;
            --dark-gray: #343a40;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background-color: var(--light-gray);
            color: var(--dark-gray);
            line-height: 1.6;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: var(--white);
            padding: 1.5rem 0;
            text-align: center;
            position: relative;
            box-shadow: var(--shadow);
        }
        
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            position: relative;
        }
        
        h1 {
            font-size: 2.2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .tagline {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        nav {
            background-color: var(--primary-dark);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow);
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        nav a {
            color: var(--white);
            text-decoration: none;
            margin: 0 1rem;
            padding: 0.5rem 1rem;
            font-weight: 500;
            border-radius: 4px;
            transition: var(--transition);
            position: relative;
        }
        
        nav a:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        nav a::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 0;
            width: 0;
            height: 2px;
            background-color: var(--white);
            transition: var(--transition);
        }
        
        nav a:hover::after {
            width: 100%;
        }
        
        .auth-buttons {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
        }
        
        .btn {
            padding: 0.6rem 1.2rem;
            border-radius: 4px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            border: none;
            font-family: 'Poppins', sans-serif;
        }
        
        .btn-primary {
            background-color: var(--white);
            color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-light);
            transform: translateY(-2px);
        }
        
        .btn-outline {
            background-color: transparent;
            color: var(--white);
            border: 1px solid var(--white);
        }
        
        .btn-outline:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        main {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 20px;
        }
        
        .content-section {
            background-color: var(--white);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
            animation: fadeIn 0.5s ease;
            display: none;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .content-section h2 {
            color: var(--primary-dark);
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        .content-section h2::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 60px;
            height: 3px;
            background-color: var(--primary-color);
        }
        
        .content-section p {
            margin-bottom: 1.5rem;
            color: #555;
        }
        
        .login-container {
            max-width: 500px;
            margin: 2rem auto;
            background-color: var(--white);
            border-radius: 8px;
            padding: 2rem;
            box-shadow: var(--shadow);
            display: none;
            animation: fadeIn 0.5s ease;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--dark-gray);
        }
        
        .form-group input {
            width: 100%;
            padding: 0.8rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Poppins', sans-serif;
            transition: var(--transition);
        }
        
        .form-group input:focus {
            border-color: var(--primary-color);
            outline: none;
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25);
        }
        
        .submit-btn {
            width: 100%;
            padding: 0.8rem;
            background-color: var(--primary-color);
            color: var(--white);
            border: none;
            border-radius: 4px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
        }
        
        .submit-btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
        }
        
        .message {
            padding: 0.8rem;
            margin-bottom: 1rem;
            border-radius: 4px;
            text-align: center;
        }
        
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .success-message {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .link-text {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
        }
        
        .link-text:hover {
            text-decoration: underline;
        }
        
        .text-center {
            text-align: center;
        }
        
        .mt-3 {
            margin-top: 1.5rem;
        }
        
        .vr-button {
            display: inline-block;
            padding: 1rem 2rem;
            background-color: var(--primary-color);
            color: var(--white);
            text-decoration: none;
            border-radius: 4px;
            font-weight: 600;
            margin: 1.5rem 0;
            transition: var(--transition);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .vr-button:hover {
            background-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15);
        }
        
        .vr-description {
            font-style: italic;
            color: #666;
            margin-top: 0.5rem;
        }
        
        .feature-image {
            width: 100%;
            max-height: 400px;
            object-fit: cover;
            border-radius: 8px;
            margin: 1.5rem 0;
            box-shadow: var(--shadow);
        }
        
        footer {
            background-color: var(--dark-gray);
            color: var(--white);
            text-align: center;
            padding: 1.5rem 0;
            margin-top: 2rem;
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 1.8rem;
            }
            
            .nav-container {
                flex-direction: column;
                align-items: center;
            }
            
            nav a {
                margin: 0.3rem 0;
            }
            
            .auth-buttons {
                position: static;
                transform: none;
                margin-top: 1rem;
            }
            /* Library Section Styles */
.library-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin: 2rem 0;
}

.library-category {
    background-color: var(--white);
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: var(--shadow);
    transition: var(--transition);
}

.library-category:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
}

.textbook-container {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
}

.textbook-image {
    width: 150px;
    height: 200px;
    object-fit: cover;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
}

.textbook-list ul {
    margin-left: 1rem;
    list-style-type: disc;
}

.textbook-list li {
    margin-bottom: 0.5rem;
    font-size: 0.9rem;
}

.library-features {
    margin-top: 3rem;
}

.features-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-top: 1.5rem;
}

.feature-item {
    text-align: center;
}

.feature-item img {
    width: 100%;
    height: 180px;
    object-fit: cover;
    border-radius: 8px;
    margin-bottom: 0.5rem;
}

.feature-item p {
    font-weight: 500;
    color: var(--dark-gray);
}

@media (max-width: 768px) {
    .textbook-container {
        flex-direction: column;
    }
    
    .textbook-image {
        width: 100%;
        height: 150px;
    }
   }
 }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <h1>Dzidzo Augmented Reality Education</h1>
            <p class="tagline">Transforming learning through immersive technology</p>
            <div class="auth-buttons">
                <button class="btn btn-primary" id="login-button" onclick="showSection('login')">Login</button>
                <button class="btn btn-outline logout-btn" id="logout-button" onclick="logout()">Logout</button>
            </div>
        </div>
    </header>
    
    <nav>
        <div class="nav-container">
            <a href="#" onclick="showSection('home')">Home</a>
            <a href="#" onclick="showSection('library')">Library</a>
            <a href="#" onclick="showSection('classes')">Classes</a>
            <a href="#" onclick="showSection('about')">About</a>
            <a href="#" onclick="showSection('register')">Register</a>
        </div>
    </nav>

    <main>
        <!-- Home Section -->
              <section id="home" class="content-section">
                <h2>Welcome to the Future of Education</h2>
                <img src="https://images.unsplash.com/photo-1626785774573-4b799315345d?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80" alt="Students using AR in education" class="feature-image">
                <p>Explore the exciting world of augmented reality in education. Our platform revolutionizes the learning process by bringing abstract concepts to life through immersive AR experiences.</p>
                <p>With Dzidzo, students can interact with 3D models, explore virtual environments, and gain a deeper understanding of complex subjects through hands-on, visual learning.</p>
                
                <div style="margin-top: 2rem; display: flex; justify-content: space-around; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 250px; margin: 1rem; text-align: center;">
                        <h3 style="color: var(--primary-dark); margin-bottom: 1rem;">Interactive Learning</h3>
                        <p>Engage with 3D educational content that makes learning memorable</p>
                    </div>
                    <div style="flex: 1; min-width: 250px; margin: 1rem; text-align: center;">
                        <h3 style="color: var(--primary-dark); margin-bottom: 1rem;">Immersive Experiences</h3>
                        <p>Step into virtual environments that bring lessons to life</p>
                    </div>
                    <div style="flex: 1; min-width: 250px; margin: 1rem; text-align: center;">
                        <h3 style="color: var(--primary-dark); margin-bottom: 1rem;">Enhanced Understanding</h3>
                        <p>Visualize complex concepts through augmented reality</p>
                    </div>
                </div>
            </section>
    
        
        <!-- Library Section -->
<section id="library" class="content-section">
    <h2>Knowledge Library</h2>
    <?php if ($isLoggedIn): ?>
    <p>Explore our comprehensive collection of university textbooks and augmented reality learning resources:</p>
    
    <div class="library-grid">
        <!-- Science Textbooks -->
        <div class="library-category">
            <h3 style="color: var(--primary-dark); margin-bottom: 1rem; border-bottom: 2px solid var(--primary-color); padding-bottom: 0.5rem;">Science & Technology</h3>
            <div class="textbook-container">
                <img src="https://images.unsplash.com/photo-1589998059171-988d887df646?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=80" alt="Science textbooks" class="textbook-image">
                <div class="textbook-list">
                    <ul>
                        <li>University Physics with Modern Physics</li>
                        <li>Molecular Biology of the Cell</li>
                        <li>Organic Chemistry by Clayden</li>
                        <li>Introduction to Algorithms</li>
                        <li>Computer Networking: A Top-Down Approach</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Engineering Textbooks -->
        <div class="library-category">
            <h3 style="color: var(--primary-dark); margin-bottom: 1rem; border-bottom: 2px solid var(--primary-color); padding-bottom: 0.5rem;">Engineering</h3>
            <div class="textbook-container">
                <img src="https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=80" alt="Engineering textbooks" class="textbook-image">
                <div class="textbook-list">
                    <ul>
                        <li>Mechanics of Materials</li>
                        <li>Fundamentals of Electric Circuits</li>
                        <li>Chemical Engineering Design</li>
                        <li>Structures: Or Why Things Don't Fall Down</li>
                        <li>Control Systems Engineering</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Medicine Textbooks -->
        <div class="library-category">
            <h3 style="color: var(--primary-dark); margin-bottom: 1rem; border-bottom: 2px solid var(--primary-color); padding-bottom: 0.5rem;">Medicine</h3>
            <div class="textbook-container">
                <img src="https://images.unsplash.com/photo-1576091160550-2173dba999ef?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=80" alt="Medical textbooks" class="textbook-image">
                <div class="textbook-list">
                    <ul>
                        <li>Gray's Anatomy for Students</li>
                        <li>Robbins and Cotran Pathologic Basis of Disease</li>
                        <li>Harrison's Principles of Internal Medicine</li>
                        <li>Netter's Atlas of Human Anatomy</li>
                        <li>Basic & Clinical Pharmacology</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- AR/VR Resources -->
        <div class="library-category">
            <h3 style="color: var(--primary-dark); margin-bottom: 1rem; border-bottom: 2px solid var(--primary-color); padding-bottom: 0.5rem;">AR/VR Resources</h3>
            <div class="textbook-container">
                <img src="https://images.unsplash.com/photo-1581092921461-39b2f2aa99b3?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=80" alt="AR/VR resources" class="textbook-image">
                <div class="textbook-list">
                    <ul>
                        <li>Interactive 3D Human Anatomy</li>
                        <li>Molecular Structures in AR</li>
                        <li>Virtual Engineering Labs</li>
                        <li>Historical Events Recreated in VR</li>
                        <li>Geographical Explorations</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <div class="library-features">
        <h3 style="color: var(--primary-dark); margin: 2rem 0 1rem; text-align: center;">Library Features</h3>
        <div class="features-grid">
            <div class="feature-item">
                <img src="https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?ixlib=rb-1.2.1&auto=format&fit=crop&w=300&q=80" alt="Library study area" class="feature-image">
                <p>24/7 Digital Access to all resources</p>
            </div>
            <div class="feature-item">
                <img src="https://images.unsplash.com/photo-1501504905252-473c47e087f8?ixlib=rb-1.2.1&auto=format&fit=crop&w=300&q=80" alt="Library bookshelves" class="feature-image">
                <p>Over 10,000 digital textbooks available</p>
            </div>
            <div class="feature-item">
                <img src="https://images.unsplash.com/photo-1588072432836-e10032774350?ixlib=rb-1.2.1&auto=format&fit=crop&w=300&q=80" alt="AR in education" class="feature-image">
                <p>500+ AR-enhanced learning materials</p>
            </div>
        </div>
    </div>
    <?php else: ?>
        <div class="message error-message">
            Please <a href="#" class="link-text" onclick="showSection('login')">login</a> or 
            <a href="#" class="link-text" onclick="showSection('register')">register</a> to access our library resources.
        </div>
        <img src="https://images.unsplash.com/photo-1501504905252-473c47e087f8?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80" alt="Library Preview" class="feature-image">
        <p>Our comprehensive library of AR-enhanced learning materials is available to registered users. Gain access to thousands of interactive resources by creating an account.</p>
    <?php endif; ?>
</section>
        
  <!-- Classes Section -->
<section id="classes" class="content-section">
    <h2>Immersive Classes</h2>
    <div id="classes-content">
        <?php if ($isLoggedIn): ?>
            <p>Join our innovative AR-enhanced classes designed to make learning more engaging and effective:</p>
            <div style="text-align: center;">
                <a href="vr-classroom.php" class="vr-button" id="vr-classroom-link">
                    Join Virtual Reality Classroom 1
                </a>
                <p class="vr-description">Experience our fully immersive VR learning environment</p>
            </div>

            <div style="text-align: center;">
                <a href="vr-classroom2.php" class="vr-button" id="vr-classroom-link">
                    Join Virtual Reality Classroom 2
                </a>
                <p class="vr-description">Experience our fully immersive VR learning environment</p>
            </div>

            <p>Our classes combine traditional teaching methods with cutting-edge AR technology to create unforgettable learning experiences that improve retention and understanding.</p>
        <?php else: ?>
            <div class="message error-message">
                Please <a href="#" class="link-text" onclick="showSection('register'); return false;">register</a> and 
                <a href="#" class="link-text" onclick="showSection('login'); return false;">login</a> to access our VR classes.
            </div>
            <img src="assets/images/vr-preview.jpg" alt="VR Classes Preview" class="feature-image">
            <p>Our immersive VR classes are available to registered users only. Please create an account to experience our cutting-edge virtual reality classrooms.</p>
        <?php endif; ?>
    </div>
</section>


<!-- About Section -->
        <section id="about" class="content-section">
            <h2>About Our Mission</h2>
            <p>Dzidzo was founded with a simple goal: to make education more exciting, accessible, engaging, and effective through augmented reality, virtual reality and AI technology.</p>
            <p>Our team of educators, developers, and designers work together to create learning experiences that:</p>
            <ul style="margin-left: 2rem; margin-bottom: 1.5rem;">
                <li>Cater to different learning styles</li>
                <li>Bring abstract concepts to life</li>
                <li>Make learning fun and interactive</li>
                <li>Prepare students for the technology-driven future</li>
            </ul>
        </section>
        
        <!-- Login Section -->
        <div class="login-container" id="login">
            <h2>Login to Your Account</h2>
            <form id="login-form" onsubmit="event.preventDefault(); loginUser();"></form>
            <div class="error-message message" id="error-message" style="display: none;"></div>
            <div class="success-message message" id="success-message" style="display: none;"></div>
            
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>    
                
                <button type="button" class="submit-btn" onclick="loginUser()">Login</button>
            </form>
            
            <div class="text-center mt-3">
                Don't have an account? <a href="#" class="link-text" onclick="showSection('register')">Register here</a>
            </div>
            
            <div class="text-center mt-3">
                <a href="#" class="link-text" onclick="showSection('home')">← Back to Home</a>
            </div>
        </div>

        <!-- Registration Section -->
        <div class="registration-container" id="register">
            <h2>Create Your Account</h2>
            <form id="registration-form" onsubmit="event.preventDefault(); registerUser();">
            <div class="form-group">
                    <label for="reg_full_name">Full Name:</label>
                    <input type="text" id="reg_full_name" name="reg_full_name" required>
                </div>
                <div class="form-group">
                    <label for="reg_email">Email:</label>
                    <input type="email" id="reg_email" name="reg_email" required>
                </div>
                <div class="form-group">
                    <label for="reg_username">Username:</label>
                    <input type="text" id="reg_username" name="reg_username" required>
                </div>
                
                <div class="form-group">
                    <label for="reg_password">Password:</label>
                    <input type="password" id="reg_password" name="reg_password" required>
                </div>
                
                <div class="form-group">
                    <label for="reg_confirm_password">Confirm Password:</label>
                    <input type="password" id="reg_confirm_password" name="reg_confirm_password" required>
                </div>
                
                <button id="register-btn" type="button" class="submit-btn" onclick="registerUser()">Register</button>
            </form>
            <div class="text-center mt-3">
                <a href="#" class="link-text" onclick="showSection('home')">← Back to Home</a>
            </div>
        </div>
    </main>
    
    <footer>
        <p>© 2025 Dzidzo Augmented Reality Education. All Rights Reserved.</p>
    </footer>
    
    
    <script>
        let users = []; // Simulated user database
        let currentUser = null;
        // Add this function to check authentication
function checkAuth() {
    return <?php echo $isLoggedIn ? 'true' : 'false'; ?>;
}

// Modify showSection function to handle protected sections
function showSection(sectionId) {
    // Protected sections that require login
    const protectedSections = ['library', 'classes'];
    
    if (protectedSections.includes(sectionId)) {  // Added missing closing parenthesis
        if (!checkAuth()) {
            showSection('login');
            document.getElementById('error-message').innerText = "Please login to access this section.";
            document.getElementById('error-message').style.display = 'block';
            return;
        }
    }
    
    const sections = document.querySelectorAll('.content-section, .login-container, .registration-container');
    sections.forEach(section => {
        section.style.display = 'none';
    });
    
    const activeSection = document.getElementById(sectionId);
    if (activeSection) {
        activeSection.style.display = 'block';
    } else {
        document.getElementById('home').style.display = 'block';
    }
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

        function showSection(sectionId) {
            const sections = document.querySelectorAll('.content-section, .login-container');
            sections.forEach(section => {
                section.style.display = 'none';
            });
            
            const activeSection = document.getElementById(sectionId);
            if (activeSection) {
                activeSection.style.display = 'block';
            } else {
                document.getElementById('home').style.display = 'block';
            }
            
            // Scroll to top when switching sections
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
        
        // Show home section by default
        document.addEventListener('DOMContentLoaded', function() {
            showSection('home');
            
            // Check if user is logged in (for demo purposes)
            if (currentUser) {
                document.getElementById('login-button').style.display = 'none';
                document.getElementById('logout-button').style.display = 'block';
            } else {
                document.getElementById('login-button').style.display = 'block';
                document.getElementById('logout-button').style.display = 'none';
            }
        });

        function registerUser() {
    const fullName = document.getElementById('reg_full_name').value;
    const email = document.getElementById('reg_email').value;
    const username = document.getElementById('reg_username').value;
    const password = document.getElementById('reg_password').value;
    const confirmPassword = document.getElementById('reg_confirm_password').value;

    // Basic validation
    if (password !== confirmPassword) {
        document.getElementById('error-message').innerText = "Passwords don't match";
        document.getElementById('error-message').style.display = 'block';
        return;
    }

    fetch('register.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `full_name=${encodeURIComponent(fullName)}&email=${encodeURIComponent(email)}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('error-message').style.display = 'none';
            document.getElementById('success-message').innerText = "Registration successful! Please login.";
            document.getElementById('success-message').style.display = 'block';
            
            // Show login form after registration
            setTimeout(() => {
                showSection('login');
            }, 2000);
        } else {
            document.getElementById('error-message').innerText = data.message;
            document.getElementById('error-message').style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('error-message').innerText = 'An error occurred during registration.';
        document.getElementById('error-message').style.display = 'block';
    });
}

function loginUser() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('login.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.getElementById('error-message').style.display = 'none';
            document.getElementById('success-message').innerText = data.message;
            document.getElementById('success-message').style.display = 'block';
            
            // Update UI
            document.getElementById('login-button').style.display = 'none';
            document.getElementById('logout-button').style.display = 'block';
            document.getElementById('login').style.display = 'none';
            
            // Redirect to classes section after login
            setTimeout(() => {
                showSection('classes');
            }, 1000);
        } else {
            document.getElementById('error-message').innerText = data.message;
            document.getElementById('error-message').style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('error-message').innerText = 'An error occurred during login.';
        document.getElementById('error-message').style.display = 'block';
    });
}

function logout() {
    fetch('logout.php')
    .then(() => {
        // Update UI for logged out user
        document.getElementById('logout-button').style.display = 'none';
        document.getElementById('login-button').style.display = 'block';
        
        // Show logout confirmation
        document.getElementById('success-message').innerText = "You have been logged out successfully.";
        document.getElementById('success-message').style.display = 'block';
        document.getElementById('error-message').style.display = 'none';
        
        // Redirect to home after 1 second
        setTimeout(() => {
            showSection('home');
        }, 1000);
    });
}
    </script>
    <!-- Add this right before the closing </body> tag -->
<div class="ai-chatbot-container">
    <button class="ai-chatbot-toggle" id="aiToggle">
        <i class="fas fa-robot"></i>
    </button>
    
    <div class="ai-chatbot-window" id="aiChatWindow">
        <div class="ai-chatbot-header">
            <h3>Dzidzo Learning Assistant</h3>
            <button class="ai-chatbot-close" id="aiClose">
                <i class="fas fa-times"></i>
            </button>
        </div>
        
        <div class="ai-chatbot-body" id="aiChatBody">
            <div class="ai-message ai-bot-message">
                Hello there! I'm Dzidzo your AI learning assistant. How can I help you explore our AR/VR education platform today?
            </div>
            
            <div class="ai-quick-replies" id="quickReplies">
                <div class="ai-quick-reply" onclick="sendQuickReply('How do I access VR classes?')">Access VR classes</div>
                <div class="ai-quick-reply" onclick="sendQuickReply('What AR resources are available?')">AR resources</div>
                <div class="ai-quick-reply" onclick="sendQuickReply('How do I register?')">Registration help</div>
            </div>
        </div>
        
        <div class="ai-chatbot-input">
            <input type="text" id="aiUserInput" placeholder="Ask me about Dzidziso...">
            <button class="ai-chatbot-send" id="aiSend">
                <i class="fas fa-paper-plane"></i>
            </button>
        </div>
    </div>
</div>

<!-- Add this CSS right before the closing </style> tag -->
<style>
    /* AI Chatbot Styles */
    .ai-chatbot-container {
        position: fixed;
        bottom: 30px;
        right: 30px;
        z-index: 1000;
        font-family: 'Poppins', sans-serif;
    }
    
    .ai-chatbot-toggle {
        width: 60px;
        height: 60px;
        background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 24px;
        cursor: pointer;
        box-shadow: var(--shadow);
        transition: var(--transition);
        border: none;
        outline: none;
    }
    
    .ai-chatbot-toggle:hover {
        transform: scale(1.1);
    }
    
    .ai-chatbot-window {
        width: 350px;
        height: 500px;
        background: white;
        border-radius: 15px;
        box-shadow: var(--shadow);
        overflow: hidden;
        display: none;
        flex-direction: column;
        transform: translateY(20px);
        opacity: 0;
        transition: all 0.3s ease;
    }
    
    .ai-chatbot-window.active {
        display: flex;
        transform: translateY(0);
        opacity: 1;
    }
    
    .ai-chatbot-header {
        background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
        color: white;
        padding: 15px 20px;
        display: flex;
        align-items: center;
    }
    
    .ai-chatbot-header h3 {
        margin: 0;
        font-weight: 600;
        font-size: 1.1rem;
        flex: 1;
    }
    
    .ai-chatbot-close {
        background: none;
        border: none;
        color: white;
        font-size: 1.2rem;
        cursor: pointer;
    }
    
    .ai-chatbot-body {
        flex: 1;
        padding: 15px;
        overflow-y: auto;
        background-color: #f9f9f9;
        display: flex;
        flex-direction: column;
    }
    
    .ai-message {
        max-width: 80%;
        padding: 10px 15px;
        margin-bottom: 10px;
        border-radius: 18px;
        font-size: 0.9rem;
        line-height: 1.4;
        animation: messageIn 0.2s ease-out;
    }
    
    @keyframes messageIn {
        from { transform: translateY(10px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }
    
    .ai-bot-message {
        background: white;
        border: 1px solid #e0e0e0;
        align-self: flex-start;
        border-bottom-left-radius: 5px;
        color: #333;
    }
    
    .ai-user-message {
        background: var(--primary-color);
        color: white;
        align-self: flex-end;
        border-bottom-right-radius: 5px;
    }
    
    .ai-chatbot-input {
        padding: 15px;
        border-top: 1px solid #eee;
        display: flex;
        background: white;
    }
    
    .ai-chatbot-input input {
        flex: 1;
        padding: 10px 15px;
        border: 1px solid #ddd;
        border-radius: 25px;
        outline: none;
        font-family: 'Poppins', sans-serif;
        transition: var(--transition);
    }
    
    .ai-chatbot-input input:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.2);
    }
    
    .ai-chatbot-send {
        background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
        color: white;
        border: none;
        width: 40px;
        height: 40px;
        border-radius: 50%;
        margin-left: 10px;
        cursor: pointer;
        transition: var(--transition);
    }
    
    .ai-chatbot-send:hover {
        transform: scale(1.05);
    }
    
    .ai-quick-replies {
        display: flex;
        flex-wrap: wrap;
        margin-top: 10px;
        gap: 8px;
    }
    
    .ai-quick-reply {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 15px;
        padding: 6px 12px;
        font-size: 0.8rem;
        cursor: pointer;
        transition: var(--transition);
    }
    
    .ai-quick-reply:hover {
        background: var(--primary-light);
        border-color: var(--primary-color);
    }
    
    /* Typing indicator */
    .ai-typing {
        display: inline-block;
        padding: 10px 15px;
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 18px;
        border-bottom-left-radius: 5px;
        margin-bottom: 10px;
        align-self: flex-start;
    }
    
    .ai-typing span {
        height: 8px;
        width: 8px;
        background: #aaa;
        border-radius: 50%;
        display: inline-block;
        margin: 0 2px;
        animation: typing 1s infinite ease-in-out;
    }
    
    .ai-typing span:nth-child(2) {
        animation-delay: 0.2s;
    }
    
    .ai-typing span:nth-child(3) {
        animation-delay: 0.4s;
    }
    
    @keyframes typing {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-5px); }
    }
</style>

<!-- Add this script right before the closing </script> tag -->
<script>
    // AI Chatbot Functionality
    const aiToggle = document.getElementById('aiToggle');
    const aiChatWindow = document.getElementById('aiChatWindow');
    const aiClose = document.getElementById('aiClose');
    const aiChatBody = document.getElementById('aiChatBody');
    const aiUserInput = document.getElementById('aiUserInput');
    const aiSend = document.getElementById('aiSend');
    const quickReplies = document.getElementById('quickReplies');
    
    // Toggle chatbot window
    aiToggle.addEventListener('click', function() {
        this.classList.toggle('active');
        aiChatWindow.classList.toggle('active');
    });
    
    // Close chatbot
    aiClose.addEventListener('click', function() {
        aiToggle.classList.remove('active');
        aiChatWindow.classList.remove('active');
    });
    
    // Send message function
    function sendMessage() {
        const message = aiUserInput.value.trim();
        if (message) {
            // Add user message
            addMessage(message, 'user');
            aiUserInput.value = '';
            
            // Show typing indicator
            showTyping();
            
            // Process message and generate response
            setTimeout(() => {
                // Remove typing indicator
                const typing = document.querySelector('.ai-typing');
                if (typing) typing.remove();
                
                // Generate response
                const response = generateResponse(message);
                addMessage(response, 'bot');
                
                // Scroll to bottom
                aiChatBody.scrollTop = aiChatBody.scrollHeight;
            }, 1000 + Math.random() * 2000); // Random delay for realism
        }
    }
    
    // Send quick reply
    function sendQuickReply(message) {
        aiUserInput.value = message;
        sendMessage();
    }
    
    // Add message to chat
    function addMessage(text, sender) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('ai-message', `ai-${sender}-message`);
        messageDiv.textContent = text;
        aiChatBody.appendChild(messageDiv);
        
        // Hide quick replies after first message
        if (sender === 'user') {
            quickReplies.style.display = 'none';
        }
        
        // Scroll to bottom
        aiChatBody.scrollTop = aiChatBody.scrollHeight;
    }
    
    // Show typing indicator
    function showTyping() {
        const typingDiv = document.createElement('div');
        typingDiv.classList.add('ai-typing');
        typingDiv.innerHTML = '<span></span><span></span><span></span>';
        aiChatBody.appendChild(typingDiv);
        aiChatBody.scrollTop = aiChatBody.scrollHeight;
    }
    
    // Generate bot responses
    function generateResponse(message) {
        const lowerMsg = message.toLowerCase();
        
        // Common questions about the platform
        if (lowerMsg.includes('hello') || lowerMsg.includes('hi') || lowerMsg.includes('hey')) {
            return "Hi there! I'm here to help you navigate Dzidzo's AR/VR education platform. What would you like to know?";
        }
        else if (lowerMsg.includes('access') || lowerMsg.includes('vr class') || lowerMsg.includes('virtual')) {
            return "To access our VR classes:\n1. Go to the 'Classes' section\n2. Click 'Enter Virtual Reality Classroom'\n3. Put on your VR headset or use desktop mode\n4. Start your immersive learning experience!";
        }
        else if (lowerMsg.includes('ar') || lowerMsg.includes('augmented') || lowerMsg.includes('resource')) {
            return "Our AR resources include:\n- Interactive 3D models for STEM subjects\n- AR-enhanced textbooks\n- Virtual lab simulations\n- Historical recreations\nVisit the 'Library' section to explore them!";
        }
        else if (lowerMsg.includes('register') || lowerMsg.includes('account') || lowerMsg.includes('sign up')) {
            return "To register:\n1. Click 'Register' in the navigation\n2. Fill in your details\n3. Create a username and password\n4. Click 'Register'\nYou'll then be able to access all features!";
        }
        else if (lowerMsg.includes('feature') || lowerMsg.includes('what can') || lowerMsg.includes('offer')) {
            return "Dzidzo offers:\n- Immersive VR classrooms\n- Interactive AR learning materials\n- 3D model library\n- Personalized learning paths\n- Progress tracking\nExplore the different sections to see everything!";
        }
        else if (lowerMsg.includes('help') || lowerMsg.includes('support')) {
            return "For technical support or additional help:\n1. Check our 'About' section\n2. Contact us through the information provided\n3. Our team will respond within 24 hours\nHow else can I assist you?";
        }
        else {
            // Default response if question isn't recognized
            const responses = [
                "I can help you navigate our AR/VR education platform. Try asking about specific features or how to get started!",
                "That's an interesting question! Our platform combines augmented and virtual reality to enhance learning experiences.",
                "I'm designed to help students make the most of Dzidzo's immersive learning tools. What would you like to know more about?",
                "For the best experience, I recommend exploring our VR classrooms and AR library. Would you like details about either?",
                "I'm still learning about all the possibilities of our platform. Could you ask your question in a different way?"
            ];
            return responses[Math.floor(Math.random() * responses.length)];
        }
    }
    
    // Event listeners
    aiSend.addEventListener('click', sendMessage);
    aiUserInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
</script>

<!-- Add this to the <head> section if not already present -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</body>
</html>