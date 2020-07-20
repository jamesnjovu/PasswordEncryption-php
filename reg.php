<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <title>PHP Encryption</title>
</head>

<body>
    <form action="More/Code9.php" method="POST">
        <?php
        if (isset($_SESSION['success']) && $_SESSION['success'] != '') {
            echo '<h2 class="bg-primary text-white">' . $_SESSION['success'] . '</h2>';
            unset($_SESSION['success']);
        } elseif (isset($_SESSION['status']) && $_SESSION['status'] != '') {
            echo '<h3 class="bg-danger text-white">' . $_SESSION['status'] . '</h3>';
            unset($_SESSION['status']);
        }
        ?>
        <label for="harsting">
            <h1>Sign Up:</h1>
        </label> <br>
        <br><input type="email" name="username" placeholder="Email" required />
        <br><br><input type="password" name="pass" placeholder="Password" required />
        <br><br><input type="password" name="cpass" placeholder="Confirm Password" required />
        <br><br>
        <label for="harsting">Authentication Method:</label>
        <select name="encryption">
            <option value="md5">MD5</option>
            <option value="sha1">SHA1</option>
            <option value="crypt">Crypt-HD</option>
            <option value="hash">Hash</option>
            <option value="base64">Base64</option>
            <option value="openssl">Openssl</option>
            <option value="hybrid">Hybrid</option>
        </select> <br><br><input type="submit" name="signup">
    </form>
    <hr>
    <b>Already have an account? </b><a href="index.php">Click here</a>
</body>

</html>