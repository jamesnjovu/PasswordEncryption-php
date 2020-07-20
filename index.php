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
        <label for="harsting"><h1>Log In:</h1></label> <br>
        <br><input type="email" name="username" placeholder="Name" required />
        <br><br><input type="password" name="pass" placeholder="Email" required />

        <br><br><input type="submit" name="login">
    </form>
    <hr>
    <b>Do not have an account? </b><a href="reg.php">Click here</a>
</body>

</html>