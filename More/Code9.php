<?php
    session_start();
    require 'init.php';

    function SignUp($con,$signupPass,$signupEmail, $signupType){
        $query = "INSERT INTO user (email,password,type) VALUES ('$signupEmail','$signupPass','$signupType')";
        $query_run = mysqli_query($con, $query);

        if ($query_run) {
            $_SESSION['success'] = "Account Created. You can logIn now";
            header('location: ../index.php');
        } else {
            $_SESSION['status'] = "Account Not Created";
            header('location: ../reg.php');
        }
    }

    function Runlog($query_run){
        if ($query_run) {
            $_SESSION['success'] = 'Logged In';
            header('location: ../index.php');
        } else {
            $_SESSION['status'] = "Not loggged In";
            header('location: ../index.php');
        }
    }

    function LogIn($type, $query_run, $pass, $upass){
        if ($type === 'md5') {
            $md5p = md5($pass);

            if($md5p === $upass){
                Runlog($query_run);
            }else{
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            }
        }
        if ($type === 'sha1') {
            $sha1p = sha1($pass);

            if ($sha1p === $upass) {
                Runlog($query_run);
            } else {
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            }
        }
        if ($type === 'crypt') {
            $cryptp = crypt($pass, 'Jam');
            if ($cryptp === $upass) {
                Runlog($query_run);
            } else {
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            }
        }
        if ($type === 'hash') {
            $hashpass = password_verify($pass, $upass);
            if ($hashpass == 1) {
                Runlog($query_run);
            } else {
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            } 
        }
        if ($type === 'base64') {
            $base64p = base64_decode($upass);
            if ($base64p === $pass) {
                Runlog($query_run);
            } else {
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            } 
        }
        if($type === 'openssl'){
            // Non-NULL Initialization Vector for decryption 
            $decryption_iv = '1234567891011121';

            // Store the decryption key 
            $decryption_key = "ViperCoderJay";
            $ciphering = "AES-128-CTR";
            $options = 0;
            // Use openssl_decrypt() function to decrypt the data 
            $opensslp = openssl_decrypt(
                $upass,
                $ciphering,
                $decryption_key,
                $options,
                $decryption_iv
            );
            if ($opensslp === $pass) {
                Runlog($query_run);
            } else {
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            }
        }
        if($type === 'hybrid'){
            $iv = '1234567891011121';
            $key = "ViperCoderJay";
            $cipher = "AES-128-CTR";
            $options = 0;
            $opensslp = openssl_decrypt(
                $upass,
                $cipher,
                $key,
                $options,
                $iv
            );

            $ciphering = "BF-CBC"; 
            $iv_length = openssl_cipher_iv_length($ciphering);
            $options = 0; 
            // Decryption of string process starts 
            // Used random_bytes() which gives randomly 
            // 16 digit values 
            $decryption_iv = random_bytes($iv_length);

            // Store the decryption key 
            $decryption_key = openssl_digest(php_uname(), 'MD5', TRUE);
            $encryption_iv = random_bytes($iv_length); 

            // Descrypt the string 
            $openssl = openssl_decrypt(
                $opensslp,
                $ciphering,
                $decryption_key,
                $options,
                $encryption_iv
            );

            $hybrid=base64_decode($openssl);

            if ($hybrid === $pass) {
                Runlog($query_run);
            } else {
                $_SESSION['status'] = "Email or Password is Invalid";
                header('location: ../index.php');
            }
        }
    }

    if(isset($_POST['login'])){
        $email = $_POST['username'];
        $pass = $_POST['pass'];

        $query = "SELECT * FROM user WHERE email='$email'";
        $query_run = mysqli_query($con, $query);
        foreach ($query_run as $row) {
            $type = $row['type'];
            $upass = $row['password'];
        }
        LogIn($type, $query_run, $pass,$upass);
    }


    if(isset($_POST['signup'])){
        $type = $_POST['encryption'];
        $email = $_POST['username'];
        $pass = $_POST['pass'];
        $cpass = $_POST['cpass'];

        if ($pass === $cpass) {
            if ($type === 'md5') {
                $md5pass = md5($pass);
                SignUp($con,$md5pass,$email, $type);
            }
            if ($type === 'sha1') {
                $sha1pass = sha1($pass);
                SignUp($con, $sha1pass,$email, $type);
            }
            if ($type === 'crypt') {
                $cryptpass=crypt($pass,'Jam');
                SignUp($con, $cryptpass,$email, $type);
            }
            if ($type === 'hash') {
                $hashpass = password_hash($pass, PASSWORD_DEFAULT);
                SignUp($con, $hashpass,$email, $type);
            }
            if($type === 'base64'){
                $base64pass = base64_encode($pass);
                SignUp($con, $base64pass,$email, $type);
            }
            if($type === 'openssl'){
                // Store the cipher method 
                $ciphering = "AES-128-CTR";

                // Use OpenSSl Encryption method 
                $iv_length = openssl_cipher_iv_length($ciphering);
                $options = 0;

                // Non-NULL Initialization Vector for encryption 
                $encryption_iv = '1234567891011121';

                // Store the encryption key 
                $encryption_key = "ViperCoderJay";

                // Use openssl_encrypt() function to encrypt the data 
                $opensslpass = openssl_encrypt(
                    $pass,
                    $ciphering,
                    $encryption_key,
                    $options,
                    $encryption_iv
                );
                SignUp($con, $opensslpass, $email, $type);
            }
            if($type === 'hybrid'){

                $base64=base64_encode($pass);
  
                // Store cipher method 
                $ciphering = "BF-CBC"; 
                // Use OpenSSl encryption method 
                $iv_length = openssl_cipher_iv_length($ciphering); 
                $option = 0; 
                // Use random_bytes() function which gives 
                // randomly 16 digit values 
                $encryption_iv = random_bytes($iv_length); 
                // Alternatively, we can use any 16 digit 
                // characters or numeric for iv 
                $encryption_key = openssl_digest(php_uname(), 'MD5', TRUE);
                // Encryption of string process starts 
                $openssl = openssl_encrypt(
                    $base64, $ciphering, 
                    $encryption_key, $option, $encryption_iv);

                $cipher = "AES-128-CTR";
                $iv_length = openssl_cipher_iv_length($ciphering);
                $options = 0;
                $iv = '1234567891011121';
                $key = "ViperCoderJay";
                $hybridp = openssl_encrypt(
                    $openssl,
                    $cipher,
                    $key,
                    $options,
                    $iv
                );
                SignUp($con, $hybridp, $email, $type);
            }
        }else{
            $_SESSION['status'] = "Password did not match";
            header('location: ../reg.php');
        }
    }
?>