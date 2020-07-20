<?php
    $host = "localhost";
    $user = "root";
    $pass = "";
    $db = "phpEncrypting";

    $con = mysqli_connect($host,$user,$pass,$db);

    if ($con){
        //echo "Connected";
    }else{
        //echo "Connecction Failed";
    }
?>