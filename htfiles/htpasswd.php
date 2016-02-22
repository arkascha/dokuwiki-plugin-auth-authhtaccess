<?php

class auth_plugin_authhtaccess_htpasswd extends auth_plugin_authhtaccess_htbase
{
    private $users = null; //Array of [$userId]=cryptpass

    public function __construct($file = '') {
        parent::__construct($file);
    }

    public function getUsers() {
        return $this->users;
    }

    public function isUser($user) {
        return array_key_exists($user,$this->users);
    }

    public function verifyUser($UserID, $clearPass) {
        if (empty($UserID)) {
            return false;
        }
        if (empty($clearPass)) {
            return false;
        }
        $pass = $this->users[$UserID];
        $salt = substr($pass, 0, 2);
        $cryptPass = $this->cryptPass($clearPass, $salt);

        if ($pass == $cryptPass) {
            return true;
        }

        return false;
    }

    public function changePass ($UserID, $newPass, $oldPass = '') {

        if (empty($UserID)) {
            return false;
        }

        if (!($this->isUser($UserID))) {
            return false;
        }

        if(empty($newPass)) {
            $this->error("changePass failure - no new password submitted", 0);
            return false;
        }

        $checkname = strtolower($UserID);
        $checkpass = strtolower($newPass);

        if($checkname == $checkpass) {
            $this->error("changePass failure: UserID and password cannot be the same", 0);
            return false;
        }

        if(!(empty($oldPass))) {
            if (!($this->verifyUser($UserID,$oldPass))) {
                $this->error("changePass failure for [$UserID] : Authentication Failed", 0);
                return false;
            }

            if($newPass == $oldPass) {
                // Passwords are the same, no sense wasting time here
                return true;
            }
        }

        $this->users[$UserID] = $this->cryptPass($newPass);

        return $this->writeFile();
    }

    public function renameUser ($OldID, $NewID, $writeFile = true) {
        if (!$this->isUser($OldID)) {
            $this->error("Cannot change userid, [$OldID] does not exist", 0);
        }

        if ($this->isUser($NewID)) {
            $this->error("Cannot change UserID, [$NewID] already exists", 0);
            return false;
        }

        $oldCrypt = $this->users[$OldID];
        unset($this->users[$OldID]);
        $this->users[$NewID] = $oldCrypt;

        if ($writeFile) {
            return $this->writeFile();
        }

        return true;
    }

    public function addUser ($UserID, $newPass, $writeFile = true) {

        if (empty($UserID)) {
            $this->error("addUser fail. No UserID", 0);
            return false;
        }
        if (empty($newPass)) {
            $this->error("addUser fail. No password", 0);
            return false;
        }

        if ($this->isUser($UserID)) {
            $this->error("addUser fail. UserID already exists", 0);
            return false;
        }

        $this->users[$UserID] = $this->cryptPass($newPass);

        if ($writeFile) {
            if(!($this->writeFile())) {
                $this->error("FATAL could not add user due to file error! [$php_errormsg]", 1);
                exit; // Just in case
            }
        }
        // Successfully added user

        return true;
    }

    public function delete($users, $writeFile = true) {
        if (!is_array($users)) {
            $users = array($users);
        }

        if (empty($users)) {
            return false;
        }

        $oldUsers = $this->users;
        $this->users = array();
        foreach ($oldUsers as $user => $userinfo) {
            if (!in_array($user, $users)) {
                $this->users[$user] = $userinfo;
            }
        }

        return $this->writeFile();
    } 

    protected function loadFile() {
        $this->users = array();

        if (!file_exists($this->htFile())) {
            return;
        }

        $lines = file($this->htFile());

        if (!$lines) {
            return;
        }

        foreach ($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); //ignore comments
            list($user, $pass) = split(":", $line, 2);
            $user = trim($user);
            $pass = trim($pass);
            if (!empty($user)) {
                $this->users[$user] = $pass;
            }
        }
    }

    protected function writeFile() {

        if (!$this->htFile()) {
            return false;
        }

        $fd = fopen( $this->htFile(), 'w');

        foreach ($this->users as $user => $cryptPass) {
            fwrite($fd, "$user:$cryptPass\n");
        }

        fclose( $fd );

        return true;
    }

    private function cryptPass($passwd, $salt = '') {
        if (!($passwd)) {
            return '';
        }

        if (!empty($salt)) {
            $salt = substr ($salt, 0, 2);
        } else {
            $salt = $this->genSalt();
        }

        return (crypt($passwd, $salt));
    }

    private function genSalt() {
        $random = 0;
        $rand64 = '';
        $salt = '';

        $random = rand();

        $rand64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        $salt = substr($rand64, $random  %  64, 1) . substr($rand64, ($random/64) % 64, 1);
        $salt = substr($salt, 0, 2); // Just in case

        return($salt);
    }
}
