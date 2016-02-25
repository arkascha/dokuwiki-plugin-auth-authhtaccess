<?php

/**
 * Class auth_plugin_authhtaccess_htpasswd
 */
class auth_plugin_authhtaccess_htpasswd extends auth_plugin_authhtaccess_htbase
{
    /** @var array known users as associative array, userId as key, cryptpass as value */
    private $users = null;

    /**
     * auth_plugin_authhtaccess_htpasswd constructor.
     * @param auth_plugin_authhtaccess $authPlugin
     * @param string $file
     */
    public function __construct(auth_plugin_authhtaccess $authPlugin, $file = '') {
        parent::__construct($authPlugin, $file);
    }

    /**
     * @return array
     */
    public function getUsers() {
        return $this->users;
    }

    /**
     * @param $user
     * @return bool
     */
    public function isUser($user) {
        return array_key_exists($user,$this->users);
    }

    /**
     * @param string $userId
     * @param string $clearPass
     * @return bool
     */
    public function verifyUser($userId, $clearPass) {
        if (empty($userId)) {
            return false;
        }
        if (empty($clearPass)) {
            return false;
        }
        $pass = $this->users[$userId];
        $salt = substr($pass, 0, 2);
        $cryptPass = $this->cryptPass($clearPass, $salt);

        if ($pass == $cryptPass) {
            return true;
        }

        return false;
    }

    /**
     * @param string $userId
     * @param string $newPass
     * @param string $oldPass
     * @return bool
     */
    public function changePass ($userId, $newPass, $oldPass = '') {
        if (empty($userId)) {
            return false;
        }

        if (!($this->isUser($userId))) {
            return false;
        }

        if(empty($newPass)) {
            $this->error($this->authPlugin->getLang("Password change failure: no new password specified."), 0);
            return false;
        }

        $checkName = strtolower($userId);
        $checkPass = strtolower($newPass);

        if($checkName == $checkPass) {
            $this->error($this->authPlugin->getLang("Password change failure: identifier and password cannot be identical."), 0);
            return false;
        }

        if(!(empty($oldPass))) {
            if (!($this->verifyUser($userId,$oldPass))) {
                $this->error(sprintf($this->authPlugin->getLang("Password change failure: authentication for user [%s] failed."), $userId), 0);
                return false;
            }

            if($newPass == $oldPass) {
                // Passwords are the same, no sense wasting time here
                return true;
            }
        }

        $this->users[$userId] = $this->cryptPass($newPass);

        return $this->writeFile();
    }

    /**
     * @param string $oldId
     * @param string $newId
     * @param bool $writeFile
     * @return bool
     */
    public function renameUser ($oldId, $newId, $writeFile = true) {
        if (!$this->isUser($oldId)) {
            $this->error(sprintf($this->authPlugin->getLang("Identifier change failed: identifier [%s] does not exist."), $oldId), 0);
        }

        if ($this->isUser($newId)) {
            $this->error(sprintf($this->authPlugin->getLang("Identifier change failed: identifier [%s] already exists."), $newId), 0);
            return false;
        }

        $oldCrypt = $this->users[$oldId];
        unset($this->users[$oldId]);
        $this->users[$newId] = $oldCrypt;

        if ($writeFile) {
            return $this->writeFile();
        }

        return true;
    }

    /**
     * @param string $userId
     * @param string $newPass
     * @param bool $writeFile
     * @return bool
     */
    public function addUser ($userId, $newPass, $writeFile = true) {
        if (empty($userId)) {
            $this->error($this->authPlugin->getLang("Adding user failed: no identifier specified."), 0);
            return false;
        }
        if (empty($newPass)) {
            $this->error($this->authPlugin->getLang("Adding user failed: no password specified."), 0);
            return false;
        }

        if ($this->isUser($userId)) {
            $this->error($this->authPlugin->getLang("Adding user failed: identifier already exists."), 0);
            return false;
        }

        $this->users[$userId] = $this->cryptPass($newPass);

        if ($writeFile) {
            if(!($this->writeFile())) {
                $this->error(sprintf($this->authPlugin->getLang("Adding user failed due to a file handling error! [%s]"), $php_errormsg), 1);
                exit; // just in case
            }
        }

        // successfully added user
        return true;
    }

    /**
     * @param mixed $users
     * @param bool $writeFile
     * @return bool
     */
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

    /**
     * @brief Load and interpret file from disk.
     */
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

    /**
     * @return bool
     */
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

    /**
     * @param string $passwd
     * @param string $salt
     * @return string
     */
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

    /**
     * @return string
     */
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
