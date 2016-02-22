<?php

class auth_plugin_authhtaccess_htuser extends auth_plugin_authhtaccess_htbase
{

    private $users = array(); //Array = [$user][name|mail] = value

    public function __construct($file = '') {
        parent::__construct($file);
    }

    public function getUsers() {
        return $this->users;
    }

    public function getUserInfo($user) {
        return isset ($this->users[$user]) ? $this->users[$user] : false;
    }

    public function isUser($user) {
        return isset($this->users[$user]);
    }

    public function addUser ($UserID, $name, $mail, $writeFile = true) {

        if(empty($UserID)) {
            $this->error("add htUser fail. No UserID", 0);
            return false;
        }

        if($this->isUser($UserID)) {
            $this->error("add htUser fail. UserID already exists", 0);
            return false;
        }

        $this->users[$UserID]['name'] = $name;
        $this->users[$UserID]['mail'] = $mail;

        if ($writeFile) {
            return $this->writeFile();
        }
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

        if ($writeFile) {
            return $this->writeFile();
        }

        return true;
    } 

    public function modify($user, $changes, $writeFile = true) {

        if ($this->isUser($user)) {
            $changes = array_merge($this->users[$user], $changes);
        }

        $this->users[$user] = $changes;

        if ($writeFile) {
            return $this->writeFile();
        }

        return true;
    }
    
    protected function loadFile() {
        $this->users = array();

        if (!file_exists($this->htFile())) {
            return;
        }

        $lines = file($this->htFile());

        foreach ($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); //ignore comments
            list($user, $name, $mail) = split(":", $line, 3);
            $user = trim($user);
            $name = trim($name);
            $mail = trim($mail);
            if (!empty($user)) {
                $this->users[$user]['name'] = $name;
                $this->users[$user]['mail'] = $mail;
            }
        }
    }

    protected function writeFile() {
        if (!$this->htFile()) {
            return false;
        }

        $fd = fopen($this->htFile(), 'w');

        foreach ($this->users as $user => $userInfo) {
            $name = $userInfo['name'];
            $mail = $userInfo['mail'];
            fwrite($fd, "$user:$name:$mail\n");
        }

        fclose($fd);
        return true;
    }
}
