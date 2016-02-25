<?php

/**
 * Class auth_plugin_authhtaccess_htuser
 */
class auth_plugin_authhtaccess_htuser extends auth_plugin_authhtaccess_htbase
{
    /** @var array associative array of known users ([$user][name|mail] = value) */
    private $users = array();

    /**
     * auth_plugin_authhtaccess_htuser constructor.
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
     * @param string $user
     * @return bool
     */
    public function getUserInfo($user) {
        return isset ($this->users[$user]) ? $this->users[$user] : false;
    }

    /**
     * @param string $user
     * @return bool
     */
    public function isUser($user) {
        return isset($this->users[$user]);
    }

    /**
     * @param $userId
     * @param $name
     * @param $mail
     * @param bool $writeFile
     * @return bool
     */
    public function addUser ($userId, $name, $mail, $writeFile = true) {
        if(empty($userId)) {
            $this->error($this->authPlugin->getLang("Adding user failed: no identifier specified."), 0);
            return false;
        }

        if($this->isUser($userId)) {
            $this->error($this->authPlugin->getLang("Adding user failed: identifier already exists."), 0);
            return false;
        }

        $this->users[$userId]['name'] = $name;
        $this->users[$userId]['mail'] = $mail;

        if ($writeFile) {
            return $this->writeFile();
        }

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

        if ($writeFile) {
            return $this->writeFile();
        }

        return true;
    }

    /**
     * @param string $user
     * @param array $changes
     * @param bool $writeFile
     * @return bool
     */
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

    /**
     * @brief Load and parse file from disk.
     */
    protected function loadFile() {
        $this->users = array();

        if (!file_exists($this->htFile())) {
            return;
        }

        $lines = file($this->htFile());

        foreach ($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); // ignore comments
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

    /**
     * @return bool
     */
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
