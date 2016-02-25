<?php

/**
 * Class auth_plugin_authhtaccess_htgroup
 */
class auth_plugin_authhtaccess_htgroup extends auth_plugin_authhtaccess_htbase
{
    /** @var array user groups */
    private $groups = array();
    /** @var array users */
    private $users = array();
    /** @var string default group */
    private $defaultGroup;

    /**
     * auth_plugin_authhtaccess_htgroup constructor.
     * @param auth_plugin_authhtaccess $authPlugin
     * @param string $file
     * @param null $defaultGroup
     */
    public function __construct(auth_plugin_authhtaccess $authPlugin, $file = '', $defaultGroup = null) {
        if (isset($defaultGroup)) {
            $this->defaultGroup = trim($defaultGroup);
        }
        parent::__construct($authPlugin, $file);
    }

    /**
     * @return array
     */
    public function getGroupsByUser() {
        return $this->users;
    }

    /**
     * @param $user
     * @return bool
     */
    public function getGroupsForUser($user) {
        return isset ($this->users[$user]) ? $this->users[$user] : false;
    }

    /**
     * @param $user
     * @param $groups
     * @return bool
     */
    public function setGroupsForUser($user, $groups) {
        if (isset($this->defaultGroup) && !in_array($this->defaultGroup, $groups)) {
            $groups = array_merge(array($this->defaultGroup), $groups);
        }

        $this->users[$user] = $groups;
        $this->resetGroups();

        return $this->writeFile();
    }

    /**
     * @param $user
     * @param bool $writeFile
     * @return bool
     */
    public function delete($user, $writeFile = true) {
        if (!is_array($user)) {
            if (isset($this->users[$user])) {
                unset($this->users[$user]);
            }
        } else {
            foreach ($user as $aUser) {
                $this->delete($aUser, false);
            }
        }

        if ($writeFile) {
            $this->resetGroups();
            return $this->writeFile();
        }

        return true;
    }

    /**
     * @brief Reset groups array from users array. Will delete group.
     */
    private function resetGroups() {
        $this->groups = array();
        foreach ($this->users as $user => $groups) {
            foreach ($groups as $group) {
                $this->groups[$group][] = $user;
            }
        }
    }

    /**
     * @brief Load file from disk.
     */
    protected function loadFile() {
        $this->groups = array();
        $this->users = array();

        if (!file_exists($this->htFile())) {
            return;
        }

        $lines = file($this->htFile());
        foreach ($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); //ignore comments
            $line = trim($line);
            if (empty($line)) continue;

            $row = split(":", $line, 2);
            $group = trim($row[0]);
            if (empty($group)) continue;

            if ($group == $this->defaultGroup) continue;

            $users_in_group = preg_split("'\s'", $row[1]);
            foreach ($users_in_group as $user) {
                if (empty ($user)) continue;

                if (isset($this->defaultGroup) && !array_key_exists($user, $this->users)) {
                    $this->users[$user][] = $this->defaultGroup;
                }

                $this->groups[$group][] = $user;
                $this->users[$user][] = $group;
            }
        }
    }

    /**
     * @brief Write file to disk.
     * @return bool
     */
    protected function writeFile() {
        if (!$this->htFile()) {
            return false;
        }

        $fd = fopen($this->htFile(), 'w');

        foreach ($this->groups as $group => $users) {
            if ($group == $this->defaultGroup) continue;

            fwrite($fd, "$group:");
            foreach($users as $user) {
                fwrite($fd, " $user");
            }
            fwrite($fd, "\n");
        }

        fclose($fd);
        return true;
    }
}
