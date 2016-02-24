<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * Htaccess Dokuwiki authentication backend
 * 
 * Can be used behind a real .htaccess basic authentication OR
 * stand alone but using the htpasswd, htgroup formatted files.
 * 
 * htaccess does not support extended user info (name, email) so
 * these are either stored in a separate file 
 * 
 * TODO  Optionally get extended info from posix (like old htaccess_auth)
 * TODO  Confirm all data cleansing is done outside of this class
 * TODO  Use special empty instances of the htclasses if they don't exist
 * 
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Christian Reiner <info@christian-reiner.info>
 * Version:    2.0
 *
 * Work based on previous authentication backends by:
 * @author     Samuele Tognini <samuele@cli.di.unipi.it>
 * @author     Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author     Marcel Meulemans <marcel@meulemans.org>
 * @author     Grant Gardner <grant@lastweekend.com.au>
 * Additions:  Sebastian S <Seb.S@web.expr42.net>
 * 
 */

require_once DOKU_PLUGIN . 'authhtaccess/htfiles/htbase.php';
require_once DOKU_PLUGIN . 'authhtaccess/htfiles/htpasswd.php';
require_once DOKU_PLUGIN . 'authhtaccess/htfiles/htgroup.php';
require_once DOKU_PLUGIN . 'authhtaccess/htfiles/htuser.php';

/**
 * Class auth_plugin_authhtaccess
 */
class auth_plugin_authhtaccess extends DokuWiki_Auth_Plugin
{
    /** @var array user cache */
    protected $users = null;
    /** @var int lock file handle */
    protected $lockFile = null;
    /** @var array filter pattern */
    protected $_pattern = array();
    /** @var auth_plugin_authhtaccess_htpasswd */
    protected $htpasswd;
    /** @var auth_plugin_authhtaccess_htgroup */
    protected $htgroup;
    /** @var auth_plugin_authhtaccess_htuser */
    protected $htuser;
    /** @var string|null http realm  */
    protected $realm = null;

    /**
     * auth_plugin_authhtaccess constructor.
     * @brief Check config, read .htaccess and set capabilities.
     */
    public function __construct() {
        parent::__construct();
        $defaultGroup = $this->getConf('defaultgrp');

        $this->htpasswd = new auth_plugin_authhtaccess_htpasswd();
        $this->htuser = new auth_plugin_authhtaccess_htuser();
        $this->htgroup = new auth_plugin_authhtaccess_htgroup('', $defaultGroup);

        if (!$this->findHtAccess()) {
            $this->success = false;
            return;
        }

        if (!$this->htpasswd->canRead()) {
            $this->success = false;
            return;
        }

        if (isset ($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
            $this->cando['external'] = true;
            $this->cando['logoff'] = true;
        }

        $this->cando['getUsers'] = true;
        $this->cando['getUserCount'] = true;

        if ($this->htpasswd->canModify() && $this->htuser->canModify()) {
            $this->cando['addUser'] = true;
            $this->cando['delUser'] = true;
            $this->cando['modLogin'] = true;
            $this->cando['modPass'] = true;
            $this->cando['modName'] = true;
            $this->cando['modMail'] = true;
        }

        if ($this->htgroup->canRead()) {
            $this->cando['getGroups'] = true;
            if ($this->htgroup->canModify()) {
                $this->cando['modGroups'] = true;
            }
        }

        $this->success = true;
    }

    /**
     * @param string $user user name
     * @param string $pass cleartext password
     * @param bool $sticky cookie should not expire
     * @return bool true on successful auth
     * @see auth_login()
     */
    public function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO;

        // never use $user, $pass as user will never arrive via login page.
        $user = $_SERVER['PHP_AUTH_USER'];
        $pass = $_SERVER['PHP_AUTH_PW'];

        // possibly could trust those headers, but why bother!
        if (! $this->htpasswd->verifyUser($user, $pass)) {
            return false;
        }

        $userInfo = $this->getUserData($user);

        $USERINFO['name'] = $userInfo['name'];
        $USERINFO['mail'] = $userInfo['mail'];
        $USERINFO['grps'] = $userInfo['grps'];
        $USERINFO['pass'] = $userInfo['pass'];
        $_SERVER['REMOTE_USER'] = $user;
        $_SESSION[$GLOBALS['conf']['title']]['auth']['user'] = $user;
        $_SESSION[$GLOBALS['conf']['title']]['auth']['pass'] = $pass;
        $_SESSION[$GLOBALS['conf']['title']]['auth']['info'] = $USERINFO;

        return true;
    }

    /**
     * @brief Http logoff in case a realm is set, forces a http basic authentication.
     */
    public function logOff() {
        //works only with basic http authentication on some browsers!.
        //Don't try logging in again, must hit cancel
        if (isset ($this->realm)) {
            header('WWW-Authenticate: Basic realm="' . $this->realm . '"');
            header('HTTP/1.0 401 Unauthorized');
            $logoutSlogan = $this->getConf('logoutmsg');
            print(sprintf($logoutSlogan, DOKU_BASE));
            exit;
        }
    }

    /**
     * @brief Check user and password, if using the login page or update profile form.
     * @param string $user user name
     * @param string $pass clear text password
     * @return  bool
     */
    public function checkPass($user, $pass) {
        return $this->htpasswd->verifyUser($user, $pass);
    }
  
   /**
    * @brief Return user info.
    * @param string $user user name
    * @param bool $htDefaultGroup
    * @return bool
    */
    public function getUserData($user, $htDefaultGroup = true) {

        if ($this->users === null) {
            $this->loadUserData();
        }

        return isset ($this->users[$user]) ? $this->users[$user] : false;
    }

    /**
     * @param array $filter
     * @return int
     */
    public function getUserCount($filter = array()) {
        if ($this->users === null) {
            $this->loadUserData();
        }

        if (!count($filter)) {
            return count($this->users);
        }

        $count = 0;
        $this->constructPattern($filter);

        foreach ($this->users as $user => $info) {
            $count += $this->filter($user, $info);
        }

        return $count;
    }

    /**
     * @param int $start
     * @param int $limit
     * @param array $filter
     * @return array
     */
    public function retrieveUsers($start = 0, $limit = 0, $filter = array()) {
        if ($this->users === null) {
            $this->loadUserData();
        }

        ksort($this->users);

        $i = 0;
        $count = 0;
        $out = array();
        $this->constructPattern($filter);

        foreach ($this->users as $user => $info) {
            if ($this->filter($user, $info)) {
                if ($i >= $start) {
                    $out[$user] = $info;
                    $count++;
                    if (($limit > 0) && ($count >= $limit))
                        break;
                }
                $i++;
            }
        }

        return $out;
    }

    /**
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param null $grps
     * @return bool
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {

        $lockfp = $this->lockWrite();

        $this->htpasswd->reload();
        $this->htuser->reload();

        $addOK = $this->htpasswd->addUser($user, $pwd);
        $addOK = $addOK && $this->htuser->addUser($user, $name, $mail);

        if (isset($grps)) {
            $this->htgroup->reload();
            $addOK = $addOK && $this->htgroup->setGroupsForUser($user, $grps);
        }

        $this->lockRelease($lockfp);
        $this->loadUserData();

        return $addOK;
    }

    /**
     * @param array $users
     * @return int
     */
    public function deleteUsers($users) {

        $userCount = $this->getUserCount();

        $lockfp = $this->lockWrite();

        $this->htpasswd->reload();
        $deleteOK = $this->htpasswd->delete($users);

        if ($this->htuser) {
            $this->htuser->reload();
            $deleteOK =  $deleteOK && $this->htuser->delete($users);
        }

        $this->htgroup->reload();
        $deleteOK = $deleteOK && $this->htgroup->delete($users);

        $this->lockRelease($lockfp);

        $this->loadUserData();
        return ($userCount - $this->getUserCount());
    }

    /**
     * @param string $user
     * @param array $changes
     * @return bool
     */
    public function modifyUser($user, $changes) {

        $lockfp = $this->lockWrite();

        $modifyOK = true;

        $this->htpasswd->reload();
        $this->htuser->reload();
        $this->htgroup->reload();

        if (!empty($changes['user'])) {

            $newUser = $changes['user'];
            $modifyOK = $this->htpasswd->renameUser($user, $newUser, empty($changes['pass']));

            if ($modifyOK) {
                $userInfo = $this->htuser->getUserInfo($user);
                if ($userInfo) {
                    $modifyOK = $modifyOK && $this->htuser->delete($user, false);
                    $changes = array_merge($userInfo, $changes);
                }

                $oldGroups = $this->htgroup->getGroupsForUser($user);
                if ($oldGroups) {
                    $modifyOK = $modifyOK && $this->htgroup->delete($user, false);
                    if (empty($changes['grps'])) {
                            $changes['grps'] = $oldGroups;
                    }
                }
                $user = $newUser;
            }
        }

        if (!empty($changes['pass'])) {
            $modifyOK = $modifyOK && $this->htpasswd->changePass($user, $changes['pass']);
        }

        if (!empty($changes['grps'])) {
            $modifyOK = $modifyOK && $this->htgroup->setGroupsForUser($user, $changes['grps']);
        }

        $modifyOK = $modifyOK && $this->htuser->modify($user, $changes);

        $this->lockRelease($lockfp);
        $this->loadUserdata();
        return $modifyOK;
    }

    /**
     * @param string $user
     * @return array
     */
    private function defaultUserInfo($user) {
        $defaultGroup = $this->getConf('defaultgrp');

        $name = $user;
        $mail = $user."@localhost";
        $pass = "";
        $userInfo = compact("name", "mail", "pass");

        $userInfo['grps'] = $defaultGroup ? array($defaultGroup) : array();

        return $userInfo;
    }

    /**
     * @brief Load user data.
     */
    private function loadUserData() {

        $this->users = array();
        $passwords = $this->htpasswd->getUsers();
        foreach ($passwords as $user => $cryptPass) {

            $this->users[$user] = $this->defaultUserInfo($user);
            $this->users[$user]['pass']=$cryptPass;
        }

        $extendedUserInfo = $this->htuser->getUsers();
        foreach ($extendedUserInfo as $user => $userinfo) {
            if (!isset($this->users[$user])) {
                $this->users[$user] = $this->defaultUserInfo($user);
            }
            $this->users[$user] = array_merge($this->users[$user], $userinfo);
        }

        $groupsByUser = $this->htgroup->getGroupsByUser();
        foreach ($groupsByUser as $user => $groups) {

            if (!isset($this->users[$user])) {
                $this->users[$user] = $this->defaultUserInfo($user);
            }
            $this->users[$user]['grps']=$groups;
        }
    }

    /**
     * @brief Return 1 if $user + $info match $filter criteria, 0 otherwise.
     * @param string $user
     * @param array $info
     * @return int
     */
    private function filter($user, $info) {

        foreach ($this->_pattern as $item => $pattern) {
            if ($item == 'user') {
                if (!preg_match($pattern, $user))
                    return 0;
            } else
                if ($item == 'grps') {
                    if (!count(preg_grep($pattern, $info['grps'])))
                        return 0;
                } else {
                    if (!preg_match($pattern, $info[$item]))
                        return 0;
                }
        }
        return 1;
    }

    /**
     * @param array $filter
     */
    private function constructPattern($filter) {
        $this->_pattern = array();
        foreach ($filter as $item => $pattern) {
            //$this->_pattern[$item] = '/'.preg_quote($pattern,"/").'/'; // don't allow regex characters
            $this->_pattern[$item] = '/' . str_replace('/', '\/', $pattern) . '/'; // allow regex characters
        }
    }

    /**
     * @return bool
     */
    private function findHtAccess() {
        $htaccessFile = $this->getConf('htaccess');

        if (empty($htaccessFile)) {
            $htaccess = realpath(dirname(__FILE__) . '/../../');
            //Stop at docroot or '/'
            while (!empty ($htaccess) && !file_exists($htaccess . '/.htaccess')) {

                $parentDir = dirname($htaccess);
                if ($parentDir == $htaccess) {
                    $htaccess = '';
                } else {
                    $htaccess = dirname($htaccess);
                }
            }
              $htaccessFile = $htaccess . "/.htaccess";
        }

        if (!file_exists($htaccessFile)) {
            return false;
        }

        $lockfp = $this->lockRead($htaccessFile);

        $lines = file($htaccessFile);

        foreach ($lines as $line) {
            $row = preg_split("'\\s'", $line, 2);
            $var = strtolower(trim($row[0]));
            $value = trim($row[1]);

            if ($var == "authuserfile") {
                $this->htpasswd->init($value);
                $htUserFile = $this->getConf('htuser');
                if (empty($htUserFile)) {
                    $htUserFile="htuser";
                }
                if (basename($htUserFile) == $htUserFile) {
                    $htUserFile = dirname($value) . '/' . $htUserFile;
                }
                $this->htuser->init($htUserFile);
            }
            elseif ($var == "authgroupfile") {
                $this->htgroup->init($value);
            } elseif ($var == "authname") {
                $this->realm = $value;
            }

        }

        $this->lockRelease($lockfp);

        return true;
    }

    /**
     * @param string $lockFile
     * @return resource
     */
    private function lockRead($lockFile) {
        $this->lockFile = $lockFile;
        $lockfp = fopen($lockFile, 'r');
        flock($lockfp, LOCK_SH) || die("Can't get lock");
        return $lockfp;
    }

    /**
     * @return resource
     */
    private function lockWrite() {
        $lockfp = fopen($this->lockFile, 'r');
        flock($lockfp, LOCK_EX) || die("Can't get lock");
        return $lockfp;
    }

    /**
     * @param $lockfp
     */
    private function lockRelease($lockfp) {
        flock($lockfp, LOCK_UN);
    }
}
