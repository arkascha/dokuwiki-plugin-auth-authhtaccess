<?php

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
 * @author	   Grant Gardner <grant@lastweekend.com.au>
 * Version:    0.1
 *
 * Work based on previous authentication backends by:
 * @author     Samuele Tognini <samuele@cli.di.unipi.it>
 * @author     Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author     Marcel Meulemans <marcel_AT_meulemans_DOT_org>
 * Additions:  Sebastian S <Seb.S@web.expr42.net>
 * 
 */

define('DOKU_AUTH', dirname(__FILE__));
require_once (DOKU_AUTH . '/basic.class.php');
require_once ('htbase.class.php');
require_once ('htpasswd.class.php');
require_once ('htgroup.class.php');
require_once ('htuser.class.php');

class auth_htaccess extends auth_basic {

	var $users = null;
	var $lockFile = null;
	var $htpasswd;
	var $htgroup;
	var $htusers;
	var $realm = null;
	var $_pattern = array ();

	/**
	 * Constructor
	 * Check config, .htaccess and set capabilities
	 */
	function auth_htaccess() {
		global $conf;
		$defaultGroup = $conf['htaccess_defaultgrp'];

		$this->htpasswd = new htpasswd();
		$this->htuser = new htuser();
		$this->htgroup = new htgroup("",$defaultGroup);
		
		if (!$this->findHtAccess()) {
       $this->success = false;
       return;
    } 

		if (!$this->htpasswd->canRead()) {
			$this->success = false;
			return;
		}

		if (isset ($_SERVER['PHP_AUTH_USER']) and isset ($_SERVER['PHP_AUTH_PW'])) {			
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
		
			
		//And groups.
		if ($this->htgroup->canRead()) {
			$this->cando['getGroups'] = true;
			if ($this->htgroup->canModify()) {
				$this->cando['modGroups'] = true;		
			}
		}

		$this->success = true;
	}
	
	  
	
  /**
   *
   * @see auth_login()
   *
   * @param   string  $user    Username
   * @param   string  $pass    Cleartext Password
   * @param   bool    $sticky  Cookie should not expire
   * @return  bool             true on successful auth
   */
  function trustExternal($user,$pass,$sticky=false){
    global $USERINFO;
    global $conf;
    
    // Never use $user, $pass as user will never arrive via login page.
	$user = $_SERVER['PHP_AUTH_USER'];
	$pass = $_SERVER['PHP_AUTH_PW'];
	
	//Possibly could trust those headers, but why bother!
	if (! $this->htpasswd->verifyUser($user,$pass)) {
		return false;
	}	
	
	$userInfo = $this->getUserData($user);
	
    $USERINFO['name'] = $userInfo['name'];
    $USERINFO['mail'] = $userInfo['mail'];
    $USERINFO['grps'] = $userInfo['grps'];
    $USERINFO['pass'] = $userInfo['pass'];
    $_SERVER['REMOTE_USER'] = $user;
    $_SESSION[$conf['title']]['auth']['user'] = $user;
    $_SESSION[$conf['title']]['auth']['pass'] = $pass;
    $_SESSION[$conf['title']]['auth']['info'] = $USERINFO;
    
    return true;
  }


	
	function logOff() {
		global $conf;
		//works only with basic http authentication on some browsers!.
		//Don't try logging in again, must hit cancel
		if (isset ($this->realm)) {
			$default_msg = "Successful logout. Retry login <a href='" . DOKU_BASE . "'>here</a>.";
			header('WWW-Authenticate: Basic realm="' . $this->realm . '"');
			header('HTTP/1.0 401 Unauthorized');
			(isset ($conf['htaccess_logout'])) ? print ($conf['htaccess_logout']) : print ($default_msg);
			exit;
		} 
	}

  /**
   * Check user+password, if using the login page
   * or update profile form
   *
   * @author  Andreas Gohr <andi@splitbrain.org>
   * @return  bool
   */
  function checkPass($user,$pass){
    return $this->htpasswd->verifyUser($user,$pass);
  }
  
   /**
	* Return user info
    */
	
	function getUserData($user, $ht_defaultgrp = true) {
		global $conf;
		
		if ($this->users === null) $this->loadUserData();

		return isset ($this->users[$user]) ? $this->users[$user] : false;
	}

	function getUserCount($filter = array ()) {
		if ($this->users === null) $this->loadUserData();

		if (!count($filter))
			return count($this->users);

		$count = 0;
		$this->constructPattern($filter);

		foreach ($this->users as $user => $info) {
			$count += $this->filter($user, $info);
		}

		return $count;
	}

	function retrieveUsers($start = 0, $limit = 0, $filter = array ()) {
		if ($this->users === null) 
			$this->loadUserData();

		ksort($this->users);

		$i = 0;
		$count = 0;
		$out = array ();
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
	
	function createUser($user, $pwd, $name, $mail, $grps = null) {
		global $conf;
	
		$lockfp = $this->lockWrite();
		
		$this->htpasswd->reload();
		$this->htuser->reload();

		$addOK = $this->htpasswd->addUser($user,$pwd);
		$addOK = $addOK && $this->htuser->addUser($user,$name,$mail);
		
		if (isset($grps)) {
			$this->htgroup->reload();
			$addOK = $addOK && $this->htgroup->setGroupsForUser($user,$grps);
		}

		$this->lockRelease($lockfp);
		$this->loadUserData();
				
		return $addOK;
	}
	
	function deleteUsers($users) {
				
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
	
  function modifyUser($user, $changes) {
    	
  	$lockfp = $this->lockWrite();
  	
  	$modifyOK = true;
  	
  	$this->htpasswd->reload();
  	$this->htuser->reload();
  	$this->htgroup->reload();
  	
	if (!empty($changes['user'])) {
		
		$newUser = $changes['user'];
		$modifyOK = $this->htpasswd->renameUser($user,$newUser,empty($changes['pass']));
		
		if ($modifyOK) {
			$userInfo = $this->htuser->getUserInfo($user);
			if ($userInfo) {
				$modifyOK = $modifyOK && $this->htuser->delete($user,false);
				$changes = array_merge($userInfo,$changes);
			}

			$oldGroups = $this->htgroup->getGroupsForUser($user);
			if ($oldGroups) {
				$modifyOK = $modifyOK && $this->htgroup->delete($user,false);
				if (empty($changes['grps'])) {
						$changes['grps'] = $oldGroups;
				}
			}
						
						
			$user = $newUser;
		}
	}
	
	if (!empty($changes['pass'])) {
		$modifyOK = $modifyOK && $this->htpasswd->changePass($user,$changes['pass']);
	}
	
	if (!empty($changes['grps'])) {
		$modifyOK = $modifyOK && $this->htgroup->setGroupsForUser($user,$changes['grps']);
	}
	

	$modifyOK = $modifyOK && $this->htuser->modify($user,$changes);
	
	
	$this->lockRelease($lockfp);
	$this->loadUserdata();
    return $modifyOK;
  }
	private function defaultUserInfo($user) {
		global $conf;
		
		$defaultGroup = $conf['htaccess_defaultgrp'];
		
		$name = $user;
		$mail = $user."@localhost";
		$pass = "";
		$userInfo = compact("name","mail","pass");
		
		if ($defaultGroup) {
			$grps = array($defaultGroup);
		} else {
			$grps = array();
		}
		
		$userInfo['grps'] = $grps;
		
		return $userInfo; 
	}
	
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
		* return 1 if $user + $info match $filter criteria, 0 otherwise
		*
		* @author   Chris Smith <chris@jalakai.co.uk>
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

	private function constructPattern($filter) {
		$this->_pattern = array ();
		foreach ($filter as $item => $pattern) {
			//        $this->_pattern[$item] = '/'.preg_quote($pattern,"/").'/';          // don't allow regex characters
			$this->_pattern[$item] = '/' . str_replace('/', '\/', $pattern) . '/'; // allow regex characters
		}
	}

	private function findHtAccess() {
		global $conf;
		
	  $htaccessFile = $conf['htaccess_file'];
    
    if (empty($htaccessFile)) {
		$htaccess = realpath(DOKU_AUTH . "/../../");
		//Stop at docroot or "/"
		while (!empty ($htaccess) && !file_exists($htaccess . "/.htaccess")) {

			$parent_dir = dirname($htaccess);
			if ($parent_dir == $htaccess) {
				$htaccess = "";
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
			$row = preg_split("'\s'", $line,2);
			$var = strtolower(trim($row[0]));
			$value = trim($row[1]);

			if ($var == "authuserfile") {
				$this->htpasswd->init($value);
				$htUserFile = $conf['htaccess_htuser'];
				if (empty($htUserFile)) {
					$htUserFile="htuser";
				}
				if (basename($htUserFile) == $htUserFile) {
					$htUserFile = dirname($value)."/$htUserFile";
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


	private function lockRead($lockFile) {
		$this->lockFile = $lockFile;
		$lockfp = fopen($lockFile,'r');
		flock($lockfp,LOCK_SH) || die("Can't get lock");
		return $lockfp;
	}

	private function lockWrite() {
		$lockfp = fopen($this->lockFile,'r');		
		flock($lockfp,LOCK_EX) || die("Can't get lock");
		return $lockfp;
	}
	
	private function lockRelease($lockfp) {
		flock($lockfp,LOCK_UN);
	}
}
//Setup VIM: ex: et ts=2 enc=utf-8 :
