This is yet another authentication plugin for dokuwiki that uses the apache .htaccess style control files.
It is easy to set up since no external authority is involved and is suitable only for a relatively small number of users/groups.
It is particularly useful where you want to share user/group information with other web applications that use a similar mechanism.

==== Configuration ====
conf/dokuwiki.php options.
<code php>
$conf['authtype'] = 'htaccess';
$conf['htaccess_defaultgrp'] = 'guest'; //optional. All valid users will be members of this group.

//Optional path to htaccess configuration. Blank or not included will autodiscover a ".htaccess" file like Apache does.
//This is useful where you are not using BASIC authentication but still want to use these formats for user/password/group info.
//$conf['htaccess_file'] = 'conf/htauth';

$conf['htaccess_htuser'] = 'htuser'; //Name of htuser file. If no path specified will be in same directory as AuthUserFile.
$conf['autopasswd'] = 1;  //set to zero if you want to specify passwords to users. 
$conf['openregister']= 0; //open register won't work behind basic auth
$conf['resendpasswd']= 0; //also won't work behind basic auth
</code>

A typical .htaccess file would live in the dokuwiki root directory or somewhere further up the path
<code>

AuthName Dokuwiki
AuthUserFile /home/unison/dokuwiki/htpasswd
AuthGroupFile /home/unison/dokuwiki/htgroups

# Use Basic authentication
AuthType Basic
<Limit GET POST>
satisfy all
require valid-user
</Limit>
</code>

AuthUserFile must point to an existing (possibly empty) file.

AuthGroupFile is optional, but omitting it will only make sense if you set $conf['htaccess_defaultgrp'] and set default acl to allow something on that group.

These files must be writable by your webserver user if you want to add new users, allow users to change passwords etc...

=== Using Dokuwiki's form based login ===

This backend will also work with dokuwiki's normal login page by setting $conf['htaccess_file'] to point to a different file that has the same format as above but is not the one used to control the webserver. In this case the only relevant directives are AuthUserfile and AuthGroupFile. In fact the AuthName setting must not be used in this case, since it forces a http basic authentication upon logout.

You will lose single sign-on capability between applications but things like openregister and resendpasswd will work as dokuwiki intends.

==== Development info ====
^File^Class^Description^
|auth.php|auth_plugin_authhtaccess|Implements the dokuwiki authentication, auto discovers .htaccess etc..|`
|htbase.php|auth_plugin_authhtaccess_htbase|Basic layout for managing a data file|
|htpasswd.php|auth_plugin_authhtaccess_htpasswd|Manages an AuthUserFile (htpasswd)- format <user>:<crypt password>|
|htgroup.php|auth_plugin_authhtaccess_htgroup|Manages an AuthGroupFile - format <group>:<user1> <user2> <user3>|
|htuser.php|auth_plugin_authhtaccess_htuser|Manages file for storing full name and email address - format "<user>:<name>:<email>"|

If $_SERVER['PHP_AUTH_USER'] and $_SERVER['PHP_AUTH_PW'] are set, indicating BASIC authentication are in place then the class is deemed to support "trustExternal" and will re-verify the username and password based on these parameters. Otherwise the normal dokuwiki login page method will be used.

== Locking ==
flock is used on the .htaccess file itself whenever the other files need to be read or written to. Should be safe as long as nothing else is updating these files.

==== TODO ====
 * Test the locking strategy (uses flock) to see if it really works under load. (Lots of users changing passwords etc)
 * Test under a real apache implementation (I'm using Jetty with a HTAccessHandler that attempts to mimic apache behaviour)
 * Test on non Linux OS
 * Allow the "htuser" file to be optional (only makes sense if autopasswd is off because otherwise email is necessary for registering users)

==== Concerns ====
Whilst porting the existing implementation as required a few issues became clear. 
Those issues have not (yet) been solved or removed, since this is not part of my current goal. Nevertheless it is important to point them out: 
 * definitely only suited for a real small number of users
   * won't scale, since files have to be read in full and rewritten in full all the time
   * file system based locking indeed might get an issue with larger user base
 * selection of password hashing algorithm
   * does not obey the algorithm set in the configuration
   * usage of the `crypt()` function appears hard wired
 * password is stored (encrypted) in client side cookie
   * motivation appears to be the "remember me" feature
   * might be a general dokuwiki issue

==== Authors ====
 * Grant Gardner <grant@lastweekend.com.au>
 * Christian Reiner <info@christian-reiner.info>

Based on previous authentication backends by:
 * @author     Samuele Tognini <samuele@cli.di.unipi.it>
 * @author     Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author     Marcel Meulemans <marcel@meulemans.org>
 * @author     Grant Gardner <grant@lastweekend.com.au>
 * Additions:  Sebastian S <Seb.S@web.expr42.net>

==== Release Notes ====

=== 1.0 (Grant Gardner) ===
 * Initial implementation
=== 1.01 (Grant Gardner) ===
 * Fixed bug where deleting users would leave their groups behind
 * Fixed incorrect case-sensitive matching of values in .htaccess files
 * Allow configuration of htaccess file location to bypass .htaccess auto-discovery
=== 2.00 (Christian Reiner) ===
 * Ported implementation to the current plugin based authentication strategy used in dokuwiki since version 2014-09-29
 * A number of fixes and corrections, but no consequent cleanup
