//Configurations
const config = require('../etc/config.json');

//logging
const log = require('log-to-file');
const ldap_log = config.skdc.log_dir+"ldap.log";

//Base module extended in this class
var ldap = require('ldapjs');

//FS to read ldap certs
var fs = require('fs');

//required for the unbind (may be removed in future)
var assert = require('assert');

//async function for password generation
const { promisify } = require('util');
const exec = promisify(require('child_process').exec)

//random string generation
var randomstring = require("randomstring");


function LDAP(configObj){
    this.client = ldap.createClient({
        url: configObj.uri,
        tlsOptions: {
            'ca': fs.readFileSync(configObj.TLS.CA),
            'key': fs.readFileSync(configObj.TLS.KEY),
            'cert': fs.readFileSync(configObj.TLS.CERT)
        }
    });
    this.ldap_base_dn = configObj.base_dn;
    this.ldap_base_users = "ou="+configObj.users_ou+","+configObj.base_dn;
    this.ldap_base_groups = "ou="+configObj.groups_ou+","+configObj.base_dn;
    this.ldap_bind_username = configObj.bind_dn;
    this.ldap_bind_password = configObj.bind_password;
}

LDAP.prototype.auth = function(uid, pwd)
{
    var _this = this;
    return new Promise(function (resolve, reject){
        _this.client.bind("uid="+uid+","+_this.ldap_base_users, pwd, function(err) {
            if(err){
                log("[-] cannot auth user, reason: "+err.message,ldap_log);
                reject(err);
            }
            else{
                log("[+] User "+uid+" authed",ldap_log);
                resolve();
            }
        });
    });
}

LDAP.prototype.search = function(srcOpt)
{
    var _this = this;
    return new Promise(function (resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                var base = _this.ldap_base_users;
                var entries = [];
                _this.client.search(base, srcOpt, function (err, res) {
                    if (err)
                    {
                        log('[-] Error occurred while ldap search, reason:'+ err.message,ldap_log);
                        reject();
                    }
                    else
                    {
                        res.on('searchEntry', function (entry) {
                            var r = entry.object;
                            entries.push(r);
                        });
                        res.on('end', function (result) {
                            resolve(entries);
                        });
                    }
                });
            }
        });
    });
}

LDAP.prototype.modKey = function (uid, pubKey)
{
    var _this = this
    return new Promise(function(resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                var change = new ldap.Change({
                    operation: 'replace',
                    modification: {
                        sshPublicKey: pubKey
                    }
                });
                _this.client.modify("uid="+uid+","+_this.ldap_base_users, change,function(err) {
                    if(err){
                        log('[-] Error occurred while modifing '+ err.message,ldap_log);
                        reject(err);
                    }
                    else{
                        log('[+] User key modified',ldap_log);
                        resolve();
                    }
                });
            }
        });
    });
}

LDAP.prototype.lockAccount = function (uid)
{
    var now = new Date();
    var _this = this
    return new Promise(function(resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                var change = new ldap.Change({
                    operation: 'add',
                    modification: {
                        pwdAccountLockedTime: now.toISOString().replace(/-/g,"").replace("T","").replace(/:/g,"").slice(0,-5)+"Z"
                    }
                });
                _this.client.modify("uid="+uid+","+_this.ldap_base_users, change,function(err) {
                    if(err){
                        log('[-] Error occurred while modifing '+ err.message,ldap_log);
                        reject(err);
                    }
                    else{
                        log('[+] User key modified',ldap_log);
                        resolve();
                    }
                });
            }
        });
    });
}

LDAP.prototype.unlockAccount = function (uid)
{
    var _this = this
    return new Promise(function(resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                var change = new ldap.Change({
                    operation: 'delete',
                    modification: {
                        pwdAccountLockedTime: []
                    }
                });
                _this.client.modify("uid="+uid+","+_this.ldap_base_users, change,function(err) {
                    if(err){
                        log('[-] Error occurred while modifing '+ err.message,ldap_log);
                        reject(err);
                    }
                    else{
                        log('[+] User key modified',ldap_log);
                        resolve();
                    }
                });
            }
        });
    });
}

LDAP.prototype.modPwd = function (uid, pwd)
{
    var _this = this
    return new Promise(function(resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                _this.genLdapHashes(pwd)
                .then(
                    function(hashes){
                        var change = new ldap.Change({
                            operation: 'replace',
                            modification: {
                                userPassword: hashes.ldap,
                            }
                        });
                        _this.client.modify("uid="+uid+","+_this.ldap_base_users, change,function(err) {
                            if(err){
                                reject(err);
                            }
                            else{
                                resolve();
                            }
                        });
                        var change = new ldap.Change({
                            operation: 'replace',
                            modification: {
                                sambaNTPassword: hashes.samba
                            }
                        });
                        _this.client.modify("uid="+uid+","+_this.ldap_base_users, change,function(err) {
                            if(err){
                                reject(err);
                            }
                            else{
                                resolve();
                            }
                        });
                    },
                    function(err){
                            log("[-] unable to genearte LDAP hashes reason:"+err,ldap_log);
                    }
                );
            }
        });
    });
}


LDAP.prototype.delUser = function (uid)
{
    var _this = this
    return new Promise(function(resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                //delete user
                _this.client.del("uid="+uid+","+_this.ldap_base_users,function(err){
                    if(err){
                        reject(err);
                    }
                    else
                    {
                        //delete group
                        _this.client.del("cn="+uid+","+_this.ldap_base_groups,function(err){
                            if(err){
                                reject(err);
                            }
                            else
                            {
                                resolve();
                            }
                        });
                    }
                });
            };
        });
    });
}



LDAP.prototype.addUser = function (uid, domain, password)
{
    var _this = this
    return new Promise(function(resolve, reject){
        _this.client.bind(_this.ldap_bind_username, _this.ldap_bind_password, function(err) {
            if (err)
            {
                log('[-] Error occurred while binding'+ err.message,ldap_log);
                reject();
            }
            else
            {
                //max_uid and max_gid interrogation
                _this.search({ scope: 'sub', filter: '(uid=*)', attributes: ['uidNumber', 'gidNumber']})
                .then(
                    function(res){
                        max = res[res.length-1];
                        //incrementing uid and gid for new user
                        max_uid = parseInt(max.uidNumber) + 1;
                        max_gid = parseInt(max.gidNumber) + 1;
                        _this.genLdapHashes(password)
                            .then(
                                function(hashes){
                                    var fullname = uid.split(".");
                                    var alias_uid = fullname[0].charAt(0) + fullname[1];
                                    var user = {
                                        objectClass: ["top",
                                        "person",
                                        "posixAccount",
                                        "shadowAccount",
                                        "sambaSamAccount",
                                        "inetOrgPerson",
                                        "organizationalPerson",
                                        "ldapPublicKey"],
                                        loginShell: "/bin/bash",
                                        sambaAcctFlags: "[U          ]",
                                        sambaPasswordHistory: "0000000000000000000000000000000000000000000000000000000000000000",
                                        sambaSID: "S-1-5-21-172967073-1057704785-2805866951-"+max_gid,
                                        sambaNTPassword: hashes.samba,
                                        homeDirectory: "/home/"+uid,
                                        uid: [uid, alias_uid],
                                        cn: uid,
                                        sn: uid,
                                        uidNumber: max_uid,
                                        gidNumber: max_gid,
                                        mail: uid+"@"+domain,
                                        userPassword: hashes.ldap,
                                        sshPublicKey: ""
                                    };
                                    var group = {
                                        memberUid: uid,
                                        gidNumber: max_gid,
                                        objectClass: ["top",
                                        "posixGroup"],
                                        cn: uid
                                    };
                                    fullU = "uid="+uid+","+_this.ldap_base_users;
                                    fullG = "cn="+uid+","+_this.ldap_base_groups;
                                    //add user via LDAP
                                    _this.client.add(fullU, user,function(err){
                                        if(err){
                                            reject(err);
                                        }
                                        else
                                        {
                                            //add group
                                            _this.client.add(fullG, group,function(err){
                                                if(err){
                                                    reject(err);
                                                }
                                                else
                                                {
                                                    resolve();
                                                }
                                            });
                                        }
                                    });
                                },
                                function(err){
                                    log("[-] Cannot generate hashes, reason: "+err,ldap_log);
                                }
                            );
                        //user alias
                        var alias_uid = "";
                    },
                    function(err){
                        log("[-] Cannot search in ldap, reason: "+err,ldap_log);
                    }
                );
            }
        });
    });
}
LDAP.prototype.genLdapHashes = async function(pwd){
    var ldap = await exec("/usr/sbin/slappasswd -h '{SSHA512}' -o module-load=pw-sha2.la -o module-path=/usr/lib/ldap -s "+pwd);
    var samba = await exec("printf '%s' '"+pwd+"' | iconv -t utf16le | openssl md4|awk '{print $2}'");
    ldap = ldap.stdout.trim();
    samba = samba.stdout.trim()
    return {ldap, samba};
}
LDAP.prototype.unbind = function()
{
    this.client.unbind(err => {
        assert.ifError(err);
    });
}

module.exports = LDAP;
