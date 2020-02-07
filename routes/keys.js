//Configurations
const config = require('../etc/config.json');

//Web server
var express = require('express');
var app = express();
var router = express.Router();

//MongoDB
var DB = require("../modules/db");
var mdb = new DB(config.mongo.url);
var mongo_instance = config.mongo.instance

//LDAP
var LDAP = require("../modules/ldap");
var ldap = new LDAP(config.ldap);

//logging
const log = require('log-to-file');
const app_log = config.skdc.log_dir+"app.log"
const journal_log = config.skdc.log_dir+"journal.log"

//RSA
var AES_256_CFB = require("../modules/aes-256-cfb");
var aes_256_cfb = new AES_256_CFB();

//Base 32 decode otp secret
const base32Decode = require('base32-decode')

//Authenticator
var speakeasy = require("speakeasy");

/**************************************
 *  Contain routes for user management*
 *  (See nav bar under item "User")   *
 **************************************/


/***************************************
 *          USER MANAGEMENT            *
 ***************************************/

/* GET user add
*  return user add page*/
router.get('/key-mgmt', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role == "user") {
        log("[*] Non admin user is trying to access key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var err = ''
        err += req.query.error;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    mdb.findDocument("users", { email: req.session.email })
                        .then(
                            function (value) {
                                res.render('key-mgmt', {
                                    name: value.name,
                                    surname: value.surname,
                                    username: req.session.email,
                                    sys_username: value.sys_username,
                                    role: value.role,
                                    groups: value.group,
                                    pubKey: value.pubKey,
                                    key_lock: req.session.key_lock,
                                    code: req.query.code,
                                    error: err
                                });
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                            }
                        );
                },
                function(err){
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                });
    }
});

router.get('/key-unlock', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role == "user") {
        log("[*] Non admin user is trying to access key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var otp = req.query.otp;
        mdb.connect(mongo_instance)
        .then(
            function(value){
                mdb.findDocument("users", {email: req.session.email}, {sys_username: 1, email: 1, otp_secret: 1, key_last_unlock: 1, pubKey:1})
                    .then(
                        function(user){
                            var verified = speakeasy.totp.verify({
                              secret: user.otp_secret,
                              encoding: 'base32',
                              token: otp
                            });
                            if(verified){
                                req.session.key_lock = false;
                                var now = new Date();
                                mdb.updDocument("users", {email: req.session.email}, {$set: { key_last_unlock: now.toISOString().replace(/-/g,"").replace("T","").replace(/:/g,"").slice(0,-5)+"Z" }})
                                    .then(
                                        function(){
                                            //at first unlock key_last_unlock attribute is undefined
                                            if (user.key_last_unlock == undefined)
                                                key_last_unlock = new Date();
                                            else
                                                key_last_unlock = new Date(user.key_last_unlock.slice(4,6)+"/"+user.key_last_unlock.slice(6,8)+"/"+user.key_last_unlock.slice(0,4)+" "+user.key_last_unlock.slice(8,10)+":"+user.key_last_unlock.slice(10,12));
                                            diffTime = Math.abs(now - key_last_unlock);
                                            diffHours = Math.ceil(diffTime / (1000 * 60 * 60));

                                            //if less than 9 means 1 decryption has already been performed, no decryption needed
                                            if(diffHours<9)
                                            {
                                                log("[+] User "+req.session.email+" successfully unlocked his SSH key", app_log);
                                                log("[+] User "+req.session.email+" successfully unlocked his SSH key. request occurred from "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                                res.redirect("/key-mgmt?error=false");
                                            }
                                            else{
                                                log("[+] SKDC is decripting "+req.session.email+" key", app_log);
                                                //user first unlock
                                                if(user.pubKey == undefined)
                                                {
                                                    log("[+] User "+req.session.email+" successfully unlocked his SSH key", app_log);
                                                    res.redirect("/key-mgmt?error=false");
                                                }
                                                else if(user.pubKey.indexOf("ssh-rsa") == -1)
                                                {
                                                    var key = Buffer.from(base32Decode(user.otp_secret, 'RFC4648'), 'HEX').toString();
                                                    const decKey = aes_256_cfb.AESdecrypt(key, user.pubKey);
                                                    mdb.updDocument("users", {sys_username: user.sys_username}, { $set: { pubKey: decKey }})
                                                        .then(
                                                                function(){
                                                                    ldap.modKey(user.sys_username, decKey)
                                                                        .then(
                                                                            function(succ){
                                                                                log("[+] SKDC successfully decrypted "+req.session.email+" key", app_log);
                                                                                log("[+] User "+user.email+" public key unlocked in specified timestamp by OTP authentication", journal_log);
                                                                                res.redirect("/key-mgmt?error=false");
                                                                            },
                                                                            function(err){
                                                                                log('[-] Connection to LDAP has been established, but no query can be performed, reason: '+err.message, app_log);
                                                                                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                                                                            }
                                                                        )
                                                                },
                                                                function(err){
                                                                    log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                                                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                                                                }
                                                        );
                                                }
                                                else{
                                                    log("[+] SKDC key of "+req.session.email+" already decrypted, last unlock time: "+user.key_last_unlock+" no decryption needed.", app_log);
                                                    res.redirect("/key-mgmt?error=false");
                                                }
                                            }
                                        },
                                        function(err){
                                            log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                                        }
                                    );
                            }
                            else{
                                log("[*] User "+user.sys_username+" failed to unlock ssh public ket, reason: wrong OTP key",app_log);
                                res.redirect("/key-mgmt?error=true&code=\'SK010\'");
                            }
                        },
                        function(err){
                            log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        }
                    );
            }, function(err){
                log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
            }
        );
    }
});

router.get('/key-save-otp-secret', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role == "user") {
        log("[*] Non admin user is trying to access key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var secret = req.query.otp_secret;
        mdb.connect(mongo_instance)
            .then(
                    function(){
                        mdb.updDocument("users", {email: req.session.email}, { $set: {otp_secret: secret }})
                            .then(
                                function () {
                                    // TODO 5 Add to ansible event queue (if user exists, update keys)
                                    log("[+] User "+req.session.email+" successfully saved OTP secret.", app_log);
                                    log("[+] User "+req.session.email+" successfully saved OTP secret at specified timestamp. change occurred from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                    res.redirect('/?error=false');
                                },
                                function (err) {
                                    log('[-] Connection cannot update key on MongoDB, reason: '+err.message, app_log);
                                    res.redirect('/?error=true&code=\'DM001\'');
                                }
                            )
                    },
                    function(err){
                        log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                        res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                    }
            );
    }
});

router.post('/key-upload', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role == "user") {
        log("[*] Non admin user is trying to access key-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var pubKey = req.body.pastedPubKey;
        var email = req.session.email;
        var uid = req.body.uid;
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            p1 = mdb.updDocument("users", {"email": email}, {$set: { pubKey: pubKey }})
                            p2 = ldap.modKey(uid, pubKey)
                            Promise.all([p1, p2])
                                .then(
                                    function () {
                                        // TODO 5 Add to ansible event queue (if user exists, update keys)
                                        log("[+] User "+email+" successfully changed ssh key.", app_log);
                                        log("[+] User "+email+" update ssh public key at specified timestamp. change occurred from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                        res.redirect('/key-mgmt?error=false');
                                    },
                                    function (err) {
                                        log('[-] Connection cannot update key on MongoDB or LDAP, reason: '+err.message, app_log);
                                        res.redirect('/key-mgmt?error=true&code=\'DA001\'');
                                    }
                                )
                        },
                        function(err){
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });
    }
});


module.exports = router;
