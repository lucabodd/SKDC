//Configurations
const config = require('../etc/config.json');

//Web server
var express = require('express');
var app = express();
var router = express.Router();
var session = require('express-session');
//app.use(session({secret: 's3cr3t', saveUninitialized : true, resave : false }));

//MongoDB
var DB = require("../modules/db");
var mdb = new DB(config.mongo.url);
var mongo_instance = config.mongo.instance

//random string generation
var randomstring = require("randomstring");

//Process spawning
const exec = require('child_process').exec;

//LDAP
var LDAP = require("../modules/ldap");
var ldap = new LDAP(config.ldap);

//logging
const log = require('log-to-file');
const app_log = config.skdc.log_dir+"app.log";
const journal_log = config.skdc.log_dir+"journal.log";

//Mail module and templates
const util = require('util');
var nodemailer = require('nodemailer');
const mail = require('../etc/mailtemplates.json');

/**************************************
 *  Contain routes for user management*
 *  (See nav bar under item "User")   *
 **************************************/


/***************************************
 *          USER MANAGEMENT            *
 ***************************************/

/* GET user add
*  return user add page*/
router.get('/user-mgmt', function (req, res, next) {
        var err = ''
        err += req.query.error;
        console.log(err);
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var users = mdb.findManyDocuments("users", {}, {name: 1, surname: 1, email: 1, group: 1, role: 1, sys_username:1, pwdAccountLockedTime:1, pubKey:1, otp_secret: 1 });
                    var userCount = mdb.countCollectionItems("users");
                    var groups = mdb.findManyDocuments("groups", {});
                    Promise.all([users, userCount, groups])
                        .then(
                            function (value) {
                                res.render('user-mgmt', {
                                    users: value[0],
                                    user_count: value[1],
                                    username: req.session.email,
                                    role: req.session.role,
                                    groups: value[2],
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
});

/* POST user add
 * add new user in DB
 * This method is not adding any key in order to keep key regeneration reusable
 */

router.post('/user-add', function (req, res, next) {
    //format system username
    var fullname = req.body.uid.split(".");
    var document = {
        email: req.body.uid+"@"+req.body.domain,
        name: fullname[0].charAt(0).toUpperCase() + fullname[0].slice(1),
        surname: fullname[1].charAt(0).toUpperCase() + fullname[1].slice(1),
        sys_username: req.body.uid,
        role: req.body.user_role,
        group: req.body.user_group,
        password: undefined,
        pubKey: undefined
    };

    mdb.connect(mongo_instance)
        .then(
            function () {
                //password generation
                const password = randomstring.generate(8);
                //adding user to DBs
                var p1 = mdb.addDocument("users", document);
                var p2 = ldap.addUser(req.body.uid, req.body.domain, password);
                //Deleting attributes to add user in group members
                delete document.password;
                delete document.pubKey;
                delete document.group;
                var p3 = mdb.updDocument("groups", {name: req.body.user_group}, {$push: {members: document}});
                Promise.all([p1, p2, p3])
                    .then(
                        function () {
                            log("[+] User "+req.body.uid+" on internal system by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                            log("[+] User "+req.body.uid+" insered successfully on LDAP and MongoDB by: "+req.session.email, app_log);
                            //sending Mail
                            const transporter = nodemailer.createTransport({
                                port: 25,
                                host: 'localhost',
                                tls: {
                                    rejectUnauthorized: false
                                }
                             });
                             text="User "+document.sys_username+" has been added to SKDC your temporary password is: "+password+" please change it clicking on the button below";
                             var message = {
                                from: 'skdc.app@kaleyra.com',
                                to: document.email,
                                subject: "SKDC - User "+document.sys_username+" added",
                                html: util.format(mail.standard , text)
                             };

                             transporter.sendMail(message, (error, info) => {
                                if (error) {
                                    log("[!] User "+req.body.uid+" insered successfully on LDAP and MongoDB by: "+req.session.email+" but no mail could be sent, reason: "+error,app_log);
                                    res.render('error', {
                                        message: "500",
                                        error: {status: "Service Unvailable", detail: "Server cannot send mail"}
                                    });
                                }
                                else {
                                    log("[!] User "+req.body.uid+" insered successfully on LDAP and MongoDB by: "+req.session.email+" mail sent. ",app_log);
                                    res.redirect('/ldap-sync');
                                }
                              });
                        },
                        function (err) {
                            log('[-] Connection cannot update MongoDB or LDAP, reason: '+err.message, app_log);
                            res.redirect('/user-mgmt?error=true&code=\'DA001\'');
                        })
            },
            function (err) {
                log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
            });
});

/* GET ldap-sync
 * sync local mongo users with LDAP
 */
router.get('/ldap-sync', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
     else {
       ldap.search({ scope: 'sub', filter: '(uid=*)', attributes: ['mail','cn','userPassword','sshPublicKey', 'pwdChangedTime', 'pwdAccountLockedTime']})
         .then(
             function(ldap_rset){
                 ldap_rset.forEach(function (ldap_user) {
                     //define SKDC local user from LDAP db
                     delete ldap_user.dn;
                     fullname = ldap_user.cn.split(".");
                     var document = {
                         email: ldap_user.mail,
                         name: fullname[0].charAt(0).toUpperCase() + fullname[0].slice(1),
                         surname: fullname[1].charAt(0).toUpperCase() + fullname[1].slice(1),
                         sys_username: ldap_user.cn,
                         role: "user",
                         group: "none",
                         password: ldap_user.userPassword,
                         pubKey: ldap_user.sshPublicKey,
                         pwdChangedTime: ldap_user.pwdChangedTime,
                         pwdAccountLockedTime: ldap_user.pwdAccountLockedTime
                     };

                     //connect to DB and insert users
                     mdb.connect(mongo_instance)
                         .then(
                             function () {
                                 mdb.addDocument("users", document)
                                    .then(
                                        function(success)
                                        {
                                            log("[+] User "+document.email+" synced from LDAP by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                            log("[+] User "+document.email+" insered successfully on LDAP and MongoDB by: "+req.session.email, app_log);
                                        },
                                        function(err)
                                        {
                                            p1 = mdb.updDocument("users", {"email": document.email}, {$set: {"password": document.password}})
                                            p2 = mdb.updDocument("users", {"email": document.email}, {$set: {"pubKey": document.pubKey}})
                                            p3 = mdb.updDocument("users", {"email": document.email}, {$set: {"pwdChangedTime": document.pwdChangedTime}})
                                            p4 = mdb.updDocument("users", {"email": document.email}, {$set: {"pwdAccountLockedTime": document.pwdAccountLockedTime}})
                                            Promise.all([p1, p2, p3, p4])
                                                .then(
                                                    function(succ){
                                                        if(succ.nModified > 0){
                                                            log("[+] User "+document.email+" updated in specified timestamp from LDAP by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                                            log("[+] User "+document.email+" updated by: "+req.session.email, app_log);
                                                        }
                                                        else {
                                                            log("[-] User "+document.email+"not updated, can't detect any change ", app_log);
                                                        }
                                                    },
                                                    function(err){
                                                        log('[-] Connection cannot update MongoDB or LDAP, reason: '+err.message, app_log);
                                                    }
                                                );
                                        }
                                    );
                             },
                             function(err) {
                                 log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                                 res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                             }
                          );
                 });
                 res.redirect('/user-mgmt?error=false');
             },
             function(err){
               log('[-] Connection to LDAP cannot be established, reason: '+err.message, app_log);
               res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
             }
         );
     }
});



/* GET update-keys
 * add new user in DB
 * This method generate ssh key-pair and update user entry
 */
router.get('/delete-key', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var uname = req.query.sys_username;
        var email = req.query.email;
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            p1 = mdb.updDocument("users", {"email": email}, {$set: { pubKey: undefined }})
                            p2 = ldap.modKey(uname, "")
                            Promise.all([p1, p2])
                                .then(
                                    function () {
                                        log("[+] User "+email+" ssh key deleted in specified timestamp by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                        log("[+] User "+email+" updated by: "+req.session.email, app_log);
                                        res.redirect('/user-mgmt?error=false');
                                    },
                                    function (err) {
                                        log('[-] Connection cannot update MongoDB or LDAP, reason: '+err.message, app_log);
                                        res.redirect('/user-mgmt?error=true&code=\'DA001\'');
                                    }
                                )
                        },
                        function(err){
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });

    }
});

router.get('/delete-secret', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var uname = req.query.sys_username;
        var email = req.query.email;
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            p1 = mdb.updDocument("users", {"email": email}, {$unset: { otp_secret: 1 }})
                                .then(
                                    function () {
                                        log("[+] User "+email+" OTP secret deleted in specified timestamp by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                        log("[+] User "+email+" OTP secret deleted: "+req.session.email, app_log);
                                        res.redirect('/user-mgmt?error=false');
                                    },
                                    function (err) {
                                        log('[-] Connection cannot update MongoDB, reason: '+err.message, app_log);
                                        res.redirect('/user-mgmt?error=true&code=\'DM001\'');
                                    }
                                )
                        },
                        function(err){
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });

    }
});
/* GET user-delete
 * add new user in DB
 * This method generate ssh key-pair and update user entry
 */
router.get('/user-delete', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var email = req.query.email;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var p1 = mdb.delDocument("users", {"email": email});
                    var p2 = mdb.updManyDocuments("groups", {},  {$pull : { "members" : {"email" : email}}});
                    var p3 = mdb.delDocument("access", {"email" : email});
                    var p4 = ldap.delUser(req.query.sys_username);
                    Promise.all([p1, p2, p3, p4])
                    .then(
                            function () {
                                log("[+] User "+email+" deleted in specified timestamp by: "+req.session.email+" from "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                log("[+] User "+email+" deleted from LDAP and MongoDB by: "+req.session.email, app_log);
                                res.redirect('/user-mgmt?error=false');
                            },
                            function (err) {
                                log('[-] Connection cannot update MongoDB or LDAP, reason: '+err.message, app_log);
                                res.redirect('/user-mgmt?error=true&code=\'DA001\'');
                            }
                    )
                },
                function(err){
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                }
            )
    }
});

/* GET user lock
 * lock user in ldap
 */
router.get('/user-lock', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var uname = req.query.sys_username;
        var email = req.query.email;
        ldap.lockAccount(uname)
            .then(
                function () {
                    log("[+] User "+email+" locked in specified timestamp by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                    log("[+] User "+email+" locked by: "+req.session.email, app_log);
                    res.redirect('/ldap-sync');
                },
                function (err) {
                    log('[-] Connection cannot update LDAP, reason: '+err.message, app_log);
                    res.redirect('/user-mgmt?error=true&code=\'DL001\'');
                }
            );
    }
});

router.get('/user-unlock', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var uname = req.query.sys_username;
        var email = req.query.email;
        ldap.unlockAccount(uname)
            .then(
                function () {
                    log("[+] User "+email+" unlocked in specified timestamp by: "+req.session.email+" from"+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                    log("[+] User "+email+" unlocked by: "+req.session.email, app_log);
                    res.redirect('/ldap-sync');
                },
                function (err) {
                    log('[-] Connection cannot update LDAP, reason: '+err.message, app_log);
                    res.redirect('/user-mgmt?error=true&code=\'DL001\'');
                }
            );
    }
});
/***************************************
 *      USER MANAGEMENT - END          *
 ***************************************/


/***************************************
 *          GROUP MANAGEMENT           *
 ***************************************/

/* GET user add
 * return user add page*/
router.get('/user-groups', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {

        /* variables to pass
         * user_count
         * username  [session]
         * role [session]1
         * available groups
         * users list*/
        var err = ''
        err += req.query.error;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var users = mdb.findManyDocuments("users", {}, {
                        name: 1,
                        surname: 1,
                        email: 1,
                        sys_username: 1,
                        role: 1,
                        group: 1
                    });
                    var groupCount = mdb.countCollectionItems("groups");
                    var groups = mdb.findManyDocuments("groups", {});
                    Promise.all([users, groupCount, groups])
                        .then(
                            function (value) {
                                res.render('user-groups', {
                                    users: value[0],
                                    group_count: value[1],
                                    username: req.session.email,
                                    role: req.session.role,
                                    groups: value[2],
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

/* POST add new group
*  when group is created, there are no members inside */
router.post('/group-add', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        document = {
            name: req.body.group_name,
            members: []
        };
        mdb.connect(mongo_instance)
            .then(
                function () {
                    mdb.addDocument("groups", document)
                        .then(
                            function () {
                                log("[+] Group "+document.name+" added by: "+req.session.email, app_log);
                                res.redirect('/user-groups?error=false');
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                res.redirect('/user-groups?error=true&code=\'DM001\'');
                            }
                        )
                },
                function (err) {
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                }
            );
    }
});
/* POST ADD USER TO A GROUP
 * add a new object to members array of a group
 */
router.post('/group-add-user', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var req_users = req.body.user;
        var req_groups = req.body.user_group;
        if(!(req_users instanceof Array)){
            req_users = req_users.split();
        }
        if(!(req_groups instanceof Array)){
            req_groups = req_groups.split();
        }

        req_users.forEach(function(u){
            req_groups.forEach(function(group){
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            mdb.findDocument("groups",{"name": group ,"members.email": JSON.parse(u).email})
                                .then(
                                    function (value) {
                                        console.log(value);
                                        if (!value) {
                                            var user = JSON.parse(u);
                                            var addG = mdb.updDocument("groups", {name: group}, {$push: {members: user}})
                                            var strgroup = user.group+" "+group;
                                            strgroup = strgroup.replace("none ", "");
                                            var updU = mdb.updDocument("users", {"email" : user.email}, { $set: { "group": strgroup}})
                                            Promise.all([addG, updU])
                                                .then(
                                                    function () {
                                                        log("[+] User "+user+" added to group "+group+" by: "+req.session.email, app_log);
                                                        res.redirect('/user-groups?error=false');
                                                    },
                                                    function (err) {
                                                        log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                                        res.redirect('/user-groups?error=true&code=\'DM001\'');
                                                    });
                                        }
                                        else {
                                            log('[-] User already added to this group, skipping ...', app_log);
                                            res.redirect('/user-groups?error=true&code=\'SG010\'');
                                        }
                                    },
                                    function (err) {
                                        log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                        res.redirect('/user-groups?error=true&code=\'DM001\'');
                                    });
                        },
                        function (err) {
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });
                });
            });
    }
});


/* POST group-delete
 * delete an entire group
 */
router.post('/group-delete', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var grps = req.body.group_name;
        if(!(grps instanceof Array)){
            grps = grps.split();
        }

        grps.forEach(function(group){
            mdb.connect(mongo_instance)
                .then(
                    function () {
                        /* Consistency to users collection, keeps group field aligned */
                        mdb.findManyDocuments("users", { "group" : { $regex : group}})
                            .then(
                                function(values) {
                                    values.forEach(function (doc) {
                                            doc.group = doc.group.replace(group, '');
                                            if (doc.group == "")
                                                doc.group = "none";
                                            mdb.updDocument("users", {"email": doc.email}, doc)
                                                .then(
                                                    function () {
                                                        log('[+] Groups propagating consistency to User collection : ', app_log);
                                                    },
                                                    function (err) {
                                                        log('[-] Failed propagating consistency to User collection, application will keep on working but this is not good : '+err.message, app_log);
                                                    }
                                                );
                                        },
                                        function (err) {
                                            log('[-] Connection cannot update MongoDB, reason: : '+err.message, app_log);
                                            res.redirect('/host-groups?error=true&code=\'DM001\'');
                                        });
                                });
                        mdb.delDocument("groups", {"name": group})
                            .then(
                                function () {
                                    log("[+] Group "+group+" successfully deleted by: "+req.session.email, app_log);
                                    res.redirect('/user-groups?error=false');
                                },
                                function (err) {
                                    log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                    res.redirect('/user-groups?error=true&code=\'DM001\'');
                                }
                            );
                    },
                    function(err){
                        log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                        res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                    });
        });
    }
});

/* GET group-user-delete
 * Delete a user entry from a group (pull from stored array)
 */
router.get('/group-delete-user', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else if (req.session.role != "admin") {
        log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.status(403)
        res.render('error', {
            message: "403",
            error: {status: "Forbidden", detail: "You are not authorized to see this page"}
        });
    }
    else {
        var email = req.query.email;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    /* Consistency to users collection, keeps group field aligned */
                    mdb.findDocument("users", {"email": email})
                        .then(
                            function (doc) {
                                doc.group = doc.group.replace(req.query.group, '');
                                if(doc.group == "")
                                    doc.group="none";
                                mdb.updDocument("users", {"email": doc.email}, doc)
                                    .then(
                                        function () {
                                            log('[+] Groups propagating consistency to Users collection : ', app_log);
                                        },
                                        function (err) {
                                            log('[-] Failed propagating consistency to User collection, application will keep on working but this is not good : '+err.message, app_log);
                                        });
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                res.redirect('/host-groups?error=true&code=\'DM001\'');
                            });
                    mdb.updDocument("groups", {"name" : req.query.group },{ $pull :{ "members" : { "email" : email}}})
                        .then(
                            function () {
                                log("[+] User "+email+" successfully deleted from group "+req.query.group+" by: "+req.session.email, app_log);
                                res.redirect('/user-groups?error=false');
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                res.redirect('/user-groups?error=true&code=\'DM001\'');
                            }
                        )
                },
                function(err){
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                }
            )
    }
});
/***************************************
 *          GROUP MANAGEMENT - END     *
 ***************************************/

 /***************************************
  *          USER ROLES MANAGEMENT       *
  ***************************************/


 router.get('/user-roles', function (req, res, next) {
     if(req.session.email == undefined){
         log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
         res.render('login', {unauth: false});
     }
     else if (req.session.role != "admin") {
         log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
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
                     var users = mdb.findManyDocuments("users", {}, {name: 1, surname: 1, email: 1, group: 1, role: 1, sys_username:1 });
                     var userCount = mdb.countCollectionItems("users");
                     var groups = mdb.findManyDocuments("groups", {});
                     Promise.all([users, userCount, groups])
                         .then(
                             function (value) {
                                 res.render('user-roles', {
                                     users: value[0],
                                     user_count: value[1],
                                     username: req.session.email,
                                     role: req.session.role,
                                     groups: value[2],
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

 router.get('/update-role', function (req, res, next) {
     if(req.session.email == undefined){
         log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
         res.render('login', {unauth: false});
     }
     else if (req.session.role != "admin") {
         log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
         res.status(403)
         res.render('error', {
             message: "403",
             error: {status: "Forbidden", detail: "You are not authorized to see this page"}
         });
     }
     else {
         var role = req.query.new_role;
         var email = req.query.email;
                 mdb.connect(mongo_instance)
                     .then(
                         function () {
                             mdb.updDocument("users", {"email": email}, {$set: { role: role }})
                                 .then(
                                     function () {
                                         log("[+] User "+email+" role updated to "+role+" in specified timestamp by: "+req.session.email+" from "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                         log("[+] User "+email+" role updated by: "+req.session.email, app_log);
                                         res.redirect('/user-roles?error=false');
                                     },
                                     function (err) {
                                         log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                                         res.redirect('/user-roles?error=true&code=\'DM001\'');
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
 /***************************************
  *      USER ROLES MANAGEMENT - END    *
  ***************************************/
module.exports = router;
