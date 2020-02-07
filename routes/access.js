//Configurations
const config = require('../etc/config.json');

//Web server
var express = require('express');
var app = express();
var session = require('express-session');
var router = express.Router();
//app.use(session({secret: 's3cr3t', saveUninitialized : true, resave : false }));

//MongoDB
var DB = require("../modules/db");
var mdb = new DB(config.mongo.url);
var mongo_instance = config.mongo.instance

//logging
const log = require('log-to-file');
const app_log = config.skdc.log_dir+"app.log"
const journal_log = config.skdc.log_dir+"journal.log"


/* GET Access page. */
/*********************************************
 *  Contain routes to provide sccess to users*
 *  if noth authed automatic redirection     *
 *  send user to login page                  *
 *********************************************/

/***************************************
 *        ACCESS MANAGEMENT            *
 ***************************************/
router.get('/access-mgmt', function(req, res, next) {
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
                    var hosts = mdb.findManyDocuments("hosts", {});
                    var clusters = mdb.findManyDocuments("clusters", {});
                    var users = mdb.findManyDocuments("users", {},{
                            name: 1,
                            surname: 1,
                            email: 1,
                            sys_username: 1,
                            role: 1,
                            group: 1,
                            pubKey: 1
                    });
                    var groups = mdb.findManyDocuments("groups", {});
                    var access = mdb.findManyDocuments("access", {});
                    Promise.all([hosts, clusters, users, groups,access])
                        .then(
                            function (value) {
                                res.render('access-mgmt', {
                                    hosts: value[0],
                                    clusters: value[1],
                                    users: value[2],
                                    groups: value[3],
                                    access: value[4],
                                    error: err,
                                    code: req.query.code,
                                    username: req.session.email,
                                    role: req.session.role
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

/****************************************
 *        Insert access Rules in DB     *
 ****************************************/
router.post('/access-user2host', function (req ,res,next){
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
        var users = req.body.user
        var hosts = req.body.host

        if(!(users instanceof Array)){
            users = users.split();
        }
        if(!(hosts instanceof Array)){
            hosts = hosts.split();
        }

        hosts.forEach(function(h){
            users.forEach(function(u){
                var udata = JSON.parse(u);
                var hdata = JSON.parse(h);
                var doc={
                  name: udata.name,
                  surname: udata.surname,
                  sys_username: udata.sys_username,
                  email: udata.email,
                  hostname: hdata.hostname
                };
                mdb.connect(mongo_instance)
                   .then(
                       function() {
                           mdb.addDocument("access", doc)
                               .then(
                                   function () {
                                       log("[+] Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email, app_log);
                                       log("[+] Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email+" From: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                       res.redirect('/access-mgmt?error=false');
                                   },
                                   function (err) {
                                       log('[!] Connection to MongoDB has been established, but error occurred, reason: '+err.message, app_log);
                                       res.redirect('/access-mgmt?error=true&code=\'DM001\'');
                                   }
                               )
                       },
                       function(err)
                       {
                           log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                           res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                       }
                   );
            });
        });
    }
});

router.post('/access-group2host', function (req ,res,next) {
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
        var users = req.body.users
        var hosts = req.body.host

        if(!(users instanceof Array)){
            users = users.split();
        }
        if(!(hosts instanceof Array)){
            hosts = hosts.split();
        }
        hosts.forEach(function(hst){
            users.forEach(function(usr){
                var udata = JSON.parse(usr);
                var hdata = JSON.parse(hst);
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            udata.forEach(function (u) {
                                var doc = {
                                    name: u.name,
                                    surname: u.surname,
                                    sys_username: u.sys_username,
                                    email: u.email,
                                    hostname: hdata.hostname
                                };
                                mdb.addDocument("access", doc)
                                    .then(
                                        function () {
                                            log("[+] Bulk Action - Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email, app_log);
                                            log("[+] Bulk Action - Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email+" From: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                        },
                                        function (err) {
                                            log('[!] Connection to MongoDB has been established, but error occurred, reason: '+err.message, app_log);
                                        }
                                    );
                            });
                            res.redirect('/access-mgmt?error=false');
                        },
                        function (err) {
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });
                });
            });
    }
});

router.post('/access-user2cluster', function (req ,res,next) {
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
    else{
        var users = req.body.user
        var cluster = req.body.cluster

        if(!(users instanceof Array)){
            users = users.split();
        }
        if(!(cluster instanceof Array)){
            cluster = cluster.split();
        }

        cluster.forEach(function(cls){
            users.forEach(function(usr){
                var udata = JSON.parse(usr);
                var hdata = JSON.parse(cls);
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            hdata.forEach(function (h) {
                                var doc = {
                                    name: udata.name,
                                    surname: udata.surname,
                                    sys_username: udata.sys_username,
                                    email: udata.email,
                                    hostname: h.hostname
                                };
                                mdb.addDocument("access", doc)
                                    .then(
                                        function () {
                                            log("[+] Bulk Action - Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email, app_log);
                                            log("[+] Bulk Action - Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email+" From: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                        },
                                        function (err) {
                                            log('[!] Connection to MongoDB has been established, but error occurred, reason: '+err.message, app_log);
                                        }
                                    );
                            });
                            res.redirect('/access-mgmt?error=false');
                        },
                        function (err) {
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });
                });
        });
    }
});

router.post('/access-group2cluster', function (req ,res,next) {
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
    else{
        var users = req.body.group
        var cluster = req.body.cluster

        if(!(users instanceof Array)){
            users = users.split();
        }
        if(!(cluster instanceof Array)){
            cluster = cluster.split();
        }
        cluster.forEach(function(cls){
            users.forEach(function(usr){
                var udata = JSON.parse(usr);
                var hdata = JSON.parse(cls);
                mdb.connect(mongo_instance)
                    .then(
                        function () {
                            udata.forEach(function (u) {

                                var user = u;
                                hdata.forEach(function (h) {
                                    var doc = {
                                        name: user.name,
                                        surname: user.surname,
                                        sys_username: user.sys_username,
                                        email: user.email,
                                        hostname: h.hostname
                                    };
                                    mdb.addDocument("access", doc)
                                          .then(
                                              function () {
                                                  log("[+] Bulk Action - Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email, app_log);
                                                  log("[+] Bulk Action - Access Granted for user: "+doc.sys_username+"@"+doc.hostname+" by user: "+req.session.email+" From: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                              },
                                              function (err) {
                                                  log('[!] Connection to MongoDB has been established, but error occurred, reason: '+err.message, app_log);
                                              }
                                          );
                                });
                            });
                            res.redirect('/access-mgmt?error=false');
                        },
                        function (err) {
                            log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                            res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                        });
            });
        });
    }
});

router.get('/access-delete', function (req, res, next) {
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
        var hostname = req.query.hostname;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var p1 = mdb.delDocument("access", {"email": email, "hostname": hostname});
                    var p2 = mdb.addDocument("ansible_queue_delete", {"sys_username": req.query.sys_username, "hostname": req.query.hostname})
                    Promise.all([p1,p2])
                        .then(
                            //TODO 5 add ansible event queue
                            function () {
                                log("[+] Access for user: "+email+" at "+hostname+" removed by user: "+req.session.email, app_log);
                                log("[+] Access for user: "+email+" at "+hostname+" removed by user: "+req.session.email+" From: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'), journal_log);
                                res.redirect('/access-mgmt?error=false');
                            },
                            function (err) {
                                log('[!] Connection to MongoDB has been established, but error occurred, reason: '+err.message, app_log);
                                res.redirect('/access-mgmt?error=true&code=\'DM001\'');
                            }
                        )
                }
            )
    }
});

/****************************************
 *        report and hournal download   *
 ****************************************/
 router.get('/download-report', function (req, res, next) {
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
         res.download(config.skdc.dir+"report/access-mtrx.xlsx");
     }
 });

 router.get('/download-journal', function (req, res, next) {
     if(req.session.email == undefined){
         log("[*] Non logged user is trying to get host-mgmt page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
         res.render('login', {unauth: false});
     }
     else if (req.session.role != "admin") {
         log("[*] Non admin user is trying to access host-mgmt page from: "+req.ip+" User Agent: "+req.get('User-Agent'),app_log)
         res.status(403)
         res.render('error', {
             message: "403",
             error: {status: "Forbidden", detail: "You are not authorized to see this page"}
         });
     }
     else {
         res.download(config.skdc.log_dir+"journal.log");
     }
 });

module.exports = router;
