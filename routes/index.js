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

//logging
const log = require('log-to-file');
const app_log = config.skdc.log_dir+"app.log"

//Authenticator
var speakeasy = require("speakeasy");
var QRCode = require('qrcode');

/* GET home page. */
/*********************************************
*  Contain routes to provide just index page*
*  if noth authed automatic redirection     *
*  send user to login page                  *
*********************************************/

router.get('/', function(req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get index page from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else {
        mdb.connect(mongo_instance)
        .then(
            function() {
                var p1 = mdb.countCollectionItems("users");
                var p2 = mdb.countCollectionItems("groups");
                var p3 = mdb.countCollectionItems("hosts");
                var p4 = mdb.countCollectionItems("clusters");
                var p5 = mdb.findDocument("users", {email: req.session.email}, {otp_secret: 1});
                Promise.all([p1,p2,p3,p4,p5])
                .then(
                    function(value){
                        //if user has not otp_secret attribute generate the Secret
                        if(!('otp_secret' in value[4]))
                        {
                            var secret = speakeasy.generateSecret({length: 32});
                            QRCode.toDataURL(secret.otpauth_url.replace("SecretKey", req.session.email), function(err, image_data) {
                                res.render('index', {
                                    username: req.session.email,
                                    role: req.session.role,
                                    users_count : value[0],
                                    groups_count : value[1],
                                    hosts_count : value[2],
                                    clusters_count : value[3],
                                    otp_secret: secret.base32,
                                    otp_qr: image_data,
                                    error: req.query.error
                                });
                            });
                        }
                        //user has otp_secret attribute, authenticator setup not shown
                        else
                        {
                            res.render('index', {
                                username: req.session.email,
                                role: req.session.role,
                                users_count : value[0],
                                groups_count : value[1],
                                hosts_count : value[2],
                                clusters_count : value[3],
                                otp_secret: true,
                                code: req.query.code,
                                error: req.query.error
                            });
                        }
                    }, function(err){
                        log('[-] Connection to MongoDB has been established, but no query can be performed, reason: '+err.message, app_log);
                        res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                    }
                );
            },
            function (err) {
                log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
            }
        )
    }
});

/* GET error page
*  Using the same page for 404, 503 etc*/
router.get('/error', function (req, res, next) {
    res.render('error', req.query);
});
router.get('/docs', function (req, res, next) {
    if(req.session.email == undefined){
        log("[*] Non logged user is trying to get docs page, request occurred from: "+req.ip.replace(/f/g, "").replace(/:/g, "")+" User Agent: "+req.get('User-Agent'),app_log)
        res.render('login', {unauth: false});
    }
    else{
        res.render('docs');
    }
});

module.exports = router;
