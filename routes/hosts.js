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

//process spawning
const exec = require('child_process').exec

/* GET hosts page. */
/*********************************************
 *  Contain routes to provide host-mgmt pages*
 *  if noth authed automatic redirection     *
 *  send user to login page                  *
 *********************************************/

/***************************************
 *          HOST MANAGEMENT            *
 ***************************************/

/* GET user add
*  return user add page*/
router.get('/host-mgmt', function (req, res, next) {
        var err = ''
        err += req.query.error;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var hosts = mdb.findManyDocuments("hosts", {});
                    var hostCount = mdb.countCollectionItems("hosts");
                    var clusters = mdb.findManyDocuments("clusters", {});
                    Promise.all([hosts, hostCount, clusters])
                        .then(
                            function (value) {
                                value[0].forEach(function(host){
                                    if("error" in host)
                                    {
                                        if(host.error != "")
                                        {
                                            console.log(host.hostname);
                                            b64_decoded_err = Buffer.from(host.error, 'base64').toString();
                                            console.log(b64_decoded_err);
                                            json_err = JSON.parse(b64_decoded_err);
                                            //successful connection
                                            if(json_err.plays[0].tasks[0].hosts[host.hostname].unreachable==undefined)
                                                json_err.plays[0].tasks[0].hosts[host.hostname].unreachable=false
                                            host.error = "Message: "+json_err.plays[0].tasks[0].hosts[host.hostname].msg+"<br>Unreachable: "+json_err.plays[0].tasks[0].hosts[host.hostname].unreachable+"<br>Start Time: "+json_err.plays[0].tasks[0].task.duration.start+"<br>End Time:"+json_err.plays[0].tasks[0].task.duration.end;
                                        }
                                    }
                                });
                                res.render('host-mgmt', {
                                    hosts: value[0],
                                    host_count: value[1],
                                    username: req.session.email,
                                    role: req.session.role,
                                    clusters: value[2],
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

router.post('/host-add', function (req, res, next) {
        var document = {
            hostname: req.body.hostname,
            ip: req.body.ip,
            port: req.body.port,
            cluster: req.body.cluster,
            proxy: req.body.proxy,
            connection: "EARLY-FAIL",
            error: ""
        };

        mdb.connect(mongo_instance)
            .then(
                function () {
                    var addU = mdb.addDocument("hosts", document);
                    var addG = mdb.updDocument("clusters", {name: req.body.cluster}, {$push: {members: document}});
                    Promise.all([addU, addG])
                        .then(
                            function () {
                                log('[+] Host '+document.hostname+' Successfully added from user : '+req.session.email, app_log);
                                res.redirect('/host-mgmt?error=false');
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but no query cannot be satisfied, reason: '+err.message, app_log);
                                res.redirect('/host-mgmt?error=true&code=\'DM001\'');
                            })
                },
                function (err) {
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                });
});
/* Exec ansible playbook in order to deploy skdc client to selected host */
router.get('/host-cli-deploy', function (req, res, next) {
        var host = req.query.hostname;
        mdb.connect(mongo_instance)
        .then(
            function(){
                mdb.updDocument("hosts", {hostname: host}, {$set: {deploy_req: "SYN"}})
                .then(
                    function(){
                        log('[+] User '+req.session.email+' requested client deploy for host'+host, app_log);
                        res.redirect('/host-mgmt?error=false');
                    },
                    function(err){
                        log('[-] Connection to MongoDB has been established, but no query cannot be satisfied, reason: '+err.message, app_log);
                        res.redirect('/host-mgmt?error=true&code=\'DM001\'');
                    }
                )
            },
            function(err){
                log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
            }
        )
});
/* GET host-delete
 * add new user in DB
 * This method generate ssh key-pair and update user entry
 */
router.get('/host-delete', function (req, res, next) {
        var host = req.query.hostname;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var p1 = mdb.delDocument("hosts", {"hostname": host});
                    var p2 = mdb.updManyDocuments("clusters", {},  {$pull : { "members" : {"hostname" : host}}});
                    var p3 = mdb.delDocument("access", {"hostname" : host});
                    Promise.all([p1, p2, p3])
                        .then(
                            function () {
                                log('[+] Host '+host+' Successfully deleted from user : '+req.session.email, app_log);
                                res.redirect('/host-mgmt?error=false');
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but no query cannot be satisfied, reason: '+err.message, app_log);
                                res.redirect('/host-mgmt?error=true&code=\'DM001\'');
                            }
                        )
                }
            )
});
/***************************************
 *      HOST MANAGEMENT - END          *
 ***************************************/


/***************************************
 *    HOST GROUPS MANAGEMENT           *
 ***************************************/

/* GET user add
 * return user add page*/
router.get('/host-groups', function (req, res, next) {
        var err = ''
        err += req.query.error;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    var hosts = mdb.findManyDocuments("hosts", {});
                    var clusterCount = mdb.countCollectionItems("clusters");
                    var clusters = mdb.findManyDocuments("clusters", {});
                    Promise.all([hosts, clusterCount, clusters])
                        .then(
                            function (value) {
                                res.render('host-groups', {
                                    hosts: value[0],
                                    cluster_count: value[1],
                                    username: req.session.email,
                                    role: req.session.role,
                                    clusters: value[2],
                                    error: err,
                                    code: req.query.code
                                });
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but not all queryes can be satisfied, reason: '+err.message, app_log);
                                res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                            }
                        );
                },
                function(err){
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                });
});

/* POST add new group
*  when group is created, there are no members inside */
router.post('/cluster-add', function (req, res, next) {
        var cluster = req.body.cluster_name;
        cluster = cluster.replace(/ /g, "");
        document = {
            name: cluster,
            members: []
        };
        mdb.connect(mongo_instance)
            .then(
                function () {
                    mdb.addDocument("clusters", document)
                        .then(
                            function () {
                                log('[+] Cluster '+document.name+' Successfully added from user : '+req.session.email, app_log);
                                res.redirect('/host-groups?error=false');
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but query can be satisfied, reason: '+err.message, app_log);
                                res.redirect('/host-groups?error=true&code=\'DM001\'');
                            }
                        )
                },
                function (err) {
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                }
            );
});

/* POST ADD USER TO A GROUP
 * add a new object to members array of a group
 */
router.post('/cluster-add-host', function (req, res, next) {
        var cluster = req.body.cluster
        var req_hosts = req.body.host;
        if(!(req_hosts instanceof Array)){
            req_hosts = req_hosts.split();
        }

        req_hosts.forEach(function(h){
            mdb.connect(mongo_instance)
                .then(
                    function () {
                        var host = JSON.parse(h);
                        mdb.findDocument("clusters",{"name": cluster ,"members.hostname": host.hostname})
                            .then(
                                function (value) {
                                    if (!value) {
                                        var addH = mdb.updDocument("clusters", {name: cluster}, {$push: {members: host}});
                                        var strclus = host.cluster+" "+cluster;
                                        strclus = strclus.replace("none ", "");
                                        var updH = mdb.updDocument("hosts", {"hostname" : host.hostname}, { $set: { "cluster": strclus}});
                                        Promise.all([addH, updH])
                                            .then(
                                                function () {
                                                    log('[+] Host '+host.hostname+' Successfully added to cluster '+cluster+' from user : '+req.session.email, app_log);
                                                    res.redirect('/host-groups?error=false');
                                                },
                                                function (err) {
                                                    log('[-] Connection to MongoDB has been established, but query can be satisfied, reason: '+err.message, app_log);
                                                    res.redirect('/host-groups?error=true&code=\'DM001\'');
                                                });
                                    }
                                    else {
                                        log('[!] Host '+host.hostname+' alread added to cluster '+cluster+'skipping ...', app_log);
                                        res.redirect('/host-groups?error=true&code=\'SH010\'');
                                    }
                                },
                                function (err) {
                                    log('[-] Connection to MongoDB has been established, but query can be satisfied, reason: '+err.message, app_log);
                                    res.redirect('/host-groups?error=true&code=\'DM001\'');
                                });
                    },
                    function (err) {
                        log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                        res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                    });
        });
});


/* POST group-delete
 * delete an entire group
 */
router.post('/cluster-delete', function (req, res, next) {
        var clstrs = req.body.cluster;
        if(!(clstrs instanceof Array)){
            clstrs = clstrs.split();
        }
        clstrs.forEach(function(cluster){
            mdb.connect(mongo_instance)
                .then(
                    function () {
                        /* Consistency to hosts collection, keeps cluster field aligned */
                        mdb.findManyDocuments("hosts", { "cluster" : { $regex : cluster}})
                            .then(
                                function(values) {
                                    values.forEach(function(doc) {
                                        doc.cluster = doc.cluster.replace(cluster, '');
                                        if(doc.cluster == "")
                                            doc.cluster="none"
                                        mdb.updDocument("hosts", {"hostname": doc.hostname}, doc)
                                            .then(
                                                function () {
                                                    log('[+] Cluster propagating consistency to Host collection : ', app_log);
                                                },
                                                function (err) {
                                                    log('[-] Failed propagating consistency to Host collection, application will keep on working but this is not good : '+err.message, app_log);
                                                }
                                            );
                                    },
                                    function (err) {
                                        log('[-] Connection to MongoDB has been established, but query cannot be satisfied, reason: '+err.message, app_log);
                                        res.redirect('/host-groups?error=true&code=\'DM001\'');
                                    });
                        });
                        mdb.delDocument("clusters", {"name": cluster})
                            .then(
                                function () {
                                    log('[+] Cluster '+cluster+' Successfully deleted from user : '+req.session.email, app_log);
                                    res.redirect('/host-groups?error=false');
                                },
                                function (err) {
                                    log('[-] Connection to MongoDB has been established, but query can be satisfied, cluster not deleted, reason: '+err.message, app_log);
                                    res.redirect('/host-groups?error=true&code=\'DM001\'');
                                }
                            )
                    },
                    function (err) {
                        log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                        res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                    }
                );
            });
});

/* GET group-user-delete
 * Delete a user entry from a group (pull from stored array)
 */
router.get('/cluster-delete-host', function (req, res, next) {
        var hostname = req.query.hostname;
        mdb.connect(mongo_instance)
            .then(
                function () {
                    /* Consistency to hosts collection, keeps cluster field aligned */
                    mdb.findDocument("hosts", {"hostname": hostname})
                        .then(
                            function (doc) {
                                doc.cluster = doc.cluster.replace(req.query.cluster, '');
                                if(doc.cluster == "")
                                    doc.cluster="none";
                                mdb.updDocument("hosts", {"hostname": doc.hostname}, doc)
                                    .then(
                                        function () {
                                            log('[+] Cluster propagating consistency to Host collection : ', app_log);
                                        },
                                        function (err) {
                                            log('[-] Failed propagating consistency to Host collection, application will keep on working but this is not good : '+err.message, app_log);
                                        });
                            },
                            function (err) {
                                log('[-] Connection to MongoDB has been established, but query can be satisfied, reason: '+err.message, app_log);
                                res.redirect('/host-groups?error=true&code=\'DM001\'');
                            });
                },
                function(err){
                    log('[-] Connection to MongoDB cannot be established, reason: '+err.message, app_log);
                    res.render('error',{message: "500",  error : { status: "Service unavailable", detail : "The service you requested is temporary unvailable" }});
                });
        mdb.updDocument("clusters", {"name": req.query.cluster}, {$pull: {"members": {"hostname": hostname}}})
            .then(
                function () {
                    log("[+] Host " + hostname + " deleted successfully from cluser from user"+req.session.email, app_log);
                    res.redirect('/host-groups?error=false');
                },
                function (err) {
                    log('[-] Connection to MongoDB has been established, but query can be satisfied, reason: '+err.message, app_log);
                    res.redirect('/host-groups?error=true&code=\'DM001\'');
                }
            );
});

/***************************************
 *          GROUP MANAGEMENT - END     *
 ***************************************/
module.exports = router;
