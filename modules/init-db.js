var MongoClient = require('mongodb').MongoClient;
var url = "mongodb://localhost:27017/Hypnos";

MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    console.log("Database created!");
    dbo = db.db("SKDC");
    dbo.createCollection("users", function (err, res) {
        if (err) throw err;
        console.log("Users collection Created Succesfully!");
        db.close();
    });
    dbo.createCollection("groups", function (err, res) {
        if (err) throw err;
        console.log("Users collection Created Succesfully!");
        db.close();
    });
});

//INDEXES
//db.users.createIndex( { "email": 1 }, { unique: true } );
//db.hosts.createIndex( { "hostname": 1 }, { unique: true } );
//db.access.createIndex( { "hostname": 1, "email":1 }, { unique: true } );
//db.createCollection("groups");
//db.createCollection("clusters")
