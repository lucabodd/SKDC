//Configurations
const config = require('./etc/config.json');

//FS to read ldap certs
var fs = require('fs');

var createError = require('http-errors');
var https = require('https')
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var port = config.skdc.port;

//logging
const log = require('log-to-file');
const app_log = config.skdc.log_dir+"app.log"

var indexRouter = require('./routes/index');
var authRouter = require('./routes/login');
var usersRouter = require('./routes/users');
var hostRouter = require('./routes/hosts');
var accessRouter = require('./routes/access');
var keyRouter = require('./routes/keys');
var apiRouter = require('./routes/api');
var session = require('express-session');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');


//app.use(logger(':date - :method   :url :response-time :user-agent'));
app.use(logger('dev'));
app.use(session({secret: 's3cr3tS3ss10nt3llnobod1!',resave: false, saveUninitialized:false}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//middleware authorization for routes
app.get('/api/*', function(req,res,next){
    if(!req.session.email){
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
        next();
    }
})


app.use('/', indexRouter);
app.use('/', usersRouter);
app.use('/', authRouter);
app.use('/', hostRouter);
app.use('/', accessRouter);
app.use('/', keyRouter);
app.use('/api/', apiRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

https.createServer({
  key: fs.readFileSync(config.skdc.SSL.KEY),
  cert: fs.readFileSync(config.skdc.SSL.CERT)
}, app)
.listen(port);
console.log("[+] Server is listening on port: "+ port);

module.exports = app;
