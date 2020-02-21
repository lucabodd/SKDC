package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"github.com/sevlyar/go-daemon"
	ldap_client "github.com/lucabodd/go-ldap-client"
	"go.mongodb.org/mongo-driver/bson"
  	"go.mongodb.org/mongo-driver/mongo"
  	"go.mongodb.org/mongo-driver/mongo/options"
	ansibler "github.com/apenella/go-ansible"
	"io"
	"log"
	"os"
    "os/exec"
	"syscall"
	"time"
	"encoding/json"
	"encoding/base32"
	"encoding/base64"
	"context"
	"bytes"
	"net/smtp"
	"net/mail"
	"strconv"
	"strings"
	"fmt"
)

var (
	signal = flag.String("s", "", `Send signal to the daemon:
		quit - graceful shutdown
  		stop - fast shutdown
  		reload - reloading the configuration file`)
)
type Configuration struct {
	Skdc struct {
		Dir     string
		Log_dir string
		Run_dir string
		User	string
		Admin_mail string
	}
	Mongo struct {
		Url 	string
		Instance string
	}
	Ldap struct {
		Uri 	string
		Base_dn string
		Bind_dn string
		Bind_password string
		Read_only_dn string
		Read_only_password string
	}
}
type Mailtemplates struct {
	Standard string
	Noreset  string
	Nobutton string
}
type Host struct {
	Hostname string `bson:"hostname"`
	Ip string `bson:"ip"`
	Port string `bson:"port"`
	Proxy string `bson:"proxy"`
}
type Cluster struct {
	Name string `bson:"name"`
	Members []Host
}
type User struct {
	Sys_username string `bson:"sys_username"`
	Email string `bson:"email"`
	Role string `bson:"role"`
	Key_last_unlock string `bson:"key_last_unlock"`
	PubKey string `bson:"pubKey"`
	Password string `bson:"password"`
	Otp_secret string `bson:"otp_secret"`
	PwdChangedTime string `bson:"pwdChangedTime"`
	PwdAccountLockedTime *string `bson:"pwdAccountLockedTime"`
}

func main() {
	//parsing flags
	c := flag.String("c", "","Specify the configuration file.")
    flag.Parse()

	//Parsing system signaling
	daemon.AddCommand(daemon.StringFlag(signal, "quit"), syscall.SIGQUIT, termHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)
	daemon.AddCommand(daemon.StringFlag(signal, "reload"), syscall.SIGHUP, reloadHandler)

	file, err := os.Open(*c)
	if err != nil {
		log.Fatal("[-] Can't open config file: ", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	Config := Configuration{}
	err = decoder.Decode(&Config)
	if err != nil {
		log.Fatal("[-] Can't decode config JSON: ", err)
	}

    cntxt := &daemon.Context{
		PidFileName: Config.Skdc.Run_dir+"skdcd.pid",
		PidFilePerm: 0644,
		LogFileName: Config.Skdc.Log_dir+"daemon.log",
		LogFilePerm: 0640,
		WorkDir:     Config.Skdc.Dir+"daemons/",
		Umask:       027,
		Args:        []string{},
	}

    if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		check(err)
		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	check(err)
	if d != nil {
		return
	}
	defer cntxt.Release()

	log.Println("[+] Releasing OS pid")
	log.Println("+ - - - - - - - - - - - - - - - - - - -+")
	log.Println("|  SKDC host controller daemon started |")
    log.Println("+ - - - - - - - - - - - - - - - - - - -+")

	go worker(Config)

	err = daemon.ServeSignals()
	check(err)

    log.Println("+ - - - - - - - - - - - - - - - - - - - - +")
	log.Println("| SKDC host controller daemon terminated  |")
    log.Println("+ - - - - - - - - - - - - - - - - - - - - +")
}

var (
	stop = make(chan struct{})
	done = make(chan struct{})
)

func worker(Config Configuration) {
LOOP:
	for {
		//Object declarations, needed for tasks
		//MongoDB setup
		clientOptions := options.Client().ApplyURI(Config.Mongo.Url)
		mdb, err := mongo.Connect(context.TODO(), clientOptions)
		check(err)

		//LDAP setup
		host := strings.Split(Config.Ldap.Uri, "//")[1]
		ldap := &ldap_client.LDAPClient{
			Base:         Config.Ldap.Base_dn,
			Host:         host,
			Port:         636,
			UseSSL:       true,
	        InsecureSkipVerify: true,
			BindDN:       Config.Ldap.Bind_dn,
			BindPassword: Config.Ldap.Bind_password,
			UserFilter:   "(uid=%s)",
			GroupFilter: "(memberUid=%s)",
			Attributes:   []string{},
		}

		// Check the DB connection
		err = mdb.Ping(context.TODO(), nil)
		check(err)

		t1:=time.Now()
		t2:=time.Now()
		t3:=time.Now()
		t4:=time.Now()
		for int(t3.Sub(t4).Minutes()) <= 1440 {
			for int(t2.Sub(t1).Minutes()) <= 10 {
				// Quick tasks, below are executed instantly
				sshConfigGenerator(mdb, Config.Mongo.Instance, Config.Skdc.User)
				ansibleInventoryGenerator(mdb, Config.Mongo.Instance, Config.Skdc.Dir )
				skdcWardDeploy(mdb, Config.Mongo.Instance, Config.Skdc.User, Config.Skdc.Dir, Config.Ldap.Base_dn, host, Config.Ldap.Read_only_dn, Config.Ldap.Read_only_password)
				sshdConfigDeploy(mdb, Config.Mongo.Instance, Config.Skdc.User, Config.Skdc.Dir )
				t2=time.Now()
				// instantly quit when reciveing SIGTERM
				select {
					case <-stop:
						break LOOP
					default:
				}
			}
			//tasks below are executed every 10 minutes
			sshKeyExpire(mdb, Config.Mongo.Instance, ldap)
			//gen xlsx
		    cmd := exec.Command("/usr/local/bin/python3", "slowtasks/report.py")
		    err = cmd.Run()
			check(err)
		    log.Println("[+] .xlsx report generated successfully")
			t1=time.Now()
			t2=time.Now()
			t3=time.Now()
		}
		//tasks below are executed daily
		passwordExpire(mdb, Config.Mongo.Instance, Config.Skdc.Dir, Config.Skdc.Admin_mail, ldap)

		t4=time.Now()
	}
	done <- struct{}{}
}

//fast tasks
/************************************
	Task executed in loop
*************************************/
func sshConfigGenerator(mdb *mongo.Client, mongo_instance string, skdc_user string){
	log.Println("[*] Generating ssh config")
	//vars
	bt := 0
	f, err := os.Create("/home/"+skdc_user+"/.ssh/config")
	check(err)
	defer f.Close()

	//Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")

	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1,"proxy":1, "port":1, "ip":1})
	cur, err := hosts.Find(context.TODO(), bson.D{{}}, findOptProj)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   check(err)
	   bc, err := f.WriteString("Host "+host.Hostname+"\n")
	   bt += bc
	   check(err)
	   bc, err = f.WriteString("    User "+skdc_user+"\n")
	   bt += bc
	   check(err)
	   if(host.Proxy == "none") {
		   bc, err = f.WriteString("    HostName "+host.Ip+"\n")
		   bt += bc
		   check(err)
		   bc, err = f.WriteString("    Port "+host.Port+"\n")
		   bt += bc
		   check(err)
	   } else {
		   bc, err = f.WriteString("    HostName "+host.Hostname+"\n")
		   bt += bc
		   check(err)
		   bc, err = f.WriteString("    ProxyCommand ssh "+host.Proxy+" -W "+host.Ip+":"+host.Port+" \n")
		   bt += bc
		   check(err)
	   }
	   bc, err = f.WriteString("\n")
	   bt += bc
	   check(err)
	}
	f.Sync()
	log.Println("    |- bytes written:", bt)
	log.Println("[+] SSH config generated according to MongoDB")
}

func ansibleInventoryGenerator(mdb *mongo.Client, mongo_instance string, skdc_dir string){
	log.Println("[*] Generating ansible inventory")
	// vars
	findOptions := options.Find()
	f, err := os.Create(skdc_dir+"daemons/ansible/inventory")
	check(err)
	defer f.Close()
	bt := 0

	//Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")
	clusters := mdb.Database(mongo_instance).Collection("clusters")

	cur, err := clusters.Find(context.TODO(), bson.D{{}}, findOptions)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var cluster Cluster
	   err := cur.Decode(&cluster)
	   check(err)
	   bc, err := f.WriteString("["+cluster.Name+"]\n")
	   bt += bc
	   check(err)
	   for _,h := range cluster.Members {
		   bc, err := f.WriteString(h.Hostname+"\n")
		   check(err)
		   bt += bc
	   }
	   f.WriteString("\n")
	}
	err = cur.Err()
	check(err)

	// write ungrouped hosts
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1})
	cur, err = hosts.Find(context.TODO(), bson.M{"cluster": "none"}, findOptProj)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var host Host
		err := cur.Decode(&host)
 	   	check(err)
 	   	bc, err := f.WriteString(host.Hostname+"\n")
		check(err)
		bt += bc
 	}
	f.Sync()
	log.Println("    |- bytes written:", bt)
	log.Println("[+] Ansible inventory generated according to MongoDB")
}

func sshdConfigDeploy(mdb *mongo.Client, mongo_instance string, skdc_user string, skdc_dir string ){
	log.Println("[*] Undergoing Access deploy to managed hosts")
	log.Println(" |___")

	// vars
	findOptions := options.Find()
	var conn string
	error := ""

	// Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")
	access := mdb.Database(mongo_instance).Collection("access")
	users := mdb.Database(mongo_instance).Collection("users")

	// Get all Hosts
	var res_hosts []*Host
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1, "port": 1})
	cur, err := hosts.Find(context.TODO(), bson.D{{}}, findOptProj)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   check(err)
	   res_hosts = append(res_hosts, &host)
	}
	err = cur.Err()
	check(err)

	// Iterate trough all hosts and define ACL
	for _, h := range res_hosts {
		ACL := []*User{}
		cur, err = access.Find(context.TODO(), bson.M{"hostname":h.Hostname}, findOptions)
		check(err)
		defer cur.Close(context.TODO())
		for cur.Next(context.TODO()) {
		   var user User
		   err := cur.Decode(&user)
		   check(err)
		   ACL = append(ACL, &user)
		}
		err := cur.Err()
		check(err)

		//find admins (Has system wide access)
		findOptProj := options.Find().SetProjection(bson.M{"sys_username": 1})
		cur, err = users.Find(context.TODO(), bson.M{"role":"admin"}, findOptProj)
		defer cur.Close(context.TODO())
		for cur.Next(context.TODO()) {
		   var user User
		   err := cur.Decode(&user)
		   check(err)
		   ACL = append(ACL, &user)
		}
		err = cur.Err()
		check(err)

		// get all users in string
		ACL_string := skdc_user + " root"
		for _,a := range ACL {
			ACL_string = ACL_string + " " + a.Sys_username
		}
		b64_banner := base64.StdEncoding.EncodeToString([]byte(h.Hostname))
		ansiblePlaybookConnectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{}
		ansiblePlaybookOptions := &ansibler.AnsiblePlaybookOptions{
			Inventory: skdc_dir+"daemons/ansible/inventory",
			Limit: h.Hostname,
			ExtraVars: map[string]interface{}{
				"sshd_users": ACL_string,
				"port": h.Port,
				"banner": b64_banner,
			},
		}

		stdout := new(bytes.Buffer)
		playbook := &ansibler.AnsiblePlaybookCmd{
			Playbook:          skdc_dir+"daemons/ansible/playbooks/sshd-config-deploy.yml",
			ConnectionOptions: ansiblePlaybookConnectionOptions,
			Options:           ansiblePlaybookOptions,
			ExecPrefix:        "",
			Writer:				stdout,
		}

		err = playbook.Run()
		error = ""
		//read connection status
		if err != nil {
			if (strings.Contains(stdout.String(), "Missing sudo") || strings.Contains(stdout.String(), "password is required to run sudo")) {
				conn = "SUDOERR"
				error = stdout.String()
			} else if(strings.Contains(stdout.String(), "Failed to connect")){
				conn = "EARLY-FAIL"
				error = stdout.String()
			} else if(strings.Contains(stdout.String(), "CLI-UNDEPLOYED")){
				conn = "CLI-UNDEPLOYED"
				error = stdout.String()
			} else {
				conn = "UNKNOWN"
				error = stdout.String()
			}
			//logging
			if error != "" {
				log.Println("    |- "+h.Hostname+" Error establishing connection, detected error "+conn+" might be fixed in SKDC host-mgmt")
			}
		} else {
			conn = "TRUE"
		}
		error = strings.Replace(error, "=>", "", -1)
		error = strings.Replace(error, "\n", "", -1)
		error = strings.Replace(error, "  ", "", -1)
		error = base64.StdEncoding.EncodeToString([]byte(error))
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$set": bson.M{ "connection" : conn, "error": error }})
		check(err)
	}
	log.Println("    |[+] Access control deployed according to SKDC user defined rules")
}

func skdcWardDeploy(mdb *mongo.Client, mongo_instance string, skdc_user string, skdc_dir string, base_dn string, ldap_host string, bind_dn string, bind_password string) {
	log.Println("[*] Undergoing client deployment")
	log.Println(" |___")

	// Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")

	// Get all Hosts
	var res_hosts []*Host
	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1})
	cur, err := hosts.Find(context.TODO(), bson.M{ "deploy_req": bson.M{ "$exists": true }}, findOptProj)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   check(err)
	   res_hosts = append(res_hosts, &host)
	}
	err = cur.Err()
	check(err)


	for _, h := range res_hosts {
		ansiblePlaybookConnectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{}
		ansiblePlaybookOptions := &ansibler.AnsiblePlaybookOptions{
			Inventory: skdc_dir+"daemons/ansible/inventory",
			Limit: h.Hostname,
			ExtraVars: map[string]interface{}{
				"base": base_dn,
				"host": ldap_host,
				"bind_dn": bind_dn,
				"bind_password": bind_password,
			},
		}

		stdout := new(bytes.Buffer)
		playbook := &ansibler.AnsiblePlaybookCmd{
			Playbook:          skdc_dir+"daemons/ansible/playbooks/skdc-ward-deploy.yml",
			ConnectionOptions: ansiblePlaybookConnectionOptions,
			Options:           ansiblePlaybookOptions,
			ExecPrefix:        "",
			Writer:				stdout,
		}

		err = playbook.Run()
		check(err)
		log.Println("    |- client deployed to: "+h.Hostname)
		_, err = hosts.UpdateOne(context.TODO(), bson.M{"hostname":h.Hostname }, bson.M{ "$unset": bson.M{ "deploy_req" : 1}})
		check(err)
	}
	log.Println("[+] skdc-ward deployed according to SKDC requests")
}

//slow tasks
/************************************
	Task executed every 10 minutes
*************************************/
func sshKeyExpire(mdb *mongo.Client, mongo_instance string, ldap *ldap_client.LDAPClient){
	log.Println("[*] Undergoing key expiration procedure")
	log.Println(" |___")

	// vars
	users := mdb.Database(mongo_instance).Collection("users")
	expirationDelta := 9

	findOptProj := options.Find().SetProjection(bson.M{"sys_username":1, "email":1, "pubKey": 1, "otp_secret":1, "key_last_unlock":1})
	cur, err := users.Find(context.TODO(), bson.M{ "pubKey": bson.M{ "$exists": true, "$nin": bson.A{nil, ""} }}, findOptProj)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var user User
		err := cur.Decode(&user)
		check(err)
		diff := timeHoursDiff(user.Key_last_unlock)
		if (diff >= expirationDelta) {
			//cipher string only if it is unciphered
			if(strings.Contains(user.PubKey, "ssh-rsa")) {
				//return a byte string
				b32_decoded_otp_secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(user.Otp_secret)
				check(err)
				key := b32_decoded_otp_secret
				encKey := AESencrypt(string(key), user.PubKey)
				_, err = users.UpdateOne(context.TODO(), bson.M{"email":user.Email }, bson.M{ "$set": bson.M{ "pubKey" : encKey}})
				check(err)
				_, err = ldap.SetUserAttribute(user.Sys_username, "sshPublicKey", encKey)
				check(err)
				log.Println("    |- SSH public key for user "+user.Sys_username+" Locked due to expiration")
			}
		}
	}
	log.Println("[+] Expired keys locked successfully")
}

//slow tasks
/************************************
	Task executed daily
*************************************/
func passwordExpire(mdb *mongo.Client, mongo_instance string, skdc_dir string, admin_mail string, ldap *ldap_client.LDAPClient){
	log.Println("[*] Undergoing key expiration procedure")
	log.Println(" |___")
	// vars
	users := mdb.Database(mongo_instance).Collection("users")
	warningDelta:=75
	expirationDelta:=90
	//OPening mail templates
	file, err := os.Open(skdc_dir+"etc/mailtemplates.json")
	check(err)
	defer file.Close()
	decoder := json.NewDecoder(file)
	Templates := Mailtemplates{}
	err = decoder.Decode(&Templates)
	check(err)

	findOptProj := options.Find().SetProjection(bson.M{"email":1, "sys_username": 1, "pwdChangedTime":1, "pwdAccountLockedTime":1})
	cur, err := users.Find(context.TODO(), bson.M{"sys_username": "luca.bodini"}, findOptProj)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var user User
		err := cur.Decode(&user)
		check(err)
		diff := timeHoursDiff(user.PwdChangedTime)
		if (diff >= warningDelta && diff < expirationDelta) {
			//Mail parameters
			subject := "SKDC - User "+user.Sys_username+" password is expiring soon"
			txt := "Your password is "+strconv.Itoa(diff)+" old and will expire in "+strconv.Itoa(expirationDelta-diff)+" days. please, log in clicking on the button below and change it as soon as possible"
			body := strings.Replace(Templates.Standard,"%s",txt,-1)
			err = SendMail("127.0.0.1:25", (&mail.Address{"SKDC", admin_mail}).String(), subject, body, []string{(&mail.Address{user.Sys_username, user.Email}).String()})
			check(err)
			log.Println("    |- Password expiration notifyed to user "+user.Sys_username)
		} else if (diff >= expirationDelta && user.PwdAccountLockedTime==nil) {
			format := "20060102150405Z"
			now := time.Now().Format(format)
			_, err = ldap.AddUserAttribute(user.Sys_username, "pwdAccountLockedTime", now)
			check(err)
			_, err = users.UpdateOne(context.TODO(), bson.M{"email":user.Email }, bson.M{ "$set": bson.M{ "pwdAccountLockedTime" : now, "key_last_unlock": "19700101000010Z" }, "$unset": bson.M{"otp_secret":1, "pubKey":1}})
			check(err)
			_, err = ldap.SetUserAttribute(user.Sys_username, "sshPublicKey", "")
			check(err)
			subject := "SKDC - User "+user.Sys_username+" password is expired"
			txt := "Your password is "+strconv.Itoa(diff)+" days old and is expired. Your account has been locked for security reason, please ask Administrators to unlock your account."
			body := strings.Replace(Templates.Nobutton,"%s",txt,-1)
			err = SendMail("127.0.0.1:25", (&mail.Address{"SKDC", admin_mail}).String(), subject, body, []string{(&mail.Address{user.Sys_username, user.Email}).String()})
			check(err)
			log.Println("    |- Account for user "+user.Sys_username+" Locked due to password expiration")
		}
	}
	log.Println("[+] Password expiration carried according to policy")
}

//System signaling handling
func termHandler(sig os.Signal) error {
	log.Println("[*] System SIGQUIT recived, Terminating daemon sshd config on remote hosts won't be updated anymore...")
	log.Println("+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+")
	log.Println("|       SIGQUIT: gracefully terminating pending processes          |")
    log.Println("+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+")
	stop <- struct{}{}
	if sig == syscall.SIGQUIT {
		<-done
	}
	return daemon.ErrStop
}

func reloadHandler(sig os.Signal) error {
	log.Println("[*] System SIGHUP recived reloading configuration ...")
	return nil
}

//utilityes
/***************************************
	AES encryption
****************************************/
func AESencrypt(keyStr string, cryptoText string) string {
	keyBytes := sha256.Sum256([]byte(keyStr))
	return encrypt(keyBytes[:], cryptoText)
}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	check(err)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	check(err)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func AESdecrypt(keyStr string, cryptoText string) string {
	keyBytes := sha256.Sum256([]byte(keyStr))
	return decrypt(keyBytes[:], cryptoText)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	check(err)

	block, err := aes.NewCipher(key)
	check(err)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	return fmt.Sprintf("%s", ciphertext)
}
/***************************************
	AES end
****************************************/

func timeHoursDiff(date string) (int) {
    timeFormat := "20060102150405Z"
	then, err := time.Parse(timeFormat, date)
    check(err)
    duration := time.Since(then)
    return int(duration.Hours())
}

func timeDaysDiff(date string) (int) {
    timeFormat := "20060102150405Z"
	then, err := time.Parse(timeFormat, date)
    check(err)
    duration := time.Since(then)
    return int(duration.Hours()/24)
}

func SendMail(addr, from, subject, body string, to []string) error {
	r := strings.NewReplacer("\r\n", "", "\r", "", "\n", "", "%0a", "", "%0d", "")

	c, err := smtp.Dial(addr)
	check(err)
	defer c.Close()
	err = c.Mail(r.Replace(from))
	check(err)
	for i := range to {
		to[i] = r.Replace(to[i])
		err = c.Rcpt(to[i])
		check(err)
	}

	w, err := c.Data()
	check(err)

	msg := "To: " + strings.Join(to, ",") + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + base64.StdEncoding.EncodeToString([]byte(body))

	_, err = w.Write([]byte(msg))
	check(err)
	err = w.Close()
	check(err)
	return c.Quit()
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
}
