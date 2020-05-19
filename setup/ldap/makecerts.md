#Setup SSL certs for LDAP server
the following instructions will guide you trough setting up a ldap cluster in mirror mode over ssl

##Steps
###Create cert dir
``` mkdir -p /etc/ssl/openldap/{private,certs,newcerts} ```

###edit opessl.conf
``` vim /usr/lib/ssl/openssl.cnf ```
and add dir line like
```
...
[ CA_default ]

#dir            = ./demoCA              # Where everything is kept
dir             = /etc/ssl/openldap
certs           = $dir/certs            # Where the issued certs are kept
crl_dir         = $dir/crl              # Where the issued crl are kept
database        = $dir/index.txt        # database index file.
...
```
###You also need some files for tracking the signed certificates.
