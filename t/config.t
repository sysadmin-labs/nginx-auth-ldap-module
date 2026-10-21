use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: a server block with a url and a bind is read
--- http_config
    ldap_server good {
        url ldap://127.0.0.1:389/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        require valid_user;
    }
--- config
    location = /t {
        return 200 ok;
    }
--- request
GET /t
--- response_body chomp
ok



=== TEST 2: a url that is not ldap is refused
--- http_config
    ldap_server bad {
        url ftp://127.0.0.1:21/ou=people?uid?sub?(objectClass=*);
        require valid_user;
    }
--- config
    location = /t {
        return 200 ok;
    }
--- must_die
--- error_log
URL doesnt begin with



=== TEST 3: a server block without a name is refused
--- http_config
    ldap_server {
        url ldap://127.0.0.1:389/ou=people?uid?sub?(objectClass=*);
    }
--- config
    location = /t {
        return 200 ok;
    }
--- must_die
--- error_log
invalid number of arguments in "ldap_server" directive



=== TEST 4: auth_ldap_servers naming a server that does not exist
--- http_config
    ldap_server good {
        url ldap://127.0.0.1:389/ou=people?uid?sub?(objectClass=*);
        require valid_user;
    }
--- config
    location = /t {
        auth_ldap "Restricted";
        auth_ldap_servers nowhere;
        return 200 ok;
    }
--- must_die
--- error_log
has not been defined



=== TEST 5: a connection count of zero is refused
--- http_config
    ldap_server good {
        url ldap://127.0.0.1:389/ou=people?uid?sub?(objectClass=*);
        require valid_user;
        connections 0;
    }
--- config
    location = /t {
        return 200 ok;
    }
--- must_die
--- error_log
'connections' value has to be a number greater than 0



=== TEST 6: a satisfy that is neither all nor any
--- http_config
    ldap_server good {
        url ldap://127.0.0.1:389/ou=people?uid?sub?(objectClass=*);
        require valid_user;
        satisfy maybe;
    }
--- config
    location = /t {
        return 200 ok;
    }
--- must_die
--- error_log
Incorrect value for auth_ldap_satisfy



=== TEST 7: a url without a user attribute is refused
--- http_config
    ldap_server good {
        url ldap://127.0.0.1:389/ou=people,dc=test,dc=local???(objectClass=*);
        require valid_user;
    }
--- config
    location = /t {
        return 200 ok;
    }
--- must_die
--- error_log
No user attribute specified
