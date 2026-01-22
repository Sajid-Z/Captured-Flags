# ADMIN DASHBOARD

## Description
Login and get the flag.
URL: http://50.116.19.213:3000/

## Vulnerability Analysis
The challenge presents a login form vulnerable to SQL injection.
We bypassed the quote filter by sending a backslash in the username field, which escaped the closing quote of the query.
This allowed us to inject SQL commands into the password field.

## Exploitation Payload
Username: \nPassword:  UNION SELECT *, 2 FROM flag -- 

## Flag
KCTF{0c259a70a089442a7e622d02bb5d911f}
