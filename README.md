# Overview

Cross-site request forgery(CSRF) vulnerability in Teedy versions <= v1.11 allows remote attackers to force an end user to change their user information(username, password, etc...) on the web application in which they're currently authenticated.

# Vulnerability

User information change endpoint is ```/api/user/:username```.<br />This endpoint only checks auth_token in cookies for authorization.<br />The auth_token value can be used from other origin websites.<br />
```
POST /api/user/admin HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded;charset=utf-8
Content-Length: 173
Origin: http://localhost:8080
Connection: keep-alive
Referer: http://localhost:8080/
Cookie: auth_token=890b02eb-3e4b-4134-a523-56093a25952b
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0

username=admin&groups=administrators&email=admin%40example.com&totp_enabled=false&storage_quota=0&storage_current=0&disabled=false&password=superSecure&passwordconfirm=superSecure
```
Therefore, making an end user to visit the website that sends requests to /api/user/:username leads to change end user's information to remote attacker's one.<br />User information includes password.<br />This could lead to account takeover.<br />This attack is achievable when a remote attacker knows username of an end user.<br />This attack is exploitable against both admin and guest users.<br />In this situation, an attacker can take over victim's user by setting victim user's password to attacker's password and logging in to victim's user with attacker's password.

# Fix

To fix this vulnerability, attach CSRF token when requesting to ```/api/user/:username```
```
POST /api/user/admin HTTP/1.1

...

username=admin&groups=administrators&email=admin%40example.com&totp_enabled=false&storage_quota=0&storage_current=0&disabled=false&password=superSecure&passwordconfirm=superSecure&csrf_token=<randomly generated token>
```
This protects against CSRF attack because an attacker doesn't know CSRF token value.<br />To use CSRF token securely, follow these steps<br />
1. Embed randomly generated CSRF token in request form.
2. Use CORS HTTP Header to protect CSRF token from being leaked by other origin websites.
</br>

First, create these files in ```docs/docs-web/src/main/java/com/sismics/docs/rest/util``` directory.<br />
- CSRFToken.java
- RandomTokenGenerator.java
CSRFToken.java
```java
package com.sismics.docs.rest.util;

import java.util.Map;
import java.util.HashMap;
import java.security.SecureRandom;
import com.sismics.docs.rest.util.RandomTokenGenerator;

/**
 * CSRF Token Class that manages users' CSRF Token
 */
public class CSRFToken {

    private static CSRFToken instance = new CSRFToken();
    private Map<String, String> tokenMap = new HashMap<String, String>();

    private CSRFToken() {}

    public static CSRFToken getInstance() {
        return instance;
    }

    public void setToken(String userName, String token) {
        tokenMap.put(userName, token);
    }

    public String getToken(String userName) {
        if (tokenMap.containsKey(userName)) {
            return tokenMap.get(userName);
        }
        // avoid using predictable string because bruteforcing this value could lead to bypass CSRF check
        return RandomTokenGenerator.generate();
    }

    public boolean validate(String userName, String token) {
        return this.getToken(userName).equals(token);
    }
}
```
RandomTokenGenerator.java
```java
package com.sismics.docs.rest.util;

import java.security.SecureRandom;
import java.lang.StringBuilder;
import java.lang.String;

/**
 * A token generator for CSRF Token
 */
public class RandomTokenGenerator {

    public static String generate() {
        byte[] bytes = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
```
After that, change these files to the following.
- docs/docs-web/src/main/webapp/src/app/docs/controller/settings/SettingsUserEdit.js
- docs/docs-web/src/main/java/com/sismics/docs/rest/resource/UserResource.java
![UserResourceDiff1](https://github.com/sota70/teedy-v1.11-csrf/blob/main/UserResource_1.png?raw=true)
![UserResourceDiff2](https://github.com/sota70/teedy-v1.11-csrf/blob/main/UserResource_2.png?raw=true)
![SettingsUserEditDiff1](https://github.com/sota70/teedy-v1.11-csrf/blob/main/SettingsUserEdit_1.png?raw=true)
![SettingsUserEditDiff2](https://github.com/sota70/teedy-v1.11-csrf/blob/main/SettingsUserEdit_2.png?raw=true)

# References

sismics - Teedy(https://github.com/sismics/docs)<br />portswigger - Cross-site request forgery(CSRF)(https://portswigger.net/web-security/csrf)<br />Mozilla - Examples of access control scenarios(https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#examples_of_access_control_scenarios)

# Credits

I want to say thank you <a href="https://github.com/ayato-shitomi" target="_blank">Ayato</a> for teaching me how to report a vulnerability.
