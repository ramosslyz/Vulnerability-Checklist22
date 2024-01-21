# What is Server-side Request Forgery (SSRF)?

Server-Side Request Forgery (SSRF) is a type of web application vulnerability that allows an attacker to send arbitrary HTTP requests from a vulnerable web application to an external server. The application may be tricked into sending malicious requests to internal systems, which could lead to sensitive data exposure or other security issues.

SSRF vulnerabilities occur when an application is designed to forward a user-supplied URL or other input to an external server, without properly validating or sanitizing the input. This can allow an attacker to craft a request that causes the application to send a request to an internal system or resource that would otherwise be inaccessible. For example, an attacker could use SSRF to access internal network resources such as databases, file servers, or other sensitive systems.
![maxresdefault](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/8a175435-74df-41c1-a988-c8adde2203d1)

# What is its impact?
**A malicious actor can retrieve the content of arbitrary files on the system, which leads to sensitive information exposure(passwords, source code, confidential data, etc.).**
1. Sensitive Data Exposure
2. Unauthenticated Requests
3. Port Scans or Cross Site Port Attack (XSPA)
4. Protocol Smuggling

# General methodology and checklist for testing for SSRF vulnerabilities

**SSRF vulnerabilities typically involves the following steps**

1. Identify potential inputs that are used to construct URLs or initiate requests to external servers. These inputs may include GET or POST parameters, headers, and other user-supplied data.

2. Test each input by providing a variety of different URLs or IP addresses as the input, including internal resources, localhost, and other special values.

3. Observe the application’s behavior when provided with different inputs, and look for signs of SSRF vulnerabilities, such as the ability to access internal resources or exfiltrate data.

4. Document any vulnerabilities found, including the input that was used to trigger the vulnerability, the type of vulnerability, and the potential impact.

**A checklist for testing for SSRF vulnerabilities**

* Verify if the application makes HTTP requests to user-supplied URLs

* Verify if the application makes HTTP requests to user-supplied IP addresses

* Verify if the application makes HTTP requests with user-supplied headers and/or cookies

* Verify if the application makes HTTP requests to internal resources or localhost

* Check if the application has any protection mechanisms against SSRF attacks (e.g. whitelisting allowed URLs)

* Test if it’s possible to use the SSRF vulnerability to gain access to internal resources or steal sensitive data

* Test if it’s possible to use the SSRF vulnerability to perform out-of-band data exfiltration

* Test if it’s possible to use the SSRF vulnerability to perform internal port scanning

* Test if it’s possible to use the SSRF vulnerability to bypass access controls

* Test if it’s possible to use the SSRF vulnerability to exploit other vulnerabilities

# Steps To Reproduce

1. Login to Search.gov and click help manual.
2. The following request was vulnerable.

![ssrf1](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/f7e9a029-7bf7-495f-8320-1fba0cd5c701)

3. If you insert http://127.0.0.1:21/?%0A before url parameter and send request, then response time is about 450ms. (Port is closed)
 
![ssrf2](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/00ca7a9d-edb9-4a7d-a93c-215f05aea769)

4. If you insert http://127.0.0.1:22/?%0A before url parameter and send request, then response time is about 10,468ms. (Port is open)
 
![ssrf3](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/4e86c00b-9584-474f-aa9e-232fbd22da45)

5. If you insert http://169.254.169.254/latest/meta-data/iam/security-credentials/?%0A before url parameter, then response body is empty. (/security-credentials exists)
 
![ssrf4](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/1ae78381-24c7-41dc-b4d3-671647ef4df7)

6. If you insert http://169.254.169.254/latest/meta-data/iam/security-credentialx/?%0A before url parameter, then response body is Unable to retrieve error. (/security-credentialx does not exists)

![ssrf5](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/d441d154-77aa-4d3a-a8de-2892987a248e)

7. Finally Successfully Exploited SSRF Vulnerability.

![ssrf6](https://github.com/InfoSecExplorer/Server-side-Request-Forgery-SSRF-/assets/145893728/d77cbcc0-48b9-4d95-b326-76e3e390adb4)


# SSRF vulnerability exploits

**There are several methods for exploiting Server-Side Request Forgery (SSRF) vulnerabilities, including**

* Internal Port Scanning: An attacker can use an SSRF vulnerability to scan internal networks for open ports and potentially discover sensitive information or other vulnerabilities.

* Out-of-band Data Exfiltration: An attacker can use an SSRF vulnerability to extract sensitive data from the target system by sending the data to a server under the attacker’s control.

* File Reading: An attacker can use an SSRF vulnerability to read sensitive files on the target system, such as configuration files or sensitive data.

* File Upload: An attacker can use an SSRF vulnerability to upload malicious files to the target system.

* Command Injection: An attacker can use an SSRF vulnerability to execute arbitrary commands on the target system.

* Accessing Sensitive Internal Resources: An attacker can use an SSRF vulnerability to access sensitive internal resources, such as databases or other internal servers.

* HTTP Request Smuggling: An attacker can use an SSRF vulnerability to smuggle malicious HTTP requests through the target system, potentially bypassing security controls.

* HTTP Request Hijacking: An attacker can use an SSRF vulnerability to hijack legitimate HTTP requests and redirect them to a server under the attacker’s control.

* Bypassing Firewalls and Intrusion Detection Systems: An attacker can use an SSRF vulnerability to bypass firewalls and intrusion detection systems by making requests to internal resources.

* DDoS Attack: An attacker can use an SSRF vulnerability to launch a Distributed Denial of Service (DDoS) attack by making requests to external resources.

# List of payloads suitable for SSRF vulnerabilities

1. Internal IP Address: Attempting to access internal IP addresses, such as “http://127.0.0.1” or “http://10.0.0.1“, can help identify SSRF vulnerabilities that allow access to internal resources.

2. Loopback Address: Attempting to access the loopback address, such as “http://localhost“, can help identify SSRF vulnerabilities that allow access to internal resources.

3. File Paths: Attempting to access file paths, such as “file:///etc/passwd”, can help identify SSRF vulnerabilities that allow access to sensitive files on the target system.

4. External IP Address: Attempting to access external IP addresses, such as “http://8.8.8.8” can help identify SSRF vulnerabilities that allow access to external resources.

5. DNS Lookup: Attempting to perform a DNS lookup, such as “http://example.com/lookup?host=google.com” can help identify SSRF vulnerabilities that allow access to external resources.

6. Localhost Address: Attempting to access the localhost address, such as “http://127.0.0.1:22” can help identify SSRF vulnerabilities that allow access to internal resources.

7. File URL: Attempting to access a file URL, such as “file:///etc/passwd” can help identify SSRF vulnerabilities that allow access to sensitive files on the target system.

8. Bypassing Firewalls: Attempting to access internal resources by bypassing firewalls, such as “http://internal-ip-address” can help identify SSRF vulnerabilities that allow access to internal resources.

9. Data URI: Attempting to access data URI, such as “data:text/html,<html>test</html>” can help identify SSRF vulnerabilities that allow access to internal resources.

10. Local File Inclusion: Attempting to access local files using LFI payloads, such as “http://127.0.0.1/../../../../../../etc/passwd” can help identify SSRF vulnerabilities that allow access to sensitive files on the target system.

# How to be protected from SSRF vulnerabilities

* Validate and sanitize user input: Make sure that your web application properly validates and sanitizes user input to prevent SSRF vulnerabilities. This includes using whitelists to restrict the types of URLs that can be accessed, and implementing input validation checks to ensure that user input conforms to a specific format.

* Use a Content Security Policy (CSP): Use a Content Security Policy (CSP) to specify which sources of content are allowed to be loaded by your web application. This can help prevent SSRF attacks by blocking malicious requests from being loaded.

* Implement access controls: Implement access controls to limit the types of requests that can be made to internal resources. This can include limiting the types of URLs that can be accessed, and implementing authentication and authorization checks to ensure that only authorized users can access internal resources.

* Use firewalls and intrusion detection systems: Use firewalls and intrusion detection systems to prevent unauthorized access to internal resources. This can include implementing rules to block specific types of requests, and monitoring for suspicious activity.

* Keep your software up-to-date: Keep your software up-to-date to ensure that you are protected against the latest SSRF vulnerabilities. This includes updating your web application framework and any other software that your web application relies on.

* Train your developer and user: Regularly train your developers, and end-users on the SSRF vulnerabilities and the importance of keeping software and systems updated.

* Monitor and Audit: Regularly monitor and audit your systems, network and applications for any suspicious activity.

# Top 25 Server-Side Request Forgery (SSRF) Parameters

* ?dest={target}
* ?redirect={target}
* ?uri={target}
* ?path={target}
* ?continue={target}
* ?url={target}
* ?window={target}
* ?next={target}
* ?data={target}
* ?reference={target}
* ?site={target}
* ?html={target}
* ?val={target}
* ?validate={target}
* ?domain={target}
* ?callback={target}
* ?return={target}
* ?page={target}
* ?feed={target}
* ?host={target}
* ?port={target}
* ?to={target}
* ?out={target}
* ?view={target}
* ?dir={target}**

**Refferance link**
* https://hackerone.com/reports/737161
* https://hackerone.com/reports/816848
* https://hackerone.com/reports/398799
* https://hackerone.com/reports/382048
* https://hackerone.com/reports/406387
* https://hackerone.com/reports/736867
* https://hackerone.com/reports/517461
* https://hackerone.com/reports/508459
* https://hackerone.com/reports/738553
* https://hackerone.com/reports/514224
* https://hackerone.com/reports/341876
* https://hackerone.com/reports/793704
* https://hackerone.com/reports/386292
* https://hackerone.com/reports/326040
* https://hackerone.com/reports/310036
* https://hackerone.com/reports/643622
* https://hackerone.com/reports/885975
* https://hackerone.com/reports/207477
