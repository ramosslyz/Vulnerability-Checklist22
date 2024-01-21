# What are file upload vulnerabilities?

* File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.

![rce1](https://github.com/InfoSecExplorer/File-upload-vulnerabilities/assets/145893728/42552d35-2705-440a-a6da-55c959752daa)

# What is the impact of file upload vulnerabilities?

**The impact of file upload vulnerabilities generally depends on two key factors:**

1. Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
2. What restrictions are imposed on the file once it has been successfully uploaded.

* In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as .php and .jsp) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.

* If the filename isn't validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name. If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations.

# How do file upload vulnerabilities arise?

* Given the fairly obvious dangers, it's rare for websites in the wild to have no restrictions whatsoever on which files users are allowed to upload. More commonly, developers implement what they believe to be robust validation that is either inherently flawed or can be easily bypassed.

* For example, they may attempt to blacklist dangerous file types, but fail to account for parsing discrepancies when checking the file extensions. As with any blacklist, it's also easy to accidentally omit more obscure file types that may still be dangerous.

* In other cases, the website may attempt to check the file type by verifying properties that can be easily manipulated by an attacker using tools like Burp Proxy or Repeater.

* Ultimately, even robust validation measures may be applied inconsistently across the network of hosts and directories that form the website, resulting in discrepancies that can be exploited.

# How do web servers handle requests for static files?

* The process for handling these static files is still largely the same. At some point, the server parses the path in the request to identify the file extension. It then uses this to determine the type of the file being requested, typically by comparing it to a list of preconfigured mappings between extensions and MIME types. What happens next depends on the file type and the server's configuration.

* If this file type is non-executable, such as an image or a static HTML page, the server may just send the file's contents to the client in an HTTP response.

* If the file type is executable, such as a PHP file, and the server is configured to execute files of this type, it will assign variables based on the headers and parameters in the HTTP request before running the script.

* The resulting output may then be sent to the client in an HTTP response.

* If the file type is executable, but the server is not configured to execute files of this type, it will generally respond with an error. However, in some cases, the contents of the file may still be served to the client as plain text. Such misconfigurations can occasionally be exploited to leak source code and other sensitive information. You can see an example of this in our information disclosure learning materials.

* The Content-Type response header may provide clues as to what kind of file the server thinks it has served. If this header hasn't been explicitly set by the application code, it normally contains the result of the file extension/MIME type mapping.

# Web shell upload via Content-Type restriction bypass

 * When submitting HTML forms, the browser typically sends the provided data in a POST request with the content type application/x-www-form-url-encoded. This is fine for sending simple text like your name or address. However, it isn't suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type multipart/form-data is preferred.

**Consider a form containing fields for uploading an image, providing a description of it, and entering your username. Submitting such a form might result in a request that looks something like this:**

*  As you can see, the message body is split into separate parts for each of the form's inputs. Each part contains a Content-Disposition header, which provides some basic information about the input field it relates to. These individual parts may also contain their own Content-Type header, which tells the server the MIME type of the data that was submitted using this input.

![rce2](https://github.com/InfoSecExplorer/File-upload-vulnerabilities/assets/145893728/063e32ff-4ba2-4b50-818c-8ef5ffe2ee8d)

* One way that websites may attempt to validate file uploads is to check that this input-specific Content-Type header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like image/jpeg and image/png. Problems can arise when the value of this header is implicitly trusted by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME type, this defense can be easily bypassed using tools like Burp Repeater.

# Web shell upload via extension blacklist bypass

* Even the most exhaustive blacklists can potentially be bypassed using classic obfuscation techniques. Let's say the validation code is case sensitive and fails to recognize that exploit.pHp is in fact a .php file. If the code that subsequently maps the file extension to a MIME type is not case sensitive, this discrepancy allows you to sneak malicious PHP files past validation that may eventually be executed by the server.

**You can also achieve similar results using the following techniques:** 

1. Provide multiple extensions. Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image: exploit.php.jpg

2. Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: exploit.php.
  
3. Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes. If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: exploit%2Ephp
 
4. Add semicolons or URL-encoded null byte characters before the file extension. If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: exploit.asp;.jpg or exploit.asp%00.jpg
  
5. Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like xC0 x2E, xC4 xAE or xC0 xAE may be translated to x2E if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

# Uploading files using PUT

* It's worth noting that some web servers may be configured to support PUT requests. If appropriate defenses aren't in place, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface.

![rce3](https://github.com/InfoSecExplorer/File-upload-vulnerabilities/assets/145893728/08eb3cb6-ce30-4cce-aa15-e08744b10d0f)
 
**Tip**
* You can try sending OPTIONS requests to different endpoints to test for any that advertise support for the PUT method.

# How to prevent file upload vulnerabilities

* Allowing users to upload files is commonplace and doesn't have to be dangerous as long as you take the right precautions. In general, the most effective way to protect your own websites from these vulnerabilities is to implement all of the following practices:

1. Check the file extension against a whitelist of permitted extensions rather than a blacklist of prohibited ones. It's much easier to guess which extensions you might want to allow than it is to guess which ones an attacker might try to upload.
 
2. Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence (../).

3. Rename uploaded files to avoid collisions that may cause existing files to be overwritten.

4. Do not upload files to the server's permanent filesystem until they have been fully validated.

5. As much as possible, use an established framework for preprocessing file uploads rather than attempting to write your own validation mechanisms.


Testing For File-Upload and Exploiting - https://kathan19.gitbook.io/howtohunt/file-upload-bypass/file_upload








