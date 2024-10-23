# gocret
`gocret` is a powerful and efficient Go-based tool designed to scan and identify sensitive information such as credentials, secrets, and tokens in web applications. It leverages HTTP requests to analyze JavaScript files and other web resources, helping developers and security professionals detect potential security vulnerabilities.

# Features
+ Fast and Lightweight: Written in Go for performance, `gocret` quickly analyzes web targets.
+ Targeted Scanning: Specify the URL to scan for sensitive information.
+ Credential Detection: Identifies API keys, tokens, passwords, and other sensitive data hidden in web content.
+ Easy to Use: Simple command-line interface for quick and effective scanning.
+ Context Timeout Handling: Automatically handles timeouts for large or slow responses, providing robust scanning capabilities even for complex web applications.

# Install
To install `gocret`, make sure you have Go installed, then run the following command:
```
go install github.com/com0t/gocret@latest
```

# Usage
To scan a target URL, use the following command:
```
gocret -u https://example.com/
```
This command will scan the specified JavaScript file for any potential credentials or secrets and output the results to the console.

```
gocret -u https://example.com/path/to/target.js
```

# Command Line Flags
```
Usage of gocret:
  -H value
        Custom header to add to the request. Can be used multiple times.
  -X string
        HTTP method to use (default "GET")
  -b int
        Batch size for finding secrets (default 20)
  -f string
        Specify the output format (e.g., json, html) (default "json")
  -html string
        Specify an HTML file to scan
  -k    Allow insecure server connections when using SSL
  -o string
        Specify the file to save the output
  -recursion-depth int
        Maximum recursion depth for scanning
  -redirect
        Follow redirects (default true)
  -t int
        Number of threads to use for scanning (default 1)
  -timeout duration
        Timeout duration (in seconds) (default 5s)
  -u string
        Specify a single URL to scan
  -uL string
        Specify a file containing a list of URLs to scan
```
