# gocret

# Install

```
go install github.com/com0t/gocret@latest
```

# Usage
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