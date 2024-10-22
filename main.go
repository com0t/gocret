package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/html"
)

type CustomHeaders []string

func (h *CustomHeaders) String() string {
	return fmt.Sprint(*h)
}

func (h *CustomHeaders) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type HTTPReq struct {
	Insecure       bool
	Timeout        time.Duration
	Redirect       bool
	Method         string
	RecursionDepth int
	Headers        *CustomHeaders
}

type Options struct {
	URL          string
	FileURL      string
	FileHtml     string
	FormatOutput string
	OutputFile   string
	Threads      int
	Bulk         int
}

type SecretResult struct {
	Link    string   `json:"Link"`
	Secrets []string `json:"Secrets"`
}

type URLResult struct {
	URL     string         `json:"URL"`
	Results []SecretResult `json:"Results"`
}

func (req *HTTPReq) MakeRequest(URL string) (string, error) {
	request, err := http.NewRequest(req.Method, URL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	for _, header := range *req.Headers {
		parts := splitHeader(header)
		if len(parts) == 2 {
			request.Header.Add(parts[0], parts[1])
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: req.Insecure},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   req.Timeout,
	}

	if !req.Redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("error executing request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	return string(body), nil
}

func (req *HTTPReq) findLinks(domain string, options *Options) ([]string, error) {
	var fullLinks []string
	var err error
	fullURL := strings.TrimSuffix(domain, "/")

	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		fullURL = fmt.Sprintf("https://%s", domain)
	}

	_, err = url.ParseRequestURI(fullURL)
	if err != nil {
		return fullLinks, err
	}

	resp, err := req.MakeRequest(fullURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		if strings.HasPrefix(fullURL, "https://") {
			fullURL = fmt.Sprintf("http://%s", domain)
			resp, err = req.MakeRequest(fullURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return fullLinks, err
			}
		} else {
			return fullLinks, err
		}
	}

	links, err := extractLinks(resp)
	links = append(links, fullURL)
	if err != nil {
		return fullLinks, err
	}

	for _, link := range links {
		if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") {
			if !strings.HasPrefix(link, "/") {
				link = fmt.Sprintf("%s/%s", fullURL, link)
			} else {
				link = fmt.Sprintf("%s%s", fullURL, link)
			}
		}
		fullLinks = append(fullLinks, link)
	}

	return fullLinks, nil
}

func (req *HTTPReq) findSecrets(link string) (SecretResult, error) {
	var secretResult SecretResult

	resp, err := req.MakeRequest(link)
	if err != nil {
		return secretResult, err
	}

	secrets, err := extractSecrets(resp)
	if err != nil {
		return secretResult, err
	}

	secretResult = SecretResult{
		Link:    link,
		Secrets: secrets,
	}

	return secretResult, nil
}

func extractLinks(htmlContent string) ([]string, error) {
	var links []string
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return links, err
	}

	attributes := map[string]string{
		"a":      "href",
		"img":    "src",
		"script": "src",
		"link":   "href",
		"iframe": "src",
		"embed":  "src",
		"object": "data",
		"source": "src",
		"area":   "href",
		"track":  "src",
	}

	uniqueLinks := make(map[string]struct{})

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if attr, found := attributes[n.Data]; found {
				for _, a := range n.Attr {
					if a.Key == attr {
						link := a.Val

						if _, exists := uniqueLinks[link]; !exists {
							uniqueLinks[link] = struct{}{}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(doc)

	links = make([]string, 0, len(uniqueLinks))
	for link := range uniqueLinks {
		links = append(links, link)
	}

	return links, nil
}

func checkExcludeSecret(secret string) bool {
	excludes := []string{
		`access_token:"emptyAccessToken"`,
	}

	for _, v := range excludes {
		if v == secret {
			return true
		}
	}

	return false
}

func extractSecrets(htmlContent string) ([]string, error) {
	sensitiveRegex := regexp.MustCompile(`(?i)((Password|S3_ACCESS_KEY|accessKey|apiKey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]`)

	uniqueSecrets := make(map[string]struct{})
	matches := sensitiveRegex.FindAllString(htmlContent, -1)
	if len(matches) > 0 {
		for _, match := range matches {
			if !checkExcludeSecret(match) {
				uniqueSecrets[match] = struct{}{}
			}
		}
	}

	secrets := make([]string, 0, len(uniqueSecrets))
	for secret := range uniqueSecrets {
		secrets = append(secrets, secret)
	}

	return secrets, nil
}

func readURLsFromFile(filePath string) ([]string, error) {
	var urls []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func splitHeader(header string) []string {
	return strings.SplitN(header, ":", 2)
}

func processURL(url string, options *Options, httpReq *HTTPReq, done <-chan struct{}) *URLResult {
	links, err := httpReq.findLinks(url, options)
	fmt.Println(links)
	if err != nil {
		return nil
	}

	var secretResults []SecretResult
	var secretSetLock sync.Mutex
	linkChan := make(chan string, len(links))

	// Gửi tất cả các link vào channel
	for _, link := range links {
		select {
		case <-done:
			return nil
		case linkChan <- link:
		}
	}
	close(linkChan)

	var linkWg sync.WaitGroup
	for i := 0; i < options.Bulk; i++ {
		linkWg.Add(1)
		go func() {
			defer linkWg.Done()
			for {
				select {
				case <-done: // Khi nhận tín hiệu ngắt, thoát goroutine
					return
				case link, ok := <-linkChan:
					if !ok {
						return // Channel đã đóng, kết thúc goroutine
					}
					result, err := httpReq.findSecrets(link)
					if err != nil {
						continue
					}

					if len(result.Secrets) > 0 {
						secretSetLock.Lock()
						secretResults = append(secretResults, SecretResult{
							Link:    result.Link,
							Secrets: result.Secrets,
						})
						secretSetLock.Unlock()
					}
				}
			}
		}()
	}

	linkWg.Wait()

	if len(secretResults) > 0 {
		return &URLResult{
			URL:     url,
			Results: secretResults,
		}
	}

	return nil
}

func showOutput(urlResults []*URLResult, options *Options) {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>URL Results</title>
    <style>
      table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        font-size: 1em;
        text-align: left;
        table-layout: fixed; /* Cố định bố cục bảng */
      }

      th,
      td {
        padding: 12px 15px;
        border: 1px solid #ddd;
      }

      th {
        background-color: #f2f2f2;
      }

      tr:nth-child(even) {
        background-color: #f9f9f9;
      }

      tr:hover {
        background-color: #e0f7fa;
        cursor: pointer;
      }

      td {
        word-wrap: break-word;
        white-space: pre-wrap;
        overflow-wrap: break-word;
      }

      .filter-container {
        margin-bottom: 20px;
      }
    </style>
  </head>
  <body>
    <div class="filter-container">
      <label for="urlFilter">Filter by URL:</label>
      <input
        type="text"
        id="urlFilter"
        onkeyup="filterTable()"
        placeholder="Enter URL to filter..."
      />

      <label for="urlFilter">Filter by Link:</label>
      <input
        type="text"
        id="urlLink"
        onkeyup="filterTable()"
        placeholder="Enter URL to filter..."
      />

      <label for="secretsFilter" style="margin-left: 20px"
        >Filter by Secrets:</label
      >
      <input
        type="text"
        id="secretsFilter"
        onkeyup="filterTable()"
        placeholder="Enter Secret to filter..."
      />
    </div>

    <table id="resultsTable">
      <thead>
        <tr>
          <th style="width: 20%">URL</th>
          <th style="width: 50%">Link</th>
          <th style="width: 30%">Secrets</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        <!-- Data will be inserted dynamically here -->
      </tbody>
    </table>

    <script>
      const data = REPLACE_DATA;
      function escapeHtml(unsafe) {
        return unsafe
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }

      function populateTable() {
        const tableBody = document.getElementById("tableBody");
        data.forEach((item) => {
          item.Results.forEach((result) => {
            const row = document.createElement("tr");

            const urlCell = document.createElement("td");
            urlCell.textContent = item.URL;

            const linkCell = document.createElement("td");
            const linkAnchor = document.createElement("a");
            linkAnchor.href = result.Link;
            linkAnchor.textContent = result.Link;
            linkAnchor.target = "_blank";
            linkCell.appendChild(linkAnchor);

            const secretsCell = document.createElement("td");
            secretsCell.innerHTML = result.Secrets.map((secret) =>
              escapeHtml(secret)
            ).join("<br><hr>");

            row.appendChild(urlCell);
            row.appendChild(linkCell);
            row.appendChild(secretsCell);

            tableBody.appendChild(row);
          });
        });
      }

      function filterTable() {
        const urlFilter = document
          .getElementById("urlFilter")
          .value.toLowerCase();
        const linkFilter = document
          .getElementById("urlLink")
          .value.toLowerCase();
        const secretsFilter = document
          .getElementById("secretsFilter")
          .value.toLowerCase();
        const rows = document.querySelectorAll("#resultsTable tbody tr");

        rows.forEach((row) => {
          const urlCell = row.cells[0].textContent.toLowerCase();
          const secretsCell = row.cells[2].textContent.toLowerCase();

          let showRow = true;

          if (urlFilter.startsWith("!")) {
            const keyword = urlFilter.slice(1);
            if (urlCell.indexOf(keyword) > -1) {
              showRow = false;
            }
          } else if (urlCell.indexOf(urlFilter) === -1) {
            showRow = false;
          }

          if (linkFilter.startsWith("!")) {
            const keyword = linkFilter.slice(1);
            if (urlCell.indexOf(keyword) > -1) {
              showRow = false;
            }
          } else if (urlCell.indexOf(linkFilter) === -1) {
            showRow = false;
          }

          if (secretsFilter.startsWith("!")) {
            const keyword = secretsFilter.slice(1);
            if (secretsCell.indexOf(keyword) > -1) {
              showRow = false;
            }
          } else if (secretsCell.indexOf(secretsFilter) === -1) {
            showRow = false;
          }

          row.style.display = showRow ? "" : "none";
        });
      }

      window.onload = populateTable;
    </script>
  </body>
</html>
`

	jsonData, err := json.MarshalIndent(urlResults, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling to JSON:", err)
		return
	}

	if options.FormatOutput == "json" {
		if options.OutputFile != "" {
			err := os.WriteFile(options.OutputFile, jsonData, 0644)
			if err != nil {
				fmt.Println("Error writing JSON to file:", err)
				return
			}
		} else {
			fmt.Println(string(jsonData))
		}
	} else if options.FormatOutput == "html" {
		if options.OutputFile != "" {
			// templateFile := "output_template.html"

			// template, err := os.ReadFile(templateFile)
			// if err != nil {
			// 	fmt.Println("Error reading file template:", err)
			// 	return
			// }

			// templateData := string(template)
			templateData := strings.Replace(htmlTemplate, "REPLACE_DATA", string(jsonData), 1)

			err = os.WriteFile(options.OutputFile, []byte(templateData), 0644)
			if err != nil {
				fmt.Println("Error writing HTML to file:", err)
				return
			}
		} else {
			fmt.Println("Error: No output file specified for HTML format")
		}
	}
}

func main() {
	options := &Options{}
	flag.StringVar(&options.URL, "u", "", "Specify a single URL to scan")
	flag.StringVar(&options.FileURL, "uL", "", "Specify a file containing a list of URLs to scan")
	flag.StringVar(&options.FileHtml, "html", "", "Specify an HTML file to scan")
	flag.StringVar(&options.FormatOutput, "f", "json", "Specify the output format (e.g., json, html)")
	flag.StringVar(&options.OutputFile, "o", "", "Specify the file to save the output")
	flag.IntVar(&options.Threads, "t", 1, "Number of threads to use for scanning")
	flag.IntVar(&options.Bulk, "b", 20, "Batch size for finding secrets")

	httpReq := &HTTPReq{}
	flag.BoolVar(&httpReq.Insecure, "k", false, "Allow insecure server connections when using SSL")
	flag.DurationVar(&httpReq.Timeout, "timeout", 30*time.Second, "Timeout duration (in seconds)")
	flag.BoolVar(&httpReq.Redirect, "redirect", true, "Follow redirects")
	flag.StringVar(&httpReq.Method, "X", "GET", "HTTP method to use")
	flag.IntVar(&httpReq.RecursionDepth, "recursion-depth", 0, "Maximum recursion depth for scanning")
	httpReq.Headers = &CustomHeaders{}
	flag.Var(httpReq.Headers, "H", "Custom header to add to the request. Can be used multiple times.")

	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Println("Usage: -h to show help")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Starting scan with the following parameters:\n")
	if options.URL != "" {
		fmt.Fprintf(os.Stderr, "URL:              %s\n", options.URL)
	}
	if options.FileURL != "" {
		fmt.Fprintf(os.Stderr, "URL List (File):  %s\n", options.FileURL)
	}
	if options.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "Output File:      %s\n", options.OutputFile)
	}
	fmt.Fprintf(os.Stderr, "Output Format:    %s\n", options.FormatOutput)
	fmt.Fprintf(os.Stderr, "Threads:          %d\n", options.Threads)
	fmt.Fprintf(os.Stderr, "Bulk Size:        %d\n", options.Bulk)

	if options.FileHtml != "" {
		fmt.Fprintf(os.Stderr, "HTML File: %s\n", options.FileHtml)
	}
	fmt.Println("")

	var urls []string

	if options.FileHtml != "" {
		htmlContent, err := os.ReadFile(options.FileHtml)
		if err != nil {
			fmt.Printf("Error reading HTML file: %v\n", err)
			os.Exit(1)
		}

		secrets, err := extractSecrets(string(htmlContent))
		if err != nil {
			fmt.Printf("Error extracting secrets: %v\n", err)
			os.Exit(1)
		}
		for _, secret := range secrets {
			fmt.Printf("Extracted secret: %v\n", secret)
		}
	} else if options.URL != "" {
		urls = append(urls, options.URL)
	} else if options.FileURL != "" {
		fileURLs, err := readURLsFromFile(options.FileURL)
		if err != nil {
			fmt.Printf("Error reading URL file: %v\n", err)
			return
		}
		urls = fileURLs
	} else {
		fmt.Println("No valid input provided. Please specify either -u, -uL, or -html.")
		os.Exit(1)
	}

	urlResults := make([]*URLResult, 0, len(urls))

	sem := make(chan struct{}, options.Threads)
	var wg sync.WaitGroup
	var mu sync.Mutex

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		<-stopChan
		fmt.Println("\nReceived interrupt signal, shutting down gracefully...")
		close(done)
	}()

UrlLoop:
	for _, u := range urls {
		select {
		case <-done:
			break UrlLoop
		default:
			sem <- struct{}{}
			wg.Add(1)
			go func(u string) {
				defer func() {
					<-sem
					wg.Done()
				}()

				result := processURL(u, options, httpReq, done)
				if result != nil {
					mu.Lock()
					urlResults = append(urlResults, result)
					mu.Unlock()
				}
			}(u)
		}
	}

	wg.Wait()
	close(sem)

	showOutput(urlResults, options)
	fmt.Fprintln(os.Stderr, "Scan completed.")
}
