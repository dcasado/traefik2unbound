package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

type urlList []string

func (u *urlList) Set(urlsString string) error {
	if urlsString != "" {
		urls := strings.Split(urlsString, ",")
		for _, url := range urls {
			if url != "" {
				*u = append(*u, url)
			}
		}
	}
	return nil
}

func (u *urlList) String() string {
	builder := strings.Builder{}
	for i, url := range *u {
		builder.WriteString(url)
		if i != len(*u) {
			builder.WriteString(",")
		}
	}
	return builder.String()
}

type router struct {
	Rule string `json:"rule"`
}

const (
	expression   = "Host(SNI)?\\(`(?P<url>[^/`]+)`"
	backupSuffix = ".bak"
)

var (
	traefikURLs             urlList
	traefikServicesFilePath string
	unboundCheckconfPath    string
)

func main() {
	flag.Var(&traefikURLs, "u", "Comma separated list of Traefik URLs in the format \"https://traefik.io,https://localhost\"")
	flag.StringVar(&traefikServicesFilePath, "p", "traefik-services.conf", "Path of the file where is going to save services hosts")
	flag.StringVar(&unboundCheckconfPath, "c", "unbound-checkconf", "Path of the unbound-checkconf executable")
	flag.Parse()

	builder := strings.Builder{}
	builder.WriteString("# The contents of this file will be overriden to add traefik endpoints dynamically\n")

	for _, URL := range traefikURLs {
		servicesHosts, err := retrieveServicesHosts(URL)
		if err != nil {
			log.Println(err)
		}
		appendServicesHostsToBuilder(servicesHosts, &builder)
	}

	createFileIfNotExists(traefikServicesFilePath)
	if !compareUpdatedContentsWithActualFile(builder.String(), traefikServicesFilePath) {
		backupFile(traefikServicesFilePath)
		err := writeContentsToFile(traefikServicesFilePath, builder.String())
		if err != nil {
			rollbackFile(traefikServicesFilePath)
			log.Fatalf("%s", err)
		}

		if checkIfFileIsValid(unboundCheckconfPath) {
			restartUnbound()
		} else {
			rollbackFile(traefikServicesFilePath)
		}
	}
}

func retrieveServicesHosts(traefikURL string) (map[string]string, error) {
	ip := retrieveIP(traefikURL)

	httpRoutersURL := traefikURL + "/api/http/routers"
	httpRouters, err := getTraefikRouters(httpRoutersURL)
	if err != nil {
		return nil, err
	}

	tcpRoutersURL := traefikURL + "/api/tcp/routers"
	tcpRouters, err := getTraefikRouters(tcpRoutersURL)
	if err != nil {
		return nil, err
	}

	allRouters := append(httpRouters, tcpRouters...)

	re, err := regexp.Compile(expression)
	if err != nil {
		log.Printf("Error compiling regular expression %s to extract the host from the router rule", expression)
		return nil, err
	}
	urls := make(map[string]string)
	for _, router := range allRouters {
		match := re.FindStringSubmatch(router.Rule)
		for i, name := range re.SubexpNames() {
			if i != 0 && name == "url" {
				urls[match[i]] = ip
			}
		}
	}
	return urls, nil
}

func retrieveIP(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Println(err)
	}
	host := u.Host

	ips, err := net.LookupIP(host)
	if err != nil {
		log.Println(err)
	}
	if len(ips) == 0 {
		log.Fatalf("No IPs found for host %s", host)
	}
	ip := ips[0].To4()
	if ip == nil {
		log.Fatalf("Could not convert IP %x to IPv4 representation from host %s", ips[0], host)
	}
	return ip.String()
}

func getTraefikRouters(routersURL string) ([]router, error) {
	resp, err := http.Get(routersURL)
	if err != nil {
		log.Printf("Could not retrieve routers from \"%s\"", routersURL)
		return nil, err
	} else {
		if resp.StatusCode >= 400 {
			log.Printf("Response from %s not successful. Status: %s", routersURL, resp.Status)
			return nil, err
		} else {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Error reading traefik response body, %s", err)
				return nil, err
			}
			routers := make([]router, 5)
			err = json.Unmarshal(body, &routers)
			if err != nil {
				log.Println("Error unmarshalling traefik response body")
				return nil, err
			}
			return routers, nil
		}
	}
}

func appendServicesHostsToBuilder(urls map[string]string, builder *strings.Builder) {
	keys := make([]string, 0, len(urls))

	for k := range urls {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i == 0 {
			builder.WriteString(fmt.Sprintf("# Endpoints extracted from %s\n", urls[k]))
		}
		builder.WriteString(fmt.Sprintf("local-data: \"%s A %s\"\n", k, urls[k]))
	}
}

func createFileIfNotExists(path string) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// create the file
		file, err := os.Create(path)
		if err != nil {
			log.Fatalf("Error creating file %s. %s", path, err)
		}
		defer file.Close()

		err = os.Chmod(path, 0644)
		if err != nil {
			log.Fatalf("Error changing permissions to file %s. %s", path, err)
		}
	}
}

func compareUpdatedContentsWithActualFile(updatedContents string, path string) bool {
	return getSHA256FromString(updatedContents) == getSHA256FromFile(path)
}

func getSHA256FromString(contents string) string {
	h := sha256.New()
	h.Write([]byte(contents))
	return string(h.Sum(nil))
}

func getSHA256FromFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening file %s. %s", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatalf("Error copying file contents of %s to calculate SHA256. %s", path, err)
	}

	return string(h.Sum(nil))
}

func backupFile(path string) {
	cmd := exec.Command("cp", path, path+backupSuffix)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()

	if err != nil {
		log.Fatalf("Error backing up %s. %s", path, errb.String())
	}
}

func writeContentsToFile(path string, contents string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening file %s", path)
		return err
	}
	defer file.Close()

	// Remove all contents from the file
	err = file.Truncate(0)
	if err != nil {
		log.Printf("Error truncating file %s", path)
		return err
	}

	_, err = file.WriteString(contents)
	if err != nil {
		log.Printf("Error writing contents to file %s", path)
		return err
	}
	return nil
}

func rollbackFile(path string) {
	cmd := exec.Command("cp", path+backupSuffix, path)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()

	if err != nil {
		log.Fatalf("Error restoring backup %s. %s", path, errb.String())
	}
}

func checkIfFileIsValid(unboundCheckconfPath string) bool {
	cmd := exec.Command(unboundCheckconfPath)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()

	if err != nil {
		log.Printf("Error checking configuration. %s", err)
		return false
	}
	return true
}

func restartUnbound() {
	cmd := exec.Command("systemctl", "restart", "unbound")
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()

	if err != nil {
		log.Fatalf("Error restarting unbound. %s, %s", outb.String(), errb.String())
	}
}
