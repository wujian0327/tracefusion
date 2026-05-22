package main

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const listenAddr = ":9080"

var (
	bookCount          = envInt("BOOK_COUNT", 100)
	detailsHostname    = envString("DETAILS_HOSTNAME", "details")
	detailsServicePort = envString("DETAILS_SERVICE_PORT", "9080")
	reviewsHostname    = envString("REVIEWS_HOSTNAME", "reviews")
	reviewsServicePort = envString("REVIEWS_SERVICE_PORT", "9080")
	ratingsHostname    = envString("RATINGS_HOSTNAME", "ratings")
	ratingsServicePort = envString("RATINGS_SERVICE_PORT", "9080")
	httpClient         = newTLSHTTP1Client()
)

type Details struct {
	ID        int    `json:"id"`
	Author    string `json:"author"`
	Genre     string `json:"genre"`
	ISBN10    string `json:"ISBN-10"`
	ISBN13    string `json:"ISBN-13"`
	Language  string `json:"language"`
	Pages     int    `json:"pages"`
	Publisher string `json:"publisher"`
	Type      string `json:"type"`
	Year      int    `json:"year"`
}

type Ratings struct {
	ID      int            `json:"id"`
	Ratings map[string]int `json:"ratings"`
	Source  string         `json:"source"`
}

type Review struct {
	Reviewer string `json:"reviewer"`
	Text     string `json:"text"`
	Rating   int    `json:"rating"`
}

type Reviews struct {
	ID      int      `json:"id"`
	Reviews []Review `json:"reviews"`
	Ratings Ratings  `json:"ratings"`
}

type ProductPage struct {
	ID      int     `json:"id"`
	Title   string  `json:"title"`
	Details Details `json:"details"`
	Reviews Reviews `json:"reviews"`
	Service string  `json:"service"`
}

func main() {
	role := envString("SERVICE_ROLE", "productpage")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", jsonHandler(func(_ *http.Request) any {
		return map[string]string{"status": role + " is healthy", "protocol": "go-tls-http1"}
	}))

	switch role {
	case "details":
		mux.HandleFunc("/details/", jsonHandler(detailsHandler))
	case "ratings":
		mux.HandleFunc("/ratings/", jsonHandler(ratingsHandler))
	case "reviews":
		mux.HandleFunc("/reviews/", jsonHandler(reviewsHandler))
	case "productpage":
		mux.HandleFunc("/", jsonHandler(productpageHandler))
		mux.HandleFunc("/productpage", jsonHandler(productpageHandler))
	default:
		log.Fatalf("unknown SERVICE_ROLE=%q", role)
	}

	cert, err := selfSignedCertificate()
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS12,
		},
	}

	log.Printf("starting %s go-tls-http1 service on %s", role, listenAddr)
	if err := server.Serve(tls.NewListener(listener, server.TLSConfig)); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func productpageHandler(r *http.Request) any {
	bookID := selectedBookID(r)
	detailsURL := fmt.Sprintf("https://%s:%s/details/%d", detailsHostname, detailsServicePort, bookID)
	reviewsURL := fmt.Sprintf("https://%s:%s/reviews/%d", reviewsHostname, reviewsServicePort, bookID)

	var details Details
	mustGetJSON(r.Context(), detailsURL, r, &details)

	var reviews Reviews
	mustGetJSON(r.Context(), reviewsURL, r, &reviews)

	return ProductPage{
		ID:      bookID,
		Title:   fmt.Sprintf("Go TLS HTTP/1.1 Book %03d", bookID),
		Details: details,
		Reviews: reviews,
		Service: "bookinfo-go-tls-http1-productpage",
	}
}

func detailsHandler(r *http.Request) any {
	bookID := pathID(r, "/details/")
	genres := []string{"distributed systems", "database internals", "observability", "performance engineering", "networking"}
	return Details{
		ID:        bookID,
		Author:    fmt.Sprintf("Author %02d", bookID),
		Genre:     genres[bookID%len(genres)],
		ISBN10:    fmt.Sprintf("1234567%03d", bookID),
		ISBN13:    fmt.Sprintf("978-1-4028-%04d-%d", bookID, bookID%10),
		Language:  "English",
		Pages:     120 + bookID*7,
		Publisher: fmt.Sprintf("Publisher%02d", bookID%9),
		Type:      "paperback",
		Year:      2000 + bookID%25,
	}
}

func reviewsHandler(r *http.Request) any {
	bookID := pathID(r, "/reviews/")
	ratingsURL := fmt.Sprintf("https://%s:%s/ratings/%d", ratingsHostname, ratingsServicePort, bookID)
	var ratings Ratings
	mustGetJSON(r.Context(), ratingsURL, r, &ratings)
	return Reviews{
		ID: bookID,
		Reviews: []Review{
			{
				Reviewer: "Reviewer1",
				Text:     fmt.Sprintf("Go TLS HTTP/1.1 review one for book %d", bookID),
				Rating:   ratings.Ratings["Reviewer1"],
			},
			{
				Reviewer: "Reviewer2",
				Text:     fmt.Sprintf("Go TLS HTTP/1.1 review two for book %d", bookID),
				Rating:   ratings.Ratings["Reviewer2"],
			},
		},
		Ratings: ratings,
	}
}

func ratingsHandler(r *http.Request) any {
	bookID := pathID(r, "/ratings/")
	source := rand.New(rand.NewSource(int64(bookID) + 17))
	return Ratings{
		ID: bookID,
		Ratings: map[string]int{
			"Reviewer1": 1 + source.Intn(5),
			"Reviewer2": 1 + source.Intn(5),
		},
		Source: "go-tls-http1-ratings",
	}
}

func jsonHandler(fn func(*http.Request) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Bookinfo-Protocol", "go-tls-http1")
		for _, name := range []string{"x-mark", "x-request-id", "x-trace-id", "x-b3-traceid", "x-b3-spanid", "traceparent", "tracestate"} {
			if value := r.Header.Get(name); value != "" {
				w.Header().Set(name, value)
			}
		}
		if err := json.NewEncoder(w).Encode(fn(r)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func newTLSHTTP1Client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: false,
		},
		Timeout: 5 * time.Second,
	}
}

func selfSignedCertificate() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "bookinfo-tls-go",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"details", "ratings", "reviews", "productpage", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(crand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func mustGetJSON(ctx context.Context, url string, inbound *http.Request, out any) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}
	for _, name := range []string{"x-mark", "x-request-id", "x-trace-id", "x-b3-traceid", "x-b3-spanid", "traceparent", "tracestate", "user-agent"} {
		if value := inbound.Header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		panic(fmt.Sprintf("unexpected status from %s: %s", url, resp.Status))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		panic(err)
	}
}

func selectedBookID(r *http.Request) int {
	rawID := r.URL.Query().Get("id")
	id, err := strconv.Atoi(rawID)
	if err != nil {
		return 0
	}
	return positiveMod(id, bookCount)
}

func pathID(r *http.Request, prefix string) int {
	rawID := strings.TrimPrefix(r.URL.Path, prefix)
	id, err := strconv.Atoi(rawID)
	if err != nil {
		return 0
	}
	return positiveMod(id, bookCount)
}

func positiveMod(value int, mod int) int {
	if mod <= 0 {
		return value
	}
	value %= mod
	if value < 0 {
		value += mod
	}
	return value
}

func envString(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
