package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

const (
	DBPath     = "./dns_records.db"
	DNSPort    = "53"
	APIPort    = ":8080"
	DefaultTTL = 300
)

type RecordRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Type   string `json:"type"`
}

type UpstreamRequest struct {
	Address string `json:"address"`
}

func initDB() *sql.DB {
	db, err := sql.Open("sqlite3", DBPath)
	if err != nil {
		log.Fatal(err)
	}

	queryRecords := `
	CREATE TABLE IF NOT EXISTS records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		ip TEXT NOT NULL,
		record_type TEXT DEFAULT 'A'
	);`

	queryUpstreams := `
	CREATE TABLE IF NOT EXISTS upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		address TEXT NOT NULL UNIQUE
	);`

	if _, err := db.Exec(queryRecords); err != nil {
		log.Fatalf("Error creating records table: %v", err)
	}
	if _, err := db.Exec(queryUpstreams); err != nil {
		log.Fatalf("Error creating upstreams table: %v", err)
	}

	return db
}

type DNSResolver struct {
	db *sql.DB
}

func (resolver *DNSResolver) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			ip, err := resolver.getRecordFromDB(q.Name)
			if err == nil && ip != "" {
				log.Printf("[LOCAL] Resolved %s -> %s", q.Name, ip)
				rr, err := dns.NewRR(fmt.Sprintf("%s %d A %s", q.Name, DefaultTTL, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				resp, err := resolver.resolveUpstream(r)
				if err == nil && resp != nil {
					log.Printf("[UPSTREAM] Forwarded %s", q.Name)
					m.Answer = resp.Answer
					m.Ns = resp.Ns
					m.Extra = resp.Extra
					m.Rcode = resp.Rcode
				} else {
					log.Printf("[ERROR] Could not resolve %s", q.Name)
					m.Rcode = dns.RcodeServerFailure
				}
			}
		}
	}

	w.WriteMsg(m)
}

func (resolver *DNSResolver) getRecordFromDB(domain string) (string, error) {
	// DNS queries usually come with a trailing dot (e.g., "google.com.")
	// Ensure consistency by checking both with and without it if needed,
	// or enforcing it in the DB. Here we assume DB stores with trailing dot.
	var ip string
	err := resolver.db.QueryRow("SELECT ip FROM records WHERE domain = ?", domain).Scan(&ip)
	if err != nil {
		return "", err
	}
	return ip, nil
}

func (resolver *DNSResolver) resolveUpstream(r *dns.Msg) (*dns.Msg, error) {
	rows, err := resolver.db.Query("SELECT address FROM upstreams")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c := new(dns.Client)
	c.Net = "udp"

	c.Timeout = 5 * time.Second

	for rows.Next() {
		var upstreamAddr string
		if err := rows.Scan(&upstreamAddr); err != nil {
			continue
		}

		resp, _, err := c.Exchange(r, upstreamAddr)
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("all upstreams failed")
}

func startAPIServer(db *sql.DB) {
	http.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req RecordRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Normalize domain to ensure trailing dot
			if !strings.HasSuffix(req.Domain, ".") {
				req.Domain += "."
			}

			_, err := db.Exec("INSERT OR REPLACE INTO records (domain, ip, record_type) VALUES (?, ?, ?)", req.Domain, req.IP, "A")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, "Added %s -> %s", req.Domain, req.IP)

		} else if r.Method == http.MethodDelete {
			var req RecordRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !strings.HasSuffix(req.Domain, ".") {
				req.Domain += "."
			}

			_, err := db.Exec("DELETE FROM records WHERE domain = ?", req.Domain)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "Deleted %s", req.Domain)
		}
	})

	http.HandleFunc("/upstreams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req UpstreamRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, err := db.Exec("INSERT INTO upstreams (address) VALUES (?)", req.Address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, "Added upstream %s", req.Address)
		} else if r.Method == http.MethodDelete {
			var req UpstreamRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, err := db.Exec("DELETE FROM upstreams WHERE address = ?", req.Address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "Deleted upstream %s", req.Address)
		}
	})

	log.Printf("API Listening on %s...", APIPort)
	log.Fatal(http.ListenAndServe(APIPort, nil))
}

func main() {
	db := initDB()
	defer db.Close()

	go startAPIServer(db)

	resolver := &DNSResolver{db: db}

	dns.HandleFunc(".", resolver.handleDNSRequest)

	server := &dns.Server{Addr: ":" + DNSPort, Net: "udp"}
	log.Printf("DNS Server listening on port %s...", DNSPort)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set up DNS server: %v", err)
	}
}
