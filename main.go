package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

type RecordRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Type   string `json:"type"`
}

type UpstreamRequest struct {
	Address string `json:"address"`
}

func initDB(dbPath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := goose.SetDialect("sqlite3"); err != nil {
		log.Fatal(err)
	}

	goose.SetBaseFS(embedMigrations)
	if err := goose.Up(db, "migrations"); err != nil {
		log.Fatal(err)
	}

	return db
}

type DNSResolver struct {
	db         *sql.DB
	defaultTTL int
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
				rr, err := dns.NewRR(fmt.Sprintf("%s %d A %s", q.Name, resolver.defaultTTL, ip))
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

func startAPIServer(db *sql.DB, apiPort string) {
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

	log.Printf("API Listening on %s...", apiPort)
	log.Fatal(http.ListenAndServe(":"+apiPort, nil))
}

func envString(key, def string) string {
	value := os.Getenv(key)
	if value == "" {
		value = def
	}
	return value
}

func envInt(key string, def int) int {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return def
	}
	val, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		slog.Warn("config invalid integer, using default", "key", key, "value", value, "default", def)
		return def
	}
	return int(val)
}

func main() {
	godotenv.Load()

	var (
		dbPath     = envString("DB_PATH", "./dns_records.db")
		dnsPort    = envString("DNS_PORT", "53")
		apiPort    = envString("API_PORT", "8888")
		defaultTTL = envInt("DEFAULT_TTL", 300)
	)

	db := initDB(dbPath)
	defer db.Close()

	go startAPIServer(db, apiPort)

	resolver := &DNSResolver{db: db, defaultTTL: defaultTTL}

	dns.HandleFunc(".", resolver.handleDNSRequest)

	server := &dns.Server{Addr: ":" + dnsPort, Net: "udp"}
	log.Printf("DNS Server listening on port %s...", dnsPort)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set up DNS server: %v", err)
	}
}
