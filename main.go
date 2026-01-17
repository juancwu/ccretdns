package main

import (
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
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

//go:embed migrations/*.sql index.html
var embedMigrations embed.FS

var indexTmpl = template.Must(template.ParseFS(embedMigrations, "index.html"))

type Record struct {
	Domain     string
	IP         string
	RecordType string
}

type Upstream struct {
	Address string
}

type PageData struct {
	Records   []Record
	Upstreams []Upstream
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
			isLanOrInternal := strings.HasSuffix(q.Name, ".lan.") || strings.HasSuffix(q.Name, ".internal.")
			isARecord := q.Qtype == dns.TypeA
			isAaaaRecord := q.Qtype == dns.TypeAAAA

			if (isARecord || isAaaaRecord) && isLanOrInternal {
				var qTypeString string
				if isARecord {
					qTypeString = "A"
				} else {
					qTypeString = "AAAA"
				}

				ip, err := resolver.getRecordFromDB(q.Name, qTypeString)
				if err == nil && ip != "" {
					log.Printf("[LOCAL] Resolved %s -> %s", q.Name, ip)
					rr, err := dns.NewRR(fmt.Sprintf("%s %d %s %s", q.Name, resolver.defaultTTL, qTypeString, ip))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
					continue
				}
			}

			// Fallback to upstream for all other cases
			var clientIP net.IP
			switch addr := w.RemoteAddr().(type) {
			case *net.UDPAddr:
				clientIP = addr.IP
			case *net.TCPAddr:
				clientIP = addr.IP
			}

			resp, err := resolver.resolveUpstream(r, clientIP)
			if err == nil && resp != nil {
				log.Printf("[UPSTREAM] Forwarded %s (ClientIP: %s)", q.Name, clientIP)
				m.Answer = resp.Answer
				m.Ns = resp.Ns
				m.Extra = resp.Extra
			} else {
				log.Printf("[ERROR] Could not resolve %s", q.Name)
				m.Rcode = dns.RcodeServerFailure
			}
		}
	}

	w.WriteMsg(m)
}

func (resolver *DNSResolver) getRecordFromDB(domain string, recordType string) (string, error) {
	// DNS queries usually come with a trailing dot (e.g., "google.com.")
	// Ensure consistency by checking both with and without it if needed,
	// or enforcing it in the DB. Here we assume DB stores with trailing dot.
	var ip string
	err := resolver.db.QueryRow("SELECT ip FROM records WHERE domain = ? AND record_type = ?", domain, recordType).Scan(&ip)
	if err != nil {
		return "", err
	}
	return ip, nil
}

func (resolver *DNSResolver) resolveUpstream(r *dns.Msg, clientIP net.IP) (*dns.Msg, error) {
	rows, err := resolver.db.Query("SELECT address FROM upstreams")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Create a copy of the message to avoid side effects
	req := r.Copy()

	// Add EDNS0 Client Subnet option
	if clientIP != nil {
		o := req.IsEdns0()
		if o == nil {
			req.SetEdns0(4096, false)
			o = req.IsEdns0()
		}

		// Filter out existing SUBNET options to ensure we are authoritative about the client IP
		var newOptions []dns.EDNS0
		for _, opt := range o.Option {
			if opt.Option() != dns.EDNS0SUBNET {
				newOptions = append(newOptions, opt)
			}
		}

		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		if ip4 := clientIP.To4(); ip4 != nil {
			e.Family = 1 // IPv4
			e.SourceNetmask = 32
			e.SourceScope = 0
			e.Address = ip4
		} else {
			e.Family = 2 // IPv6
			e.SourceNetmask = 128
			e.SourceScope = 0
			e.Address = clientIP
		}

		newOptions = append(newOptions, e)
		o.Option = newOptions
	}

	c := new(dns.Client)
	c.Net = "udp"

	c.Timeout = 5 * time.Second

	for rows.Next() {
		var upstreamAddr string
		if err := rows.Scan(&upstreamAddr); err != nil {
			continue
		}

		resp, _, err := c.Exchange(req, upstreamAddr)
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("all upstreams failed")
}

func startAPIServer(db *sql.DB, apiPort string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		recordsRows, err := db.Query("SELECT domain, ip, record_type FROM records")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer recordsRows.Close()

		var records []Record
		for recordsRows.Next() {
			var rec Record
			if err := recordsRows.Scan(&rec.Domain, &rec.IP, &rec.RecordType); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			records = append(records, rec)
		}

		upstreamsRows, err := db.Query("SELECT address FROM upstreams")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer upstreamsRows.Close()

		var upstreams []Upstream
		for upstreamsRows.Next() {
			var ups Upstream
			if err := upstreamsRows.Scan(&ups.Address); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			upstreams = append(upstreams, ups)
		}

		data := PageData{
			Records:   records,
			Upstreams: upstreams,
		}

		if err := indexTmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	http.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		domain := r.FormValue("domain")
		ip := r.FormValue("ip")
		recordType := r.FormValue("type")
		method := r.FormValue("_method")

		if method == "" {
			method = r.Method
		}

		if method == http.MethodPost {
			// Normalize domain to ensure trailing dot
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}

			if recordType == "" {
				recordType = "A"
			}
			recordType = strings.ToUpper(recordType)

			if recordType != "A" && recordType != "AAAA" {
				http.Error(w, "Invalid record type. Must be A or AAAA", http.StatusBadRequest)
				return
			}
			_, err := db.Exec("INSERT OR REPLACE INTO records (domain, ip, record_type) VALUES (?, ?, ?)", domain, ip, recordType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
		} else if method == http.MethodDelete {
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}

			_, err := db.Exec("DELETE FROM records WHERE domain = ? AND record_type = ?", domain, recordType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
		}
	})

	http.HandleFunc("/upstreams", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		address := r.FormValue("address")
		method := r.FormValue("_method")

		if method == "" {
			method = r.Method
		}

		if method == http.MethodPost {
			_, err := db.Exec("INSERT INTO upstreams (address) VALUES (?)", address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
		} else if method == http.MethodDelete {
			_, err := db.Exec("DELETE FROM upstreams WHERE address = ?", address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
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
