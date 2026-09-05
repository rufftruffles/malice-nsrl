package main

// Malice NSRL plugin — modernized for the NIST RDSv3 (Reference Data Set v3)
// SQLite database.
//
// This is an "intel" (hash-lookup / whitelisting) engine. The malice core runs
// it as a fire-and-forget container with args ["lookup", "-t", "<sha1>"] and
// the env vars MALICE_SCANID, MALICE_TIMEOUT and MALICE_ELASTICSEARCH_URL. The
// binary looks the file's SHA1 up in the bundled RDSv3 SQLite database (the NIST
// National Software Reference Library) and writes its result DIRECTLY to
// Elasticsearch at plugins.intel.nsrl (via the shared pkgs ES client, which
// does an _update against the doc the core already created).
//
// A hash present in the NSRL is a known-legitimate software file (whitelisted);
// a hash absent from the NSRL is not a known-good file and is left for the
// other engines to analyze.
//
// Unlike the old plugin (which built a probabilistic Bloom filter with a 0.1%
// false-positive rate), this engine performs an EXACT lookup against the
// authoritative RDSv3 SQLite database.
//
// The database path is configurable via the NSRL_DB env var (default
// /nsrl/RDS.db). The image bundles a real RDSv3 SQLite set so the engine is
// fully functional; point NSRL_DB at a larger set (e.g. the 18 GB
// RDS_2026.03.1_modern_minimal.db) to use the full modern whitelist.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/fatih/structs"
	_ "modernc.org/sqlite"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "nsrl"
	category = "intel"

	// defaultDBPath is where the RDSv3 SQLite database lives in the image.
	defaultDBPath = "/nsrl/RDS.db"

	// queryTimeout bounds the SQLite lookup so a wedged DB can never hang the
	// scan past the malice timeout.
	queryTimeout = 30 * time.Second
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	// es is the elasticsearch database object
	es   elasticsearch.Database
	hash string
)

// Nsrl is the stdout wrapper, mirroring the old plugin's json shape.
type Nsrl struct {
	Results ResultsData `json:"nsrl"`
}

// ResultsData is the document stored at plugins.intel.nsrl. It replicates the
// old plugin shape (found + hash + markdown) and adds the exact RDSv3 match
// metadata plus a graceful error field.
type ResultsData struct {
	Found    bool   `json:"found" structs:"found"`
	Hash     string `json:"hash" structs:"hash"`
	Sha256   string `json:"sha256,omitempty" structs:"sha256,omitempty"`
	Md5      string `json:"md5,omitempty" structs:"md5,omitempty"`
	FileName string `json:"file_name,omitempty" structs:"file_name,omitempty"`
	FileSize int64  `json:"file_size,omitempty" structs:"file_size,omitempty"`
	Error    string `json:"error,omitempty" structs:"error,omitempty"`
	MarkDown string `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"hash":     hash,
		}).Fatal(err)
	}
}

// dbPath returns the RDSv3 SQLite database path (NSRL_DB env or default).
func dbPath() string {
	if p := strings.TrimSpace(os.Getenv("NSRL_DB")); p != "" {
		return p
	}
	return defaultDBPath
}

// lookup queries the RDSv3 SQLite database for the hash. It never returns an
// error: every failure path (missing DB, open error, query error) is recorded
// in the result so a valid document is always written to Elasticsearch.
func lookup(hash string) ResultsData {
	res := ResultsData{Hash: hash}

	path := dbPath()
	if _, err := os.Stat(path); err != nil {
		res.Error = fmt.Sprintf("RDSv3 database not available at %s: %v", path, err)
		return res
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		res.Error = fmt.Sprintf("failed to open RDSv3 database: %v", err)
		return res
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	// The RDSv3 FILE view/table stores hashes upper-cased; query both cases to
	// be robust across publications. LIMIT 1: a single hash can map to several
	// file_name/package_id rows.
	var dbSha1 string
	err = db.QueryRowContext(ctx,
		`SELECT sha256, sha1, md5, file_name, file_size
		 FROM FILE
		 WHERE sha1 = ? OR sha1 = ?
		 LIMIT 1`,
		strings.ToUpper(hash), strings.ToLower(hash)).
		Scan(&res.Sha256, &dbSha1, &res.Md5, &res.FileName, &res.FileSize)
	switch {
	case err == sql.ErrNoRows:
		res.Found = false
	case err != nil:
		res.Error = fmt.Sprintf("RDSv3 query failed: %v", err)
	default:
		res.Found = true
	}

	return res
}

func generateMarkDownTable(n Nsrl) string {
	var tplOut bytes.Buffer
	t := template.Must(template.New("nsrl").Parse(tpl))
	if err := t.Execute(&tplOut, n); err != nil {
		log.Println("executing template:", err)
	}
	return tplOut.String()
}

func main() {
	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "nsrl"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice NSRL Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Query the NSRL (RDSv3) for a hash",
			ArgsUsage: "MD5/SHA1 hash of file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "elasticsearch",
					Value:       "",
					Usage:       "elasticsearch url for Malice to store results",
					EnvVar:      "MALICE_ELASTICSEARCH_URL",
					Destination: &es.URL,
				},
				cli.IntFlag{
					Name:   "timeout",
					Value:  60,
					Usage:  "malice plugin timeout (in seconds)",
					EnvVar: "MALICE_TIMEOUT",
				},
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) error {
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}

				if !c.Args().Present() {
					return errors.New("please supply a MD5/SHA1 hash to query")
				}

				// The old plugin stored the hash upper-cased in the doc; keep that.
				hash = strings.ToUpper(strings.TrimSpace(c.Args().First()))

				hashType, err := utils.GetHashType(hash)
				if err != nil || (hashType != "md5" && hashType != "sha1") {
					return errors.Errorf("please supply a proper MD5/SHA1 hash to query (got %q)", c.Args().First())
				}

				nsrl := Nsrl{Results: lookup(hash)}
				nsrl.Results.MarkDown = generateMarkDownTable(nsrl)

				// upsert into Database
				if len(c.String("elasticsearch")) > 0 {
					if err := es.Init(); err != nil {
						return errors.Wrap(err, "failed to initialize elasticsearch")
					}
					if err := es.StorePluginResults(database.PluginResults{
						ID:       utils.Getopt("MALICE_SCANID", hash),
						Name:     name,
						Category: category,
						Data:     structs.Map(nsrl.Results),
					}); err != nil {
						return errors.Wrapf(err, "failed to index malice/%s results", name)
					}
					log.WithFields(log.Fields{
						"plugin":   name,
						"category": category,
						"hash":     hash,
						"found":    nsrl.Results.Found,
					}).Debug("stored nsrl results in elasticsearch")
				}

				if c.Bool("table") {
					fmt.Println(nsrl.Results.MarkDown)
				} else {
					nsrl.Results.MarkDown = ""
					nsrlJSON, err := json.Marshal(nsrl)
					assert(err)
					fmt.Println(string(nsrlJSON))
				}
				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelp(c)
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
