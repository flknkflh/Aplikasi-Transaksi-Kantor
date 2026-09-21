package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.up.sql
var migrationsFS embed.FS

// applyMigrations runs each migrations/NNNN_*.up.sql exactly once, in name
// order, recording applied versions in schema_migrations. Safe to call on a
// fresh database and on every startup (Rencana V1 §23 M6: "migration dapat
// dijalankan dari database kosong").
func applyMigrations(db *sql.DB) error {
	if _, err := db.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (
		    version    TEXT PRIMARY KEY,
		    applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.Glob(migrationsFS, "migrations/*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, path := range entries {
		version := strings.TrimSuffix(strings.TrimPrefix(path, "migrations/"), ".up.sql")
		var done bool
		if err := db.QueryRow(`SELECT true FROM schema_migrations WHERE version=$1`, version).Scan(&done); err == nil {
			continue
		}
		body, err := migrationsFS.ReadFile(path)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES($1)`, version); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Postgres implements the same method set as Memory, backed by PostgreSQL +
// an ObjectStore for the signed PDF blobs.
type Postgres struct {
	db   *sql.DB
	objs ObjectStore
}

// OpenPostgres connects with dsn (a pgx URL), applies the schema, and uses
// objs for blobs. If objs is nil, blobs go in the `objects` table.
func OpenPostgres(dsn string, objs ObjectStore) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(time.Hour)
	for i := 0; i < 30; i++ { // wait for the container to accept connections
		if err = db.Ping(); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		return nil, err
	}
	p := &Postgres{db: db}
	if objs != nil {
		p.objs = objs
	} else {
		p.objs = dbObjects{db: db}
	}
	return p, nil
}

func (p *Postgres) Close() error { return p.db.Close() }

func norm(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// --- accounts ---

const acctCols = `id,email,display_name,full_name,organization,position,nip,password_hash,role,status,created_at`

func (p *Postgres) CreateAccount(a Account) (Account, error) {
	if a.ID == "" {
		a.ID = ID("acct")
	}
	if a.Role == "" {
		a.Role = RoleUser
	}
	if a.Status == "" {
		a.Status = AccountActive
	}
	a.CreatedAt = time.Now().UTC()
	_, err := p.db.Exec(
		`INSERT INTO accounts(id,email,display_name,full_name,organization,position,nip,password_hash,role,status,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		a.ID, a.Email, a.DisplayName, a.FullName, a.Organization, a.Position, a.NIP,
		a.PasswordHash, a.Role, a.Status, a.CreatedAt)
	if err != nil {
		return Account{}, fmt.Errorf("store: email already registered")
	}
	return a, nil
}

func scanAccountRow(s interface{ Scan(...any) error }) (Account, error) {
	var a Account
	err := s.Scan(&a.ID, &a.Email, &a.DisplayName, &a.FullName, &a.Organization,
		&a.Position, &a.NIP,
		&a.PasswordHash, &a.Role, &a.Status, &a.CreatedAt)
	return a, norm(err)
}

func (p *Postgres) AccountByEmail(email string) (Account, error) {
	return scanAccountRow(p.db.QueryRow(`SELECT `+acctCols+` FROM accounts WHERE email=$1`, email))
}

func (p *Postgres) Account(id string) (Account, error) {
	return scanAccountRow(p.db.QueryRow(`SELECT `+acctCols+` FROM accounts WHERE id=$1`, id))
}

func (p *Postgres) ListAccounts() []Account {
	rows, err := p.db.Query(`SELECT ` + acctCols + ` FROM accounts ORDER BY created_at`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		if a, err := scanAccountRow(rows); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (p *Postgres) SetAccountStatus(id, status string) error {
	return affected(p.db.Exec(`UPDATE accounts SET status=$1 WHERE id=$2`, status, id))
}

func (p *Postgres) UpdateAccountProfile(id, fullName, org string) error {
	return affected(p.db.Exec(`UPDATE accounts SET full_name=$1, organization=$2 WHERE id=$3`, fullName, org, id))
}

func (p *Postgres) SetAccountPassword(id, passwordHash string) error {
	return affected(p.db.Exec(`UPDATE accounts SET password_hash=$1 WHERE id=$2`, passwordHash, id))
}

func (p *Postgres) DeleteAccount(id string) error {
	return affected(p.db.Exec(`DELETE FROM accounts WHERE id=$1`, id))
}

// --- devices ---

func (p *Postgres) CreateDevice(d Device) (Device, error) {
	if d.ID == "" {
		d.ID = ID("dev")
	}
	if d.Status == "" {
		d.Status = DeviceActive
	}
	d.CreatedAt = time.Now().UTC()
	_, err := p.db.Exec(
		`INSERT INTO devices(id,account_id,label,platform,status,created_at) VALUES($1,$2,$3,$4,$5,$6)`,
		d.ID, d.AccountID, d.Label, d.Platform, d.Status, d.CreatedAt)
	return d, err
}

func scanDevice(s interface{ Scan(...any) error }) (Device, error) {
	var d Device
	err := s.Scan(&d.ID, &d.AccountID, &d.Label, &d.Platform, &d.Status, &d.CreatedAt)
	return d, norm(err)
}

func (p *Postgres) Device(id string) (Device, error) {
	return scanDevice(p.db.QueryRow(
		`SELECT id,account_id,label,platform,status,created_at FROM devices WHERE id=$1`, id))
}

func (p *Postgres) SetDeviceStatus(id, status string) error {
	res, err := p.db.Exec(`UPDATE devices SET status=$1 WHERE id=$2`, status, id)
	return affected(res, err)
}

func (p *Postgres) DevicesByAccount(accountID string) []Device {
	rows, err := p.db.Query(
		`SELECT id,account_id,label,platform,status,created_at FROM devices WHERE account_id=$1 ORDER BY created_at`, accountID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		if d, err := scanDevice(rows); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// --- enrollments ---

func (p *Postgres) CreateEnrollment(e Enrollment) (Enrollment, error) {
	if e.ID == "" {
		e.ID = ID("enr")
	}
	if e.Status == "" {
		e.Status = EnrollmentSubmitted
	}
	e.CreatedAt = time.Now().UTC()
	_, err := p.db.Exec(
		`INSERT INTO enrollments(id,device_id,account_id,csr_pem,csr_key_fp,status,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		e.ID, e.DeviceID, e.AccountID, e.CSRPEM, e.CSRKeyFP, e.Status, e.CreatedAt)
	return e, err
}

func scanEnrollment(s interface{ Scan(...any) error }) (Enrollment, error) {
	var e Enrollment
	err := s.Scan(&e.ID, &e.DeviceID, &e.AccountID, &e.CSRPEM, &e.CSRKeyFP, &e.Status, &e.CreatedAt)
	return e, norm(err)
}

func (p *Postgres) Enrollment(id string) (Enrollment, error) {
	return scanEnrollment(p.db.QueryRow(
		`SELECT id,device_id,account_id,csr_pem,csr_key_fp,status,created_at FROM enrollments WHERE id=$1`, id))
}

func (p *Postgres) ListEnrollments() []Enrollment {
	rows, err := p.db.Query(
		`SELECT id,device_id,account_id,csr_pem,csr_key_fp,status,created_at FROM enrollments ORDER BY created_at`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		if e, err := scanEnrollment(rows); err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (p *Postgres) SetEnrollmentStatus(id, status string) error {
	return affected(p.db.Exec(`UPDATE enrollments SET status=$1 WHERE id=$2`, status, id))
}

// --- certificates ---

func (p *Postgres) CreateCertificate(c Certificate) (Certificate, error) {
	if c.ID == "" {
		c.ID = ID("cert")
	}
	if c.Status == "" {
		c.Status = CertActive
	}
	_, err := p.db.Exec(
		`INSERT INTO certificates(id,enrollment_id,device_id,account_id,serial,fingerprint,pem,not_before,not_after,status)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.ID, c.EnrollmentID, c.DeviceID, c.AccountID, c.Serial, c.Fingerprint, c.PEM,
		c.NotBefore, c.NotAfter, c.Status)
	return c, err
}

func scanCert(s interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	var revoked sql.NullTime
	err := s.Scan(&c.ID, &c.EnrollmentID, &c.DeviceID, &c.AccountID, &c.Serial, &c.Fingerprint,
		&c.PEM, &c.NotBefore, &c.NotAfter, &c.Status, &revoked, &c.RevReason)
	if revoked.Valid {
		c.RevokedAt = revoked.Time
	}
	return c, norm(err)
}

const certCols = `id,enrollment_id,device_id,account_id,serial,fingerprint,pem,not_before,not_after,status,revoked_at,rev_reason`

func (p *Postgres) Certificate(id string) (Certificate, error) {
	return scanCert(p.db.QueryRow(`SELECT `+certCols+` FROM certificates WHERE id=$1`, id))
}

func (p *Postgres) CertificateByDevice(deviceID string) (Certificate, error) {
	return scanCert(p.db.QueryRow(
		`SELECT `+certCols+` FROM certificates WHERE device_id=$1 ORDER BY not_before DESC LIMIT 1`, deviceID))
}

func (p *Postgres) CertificateBySerial(serial string) (Certificate, error) {
	return scanCert(p.db.QueryRow(`SELECT `+certCols+` FROM certificates WHERE serial=$1`, serial))
}

func (p *Postgres) CertificatesByAccount(accountID string) []Certificate {
	rows, err := p.db.Query(`SELECT `+certCols+` FROM certificates WHERE account_id=$1 ORDER BY not_before`, accountID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		if c, err := scanCert(rows); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func (p *Postgres) RevokeCertificate(id, reason string) error {
	return affected(p.db.Exec(
		`UPDATE certificates SET status=$1, revoked_at=now(), rev_reason=$2 WHERE id=$3`,
		CertRevoked, reason, id))
}

// --- reservations & signatures ---

func (p *Postgres) CreateReservation(r Reservation) (Reservation, error) {
	if r.PublicID == "" {
		r.PublicID = ID("sig")
	}
	if r.Status == "" {
		r.Status = ReservationReserved
	}
	r.CreatedAt = time.Now().UTC()
	_, err := p.db.Exec(
		`INSERT INTO reservations(public_id,account_id,device_id,original_sha512,file_name,status,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		r.PublicID, r.AccountID, r.DeviceID, r.OriginalSHA512, r.FileName, r.Status, r.CreatedAt, r.ExpiresAt)
	return r, err
}

func (p *Postgres) Reservation(publicID string) (Reservation, error) {
	var r Reservation
	err := p.db.QueryRow(
		`SELECT public_id,account_id,device_id,original_sha512,file_name,status,created_at,expires_at
		 FROM reservations WHERE public_id=$1`, publicID).
		Scan(&r.PublicID, &r.AccountID, &r.DeviceID, &r.OriginalSHA512, &r.FileName, &r.Status, &r.CreatedAt, &r.ExpiresAt)
	return r, norm(err)
}

func (p *Postgres) SetReservationStatus(publicID, status string) error {
	return affected(p.db.Exec(`UPDATE reservations SET status=$1 WHERE public_id=$2`, status, publicID))
}

func (p *Postgres) CreateSignature(s Signature) (Signature, error) {
	s.CreatedAt = time.Now().UTC()
	_, err := p.db.Exec(
		`INSERT INTO signatures(public_id,account_id,device_id,certificate_id,cert_serial,cert_fingerprint,
		   algorithm,pdf_profile,original_sha512,signed_pdf_sha512,client_claimed_signing_time,
		   server_received_at,storage_object_key,signed_size,verification_status,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		s.PublicID, s.AccountID, s.DeviceID, s.CertificateID, s.CertSerial, s.CertFingerprint,
		s.Algorithm, s.PDFProfile, s.OriginalSHA512, s.SignedSHA512, s.ClientClaimedSigningTime,
		s.ServerReceivedAt, s.StorageObjectKey, s.SignedSize, s.VerificationStatus, s.CreatedAt)
	if err != nil {
		return Signature{}, fmt.Errorf("store: signature %s already exists", s.PublicID)
	}
	return s, nil
}

const sigCols = `public_id,account_id,device_id,certificate_id,cert_serial,cert_fingerprint,algorithm,pdf_profile,original_sha512,signed_pdf_sha512,client_claimed_signing_time,server_received_at,storage_object_key,signed_size,verification_status,created_at`

func scanSig(s interface{ Scan(...any) error }) (Signature, error) {
	var x Signature
	err := s.Scan(&x.PublicID, &x.AccountID, &x.DeviceID, &x.CertificateID, &x.CertSerial, &x.CertFingerprint,
		&x.Algorithm, &x.PDFProfile, &x.OriginalSHA512, &x.SignedSHA512, &x.ClientClaimedSigningTime,
		&x.ServerReceivedAt, &x.StorageObjectKey, &x.SignedSize, &x.VerificationStatus, &x.CreatedAt)
	return x, norm(err)
}

func (p *Postgres) Signature(publicID string) (Signature, error) {
	return scanSig(p.db.QueryRow(`SELECT `+sigCols+` FROM signatures WHERE public_id=$1`, publicID))
}

func (p *Postgres) SignaturesByAccount(accountID string) []Signature {
	rows, err := p.db.Query(`SELECT `+sigCols+` FROM signatures WHERE account_id=$1 ORDER BY created_at DESC`, accountID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Signature
	for rows.Next() {
		if x, err := scanSig(rows); err == nil {
			out = append(out, x)
		}
	}
	return out
}

// --- objects & audit ---

func (p *Postgres) PutObject(key string, data []byte) error { return p.objs.PutObject(key, data) }
func (p *Postgres) GetObject(key string) ([]byte, error)    { return p.objs.GetObject(key) }
func (p *Postgres) PutObjectFrom(key string, r io.Reader, size int64) error {
	return p.objs.PutObjectFrom(key, r, size)
}
func (p *Postgres) OpenObject(key string) (io.ReadCloser, int64, error) {
	return p.objs.OpenObject(key)
}

func (p *Postgres) Append(ev AuditEvent) {
	_, _ = p.db.Exec(
		`INSERT INTO audit_events(id,ts,type,account_id,device_id,result,detail) VALUES($1,now(),$2,$3,$4,$5,$6)`,
		ID("evt"), ev.Type, ev.AccountID, ev.DeviceID, ev.Result, ev.Detail)
}

func (p *Postgres) AuditEvents(limit int) []AuditEvent {
	if limit <= 0 {
		limit = 500
	}
	rows, err := p.db.Query(
		`SELECT id,ts,type,account_id,device_id,result,detail FROM audit_events ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.Time, &e.Type, &e.AccountID, &e.DeviceID, &e.Result, &e.Detail); err == nil {
			out = append(out, e)
		}
	}
	// caller expects oldest-first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
