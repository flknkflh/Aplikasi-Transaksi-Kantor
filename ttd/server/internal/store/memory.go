package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// Memory is a process-local Store. Safe for concurrent use.
type Memory struct {
	mu           sync.Mutex
	accounts     map[string]Account
	byEmail      map[string]string
	devices      map[string]Device
	enrollments  map[string]Enrollment
	certificates map[string]Certificate
	reservations map[string]Reservation
	signatures   map[string]Signature
	audit        []AuditEvent
	objects      map[string][]byte
}

func NewMemory() *Memory {
	return &Memory{
		accounts:     map[string]Account{},
		byEmail:      map[string]string{},
		devices:      map[string]Device{},
		enrollments:  map[string]Enrollment{},
		certificates: map[string]Certificate{},
		reservations: map[string]Reservation{},
		signatures:   map[string]Signature{},
		objects:      map[string][]byte{},
	}
}

// ID makes a random opaque id with the given prefix (e.g. "dev", "sig").
func ID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// --- accounts ---

func (m *Memory) CreateAccount(a Account) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byEmail[a.Email]; ok {
		return Account{}, fmt.Errorf("store: email already registered")
	}
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
	m.accounts[a.ID] = a
	m.byEmail[a.Email] = a.ID
	return a, nil
}

func (m *Memory) ListAccounts() []Account {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Account, 0, len(m.accounts))
	for _, a := range m.accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (m *Memory) SetAccountStatus(id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	a.Status = status
	m.accounts[id] = a
	return nil
}

func (m *Memory) UpdateAccountProfile(id, fullName, org string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	a.FullName, a.Organization = fullName, org
	m.accounts[id] = a
	return nil
}

func (m *Memory) SetAccountPassword(id, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	a.PasswordHash = passwordHash
	m.accounts[id] = a
	return nil
}

func (m *Memory) DeleteAccount(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.accounts, id)
	delete(m.byEmail, a.Email)
	return nil
}

func (m *Memory) AccountByEmail(email string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byEmail[email]
	if !ok {
		return Account{}, ErrNotFound
	}
	return m.accounts[id], nil
}

func (m *Memory) Account(id string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return Account{}, ErrNotFound
	}
	return a, nil
}

// --- devices ---

func (m *Memory) CreateDevice(d Device) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d.ID == "" {
		d.ID = ID("dev")
	}
	if d.Status == "" {
		d.Status = DeviceActive
	}
	d.CreatedAt = time.Now().UTC()
	m.devices[d.ID] = d
	return d, nil
}

func (m *Memory) Device(id string) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return Device{}, ErrNotFound
	}
	return d, nil
}

func (m *Memory) SetDeviceStatus(id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	d.Status = status
	m.devices[id] = d
	return nil
}

func (m *Memory) DevicesByAccount(accountID string) []Device {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Device
	for _, d := range m.devices {
		if d.AccountID == accountID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// --- enrollments ---

func (m *Memory) CreateEnrollment(e Enrollment) (Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.ID == "" {
		e.ID = ID("enr")
	}
	if e.Status == "" {
		e.Status = EnrollmentSubmitted
	}
	e.CreatedAt = time.Now().UTC()
	m.enrollments[e.ID] = e
	return e, nil
}

func (m *Memory) Enrollment(id string) (Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrollments[id]
	if !ok {
		return Enrollment{}, ErrNotFound
	}
	return e, nil
}

func (m *Memory) EnrollmentByDevice(deviceID string) (Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest Enrollment
	found := false
	for _, e := range m.enrollments {
		if e.DeviceID == deviceID && (!found || e.CreatedAt.After(latest.CreatedAt)) {
			latest, found = e, true
		}
	}
	if !found {
		return Enrollment{}, ErrNotFound
	}
	return latest, nil
}

func (m *Memory) ListEnrollments() []Enrollment {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Enrollment, 0, len(m.enrollments))
	for _, e := range m.enrollments {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (m *Memory) SetEnrollmentStatus(id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrollments[id]
	if !ok {
		return ErrNotFound
	}
	e.Status = status
	m.enrollments[id] = e
	return nil
}

// --- certificates ---

func (m *Memory) CreateCertificate(c Certificate) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.ID == "" {
		c.ID = ID("cert")
	}
	if c.Status == "" {
		c.Status = CertActive
	}
	m.certificates[c.ID] = c
	return c, nil
}

func (m *Memory) Certificate(id string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certificates[id]
	if !ok {
		return Certificate{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) CertificateByDevice(deviceID string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest Certificate
	found := false
	for _, c := range m.certificates {
		if c.DeviceID == deviceID && (!found || c.NotBefore.After(latest.NotBefore)) {
			latest, found = c, true
		}
	}
	if !found {
		return Certificate{}, ErrNotFound
	}
	return latest, nil
}

func (m *Memory) CertificatesByAccount(accountID string) []Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Certificate
	for _, c := range m.certificates {
		if c.AccountID == accountID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotBefore.Before(out[j].NotBefore) })
	return out
}

func (m *Memory) CertificateBySerial(serial string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.certificates {
		if c.Serial == serial {
			return c, nil
		}
	}
	return Certificate{}, ErrNotFound
}

func (m *Memory) RevokeCertificate(id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certificates[id]
	if !ok {
		return ErrNotFound
	}
	c.Status = CertRevoked
	c.RevokedAt = time.Now().UTC()
	c.RevReason = reason
	m.certificates[id] = c
	return nil
}

// --- reservations & signatures ---

func (m *Memory) CreateReservation(r Reservation) (Reservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.PublicID == "" {
		r.PublicID = ID("sig")
	}
	if r.Status == "" {
		r.Status = ReservationReserved
	}
	r.CreatedAt = time.Now().UTC()
	m.reservations[r.PublicID] = r
	return r, nil
}

func (m *Memory) Reservation(publicID string) (Reservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reservations[publicID]
	if !ok {
		return Reservation{}, ErrNotFound
	}
	return r, nil
}

func (m *Memory) SetReservationStatus(publicID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reservations[publicID]
	if !ok {
		return ErrNotFound
	}
	r.Status = status
	m.reservations[publicID] = r
	return nil
}

func (m *Memory) CreateSignature(s Signature) (Signature, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.signatures[s.PublicID]; exists {
		return Signature{}, fmt.Errorf("store: signature %s already exists", s.PublicID)
	}
	s.CreatedAt = time.Now().UTC()
	m.signatures[s.PublicID] = s
	return s, nil
}

func (m *Memory) Signature(publicID string) (Signature, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.signatures[publicID]
	if !ok {
		return Signature{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) SignaturesByAccount(accountID string) []Signature {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Signature
	for _, s := range m.signatures {
		if s.AccountID == accountID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// --- objects ---

func (m *Memory) PutObject(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.objects[key] = cp
	return nil
}

func (m *Memory) GetObject(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (m *Memory) PutObjectFrom(key string, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return m.PutObject(key, b)
}

func (m *Memory) OpenObject(key string) (io.ReadCloser, int64, error) {
	b, err := m.GetObject(key)
	if err != nil {
		return nil, 0, err
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

// --- audit ---

func (m *Memory) Append(ev AuditEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ev.ID = ID("evt")
	ev.Time = time.Now().UTC()
	m.audit = append(m.audit, ev)
}

func (m *Memory) AuditEvents(limit int) []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.audit) {
		limit = len(m.audit)
	}
	out := make([]AuditEvent, limit)
	copy(out, m.audit[len(m.audit)-limit:])
	return out
}
