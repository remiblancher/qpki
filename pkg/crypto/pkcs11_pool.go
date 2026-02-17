//go:build cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file implements PKCS#11 session pooling for efficient HSM access.
package crypto

import (
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11SessionPool manages PKCS#11 sessions for a single module.
// It implements a true connection pool pattern with Acquire/Release semantics.
// Sessions are reused across operations and properly cleaned up on Close.
type PKCS11SessionPool struct {
	mu        sync.Mutex
	ctx       *pkcs11.Ctx
	module    string
	slotID    uint
	pin       string
	available []pkcs11.SessionHandle          // sessions available for use
	inUse     map[pkcs11.SessionHandle]bool   // sessions currently in use
	loginDone bool                            // whether login was performed
	closed    bool
}

var (
	// globalPools stores singleton pools per (module, slotID) combination
	globalPools   = make(map[string]*PKCS11SessionPool)
	globalPoolsMu sync.Mutex
)

// poolKey generates a unique key for a pool based on module path and slot ID.
func poolKey(modulePath string, slotID uint) string {
	return fmt.Sprintf("%s:%d", modulePath, slotID)
}

// GetSessionPool returns the session pool for a PKCS#11 module and slot.
// If the pool doesn't exist, it creates one and initializes the module.
// The pool is a singleton per (modulePath, slotID) combination.
func GetSessionPool(modulePath string, slotID uint, pin string) (*PKCS11SessionPool, error) {
	globalPoolsMu.Lock()
	defer globalPoolsMu.Unlock()

	key := poolKey(modulePath, slotID)

	// Return existing pool if available
	if pool, ok := globalPools[key]; ok {
		pool.mu.Lock()
		if pool.closed {
			pool.mu.Unlock()
			// Pool was closed, create a new one
			delete(globalPools, key)
		} else {
			pool.mu.Unlock()
			return pool, nil
		}
	}

	// Create new context
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}

	// Initialize module (ignore CKR_CRYPTOKI_ALREADY_INITIALIZED)
	if err := ctx.Initialize(); err != nil {
		if p11err, ok := err.(pkcs11.Error); !ok || p11err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
		}
	}

	pool := &PKCS11SessionPool{
		ctx:       ctx,
		module:    modulePath,
		slotID:    slotID,
		pin:       pin,
		available: make([]pkcs11.SessionHandle, 0),
		inUse:     make(map[pkcs11.SessionHandle]bool),
	}

	globalPools[key] = pool
	return pool, nil
}

// Context returns the underlying PKCS#11 context.
func (p *PKCS11SessionPool) Context() *pkcs11.Ctx {
	return p.ctx
}

// SlotID returns the slot ID this pool is configured for.
func (p *PKCS11SessionPool) SlotID() uint {
	return p.slotID
}

// Acquire reserves a session from the pool.
// If no session is available, a new one is created.
// Returns the session handle and a release function that MUST be called when done.
// Usage:
//
//	session, release, err := pool.Acquire()
//	if err != nil { return err }
//	defer release()
//	// use session...
func (p *PKCS11SessionPool) Acquire() (pkcs11.SessionHandle, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, nil, fmt.Errorf("session pool is closed")
	}

	var session pkcs11.SessionHandle
	var err error

	// 1. Reuse an available session if possible
	if len(p.available) > 0 {
		session = p.available[len(p.available)-1]
		p.available = p.available[:len(p.available)-1]
	} else {
		// 2. Create a new session
		session, err = p.ctx.OpenSession(p.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to open session: %w", err)
		}

		// Login if not already done (login is per-token, not per-session)
		if p.pin != "" && !p.loginDone {
			if err := p.ctx.Login(session, pkcs11.CKU_USER, p.pin); err != nil {
				if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
					_ = p.ctx.CloseSession(session)
					return 0, nil, fmt.Errorf("failed to login: %w", err)
				}
			}
			p.loginDone = true
		}
	}

	p.inUse[session] = true

	// Release function returns session to pool
	release := func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		delete(p.inUse, session)

		if p.closed {
			// Pool is closing, just close the session
			_ = p.ctx.CloseSession(session)
			return
		}

		// Return to available pool
		p.available = append(p.available, session)
	}

	return session, release, nil
}

// Close closes all sessions and finalizes the module.
// This should be called at program shutdown.
func (p *PKCS11SessionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	return p.closeLocked()
}

// closeLocked closes all sessions and finalizes the module.
// Must be called with p.mu held.
func (p *PKCS11SessionPool) closeLocked() error {
	p.closed = true

	var errs []error

	// Logout first (once per token, on any session)
	if p.loginDone && (len(p.available) > 0 || len(p.inUse) > 0) {
		var anySession pkcs11.SessionHandle
		if len(p.available) > 0 {
			anySession = p.available[0]
		} else {
			for s := range p.inUse {
				anySession = s
				break
			}
		}
		if err := p.ctx.Logout(anySession); err != nil {
			if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_NOT_LOGGED_IN {
				errs = append(errs, fmt.Errorf("logout: %w", err))
			}
		}
	}

	// Close all available sessions
	for _, session := range p.available {
		if err := p.ctx.CloseSession(session); err != nil {
			errs = append(errs, fmt.Errorf("close available session: %w", err))
		}
	}

	// Close all in-use sessions (edge case - should not happen in normal use)
	for session := range p.inUse {
		if err := p.ctx.CloseSession(session); err != nil {
			errs = append(errs, fmt.Errorf("close in-use session: %w", err))
		}
	}

	// Finalize module
	if err := p.ctx.Finalize(); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED {
			errs = append(errs, fmt.Errorf("finalize: %w", err))
		}
	}

	p.ctx.Destroy()

	// Remove from global map
	globalPoolsMu.Lock()
	delete(globalPools, poolKey(p.module, p.slotID))
	globalPoolsMu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("errors closing pool: %v", errs)
	}
	return nil
}

// CloseAllPools closes all session pools.
// Use this for cleanup at program exit.
func CloseAllPools() {
	globalPoolsMu.Lock()
	pools := make([]*PKCS11SessionPool, 0, len(globalPools))
	for _, pool := range globalPools {
		pools = append(pools, pool)
	}
	globalPoolsMu.Unlock()

	for _, pool := range pools {
		_ = pool.Close()
	}
}

// =============================================================================
// Legacy API compatibility - used by GenerateHSMKeyPair, ListHSMKeys, etc.
// =============================================================================

// GetSessionPoolLegacy returns a pool using the legacy API.
// This creates a pool without slot/pin, requiring GetSession calls with those params.
// DEPRECATED: Use GetSessionPool with slot and pin directly.
func GetSessionPoolLegacy(modulePath string) (*PKCS11SessionPoolLegacy, error) {
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}

	// Initialize module (ignore CKR_CRYPTOKI_ALREADY_INITIALIZED)
	if err := ctx.Initialize(); err != nil {
		if p11err, ok := err.(pkcs11.Error); !ok || p11err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
		}
	}

	return &PKCS11SessionPoolLegacy{
		ctx:       ctx,
		module:    modulePath,
		sessions:  make(map[uint]pkcs11.SessionHandle),
		loginDone: make(map[uint]bool),
	}, nil
}

// PKCS11SessionPoolLegacy provides backwards compatibility for functions
// that need to work with multiple slots in a single operation.
type PKCS11SessionPoolLegacy struct {
	mu        sync.Mutex
	ctx       *pkcs11.Ctx
	module    string
	sessions  map[uint]pkcs11.SessionHandle // slot ID -> session
	loginDone map[uint]bool                 // slot ID -> logged in
	closed    bool
}

// Context returns the underlying PKCS#11 context.
func (p *PKCS11SessionPoolLegacy) Context() *pkcs11.Ctx {
	return p.ctx
}

// GetSession returns a session for the given slot (legacy API).
func (p *PKCS11SessionPoolLegacy) GetSession(slotID uint, pin string) (pkcs11.SessionHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, fmt.Errorf("session pool is closed")
	}

	// Return existing session if available
	if session, ok := p.sessions[slotID]; ok {
		// Login if needed and not already done
		if pin != "" && !p.loginDone[slotID] {
			if err := p.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
				if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
					return 0, fmt.Errorf("failed to login: %w", err)
				}
			}
			p.loginDone[slotID] = true
		}
		return session, nil
	}

	// Open new session
	session, err := p.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}

	p.sessions[slotID] = session

	// Login if pin provided
	if pin != "" {
		if err := p.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				_ = p.ctx.CloseSession(session)
				delete(p.sessions, slotID)
				return 0, fmt.Errorf("failed to login: %w", err)
			}
		}
		p.loginDone[slotID] = true
	}

	return session, nil
}

// GetReadOnlySession returns a read-only session for the given slot (legacy API).
func (p *PKCS11SessionPoolLegacy) GetReadOnlySession(slotID uint, pin string) (pkcs11.SessionHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, fmt.Errorf("session pool is closed")
	}

	// For read-only, we still use the same session if available
	if session, ok := p.sessions[slotID]; ok {
		if pin != "" && !p.loginDone[slotID] {
			if err := p.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
				if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
					return 0, fmt.Errorf("failed to login: %w", err)
				}
			}
			p.loginDone[slotID] = true
		}
		return session, nil
	}

	// Open read-only session
	session, err := p.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}

	p.sessions[slotID] = session

	if pin != "" {
		if err := p.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				_ = p.ctx.CloseSession(session)
				delete(p.sessions, slotID)
				return 0, fmt.Errorf("failed to login: %w", err)
			}
		}
		p.loginDone[slotID] = true
	}

	return session, nil
}

// Close closes all sessions but does NOT finalize the module.
// This is intentional: C_Finalize is a global operation that affects all PKCS#11 users.
// The module will be finalized by CloseAllPools() at program exit.
func (p *PKCS11SessionPoolLegacy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	var errs []error

	// Logout and close all sessions
	for slotID, session := range p.sessions {
		if p.loginDone[slotID] {
			if err := p.ctx.Logout(session); err != nil {
				if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_NOT_LOGGED_IN {
					errs = append(errs, fmt.Errorf("logout slot %d: %w", slotID, err))
				}
			}
		}
		if err := p.ctx.CloseSession(session); err != nil {
			errs = append(errs, fmt.Errorf("close session slot %d: %w", slotID, err))
		}
	}

	// NOTE: Do NOT call ctx.Finalize() here!
	// C_Finalize is a global operation that affects all PKCS#11 operations in the process.
	// If we finalize here, other pools using the same module will fail with CKR_CRYPTOKI_NOT_INITIALIZED.
	// The context is destroyed but the module remains initialized for other users.
	p.ctx.Destroy()

	if len(errs) > 0 {
		return fmt.Errorf("errors closing pool: %v", errs)
	}
	return nil
}
