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
// It maintains one session per slot and handles login state.
// This is a singleton per module path to avoid C_Finalize() issues.
type PKCS11SessionPool struct {
	mu        sync.Mutex
	ctx       *pkcs11.Ctx
	module    string
	sessions  map[uint]pkcs11.SessionHandle // slot ID -> session
	loginDone map[uint]bool                 // slot ID -> logged in
	refCount  int                           // number of active references
	closed    bool
}

var (
	globalPools   = make(map[string]*PKCS11SessionPool)
	globalPoolsMu sync.Mutex
)

// GetSessionPool returns the session pool for a PKCS#11 module.
// If the pool doesn't exist, it creates one and initializes the module.
// Each call increments the reference count; call Release() when done.
func GetSessionPool(modulePath string) (*PKCS11SessionPool, error) {
	globalPoolsMu.Lock()
	defer globalPoolsMu.Unlock()

	// Return existing pool if available
	if pool, ok := globalPools[modulePath]; ok {
		pool.mu.Lock()
		if pool.closed {
			pool.mu.Unlock()
			// Pool was closed, create a new one
			delete(globalPools, modulePath)
		} else {
			pool.refCount++
			pool.mu.Unlock()
			return pool, nil
		}
	}

	// Create new pool
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
		sessions:  make(map[uint]pkcs11.SessionHandle),
		loginDone: make(map[uint]bool),
		refCount:  1,
	}

	globalPools[modulePath] = pool
	return pool, nil
}

// Context returns the underlying PKCS#11 context.
func (p *PKCS11SessionPool) Context() *pkcs11.Ctx {
	return p.ctx
}

// GetSession returns a session for the given slot.
// If no session exists for this slot, one is created.
// If pin is provided and not already logged in, it logs in.
func (p *PKCS11SessionPool) GetSession(slotID uint, pin string) (pkcs11.SessionHandle, error) {
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

// GetReadOnlySession returns a read-only session for the given slot.
// Used for listing operations that don't need write access.
func (p *PKCS11SessionPool) GetReadOnlySession(slotID uint, pin string) (pkcs11.SessionHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, fmt.Errorf("session pool is closed")
	}

	// For read-only, we still use the same session if available
	// PKCS#11 sessions can do both read and write operations
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

// Release decrements the reference count.
// When the count reaches zero, the pool is closed.
func (p *PKCS11SessionPool) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.refCount--
	if p.refCount > 0 {
		return nil
	}

	return p.closeLocked()
}

// ForceClose closes the pool regardless of reference count.
// Use this for cleanup in tests or shutdown.
func (p *PKCS11SessionPool) ForceClose() error {
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

	// Finalize module
	if err := p.ctx.Finalize(); err != nil {
		errs = append(errs, fmt.Errorf("finalize: %w", err))
	}

	p.ctx.Destroy()

	// Remove from global map
	globalPoolsMu.Lock()
	delete(globalPools, p.module)
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
		_ = pool.ForceClose()
	}
}
