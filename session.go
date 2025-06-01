package session

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ClientSession struct {
	SessionID         uuid.UUID
	Username          string
	AssignedIP        net.IP
	UDPAddr           *net.UDPAddr // The client's current UDP source address for data traffic
	SessionKey        []byte       // AES-GCM key for data
	LastReceivedCounter uint32
	LastActivity      time.Time
	IsActive          bool // True if has sent initial UDP packet
}

type SessionManager struct {
	sync.RWMutex
	activeSessions       map[uuid.UUID]*ClientSession      // SessionID -> Session
	pendingSessions      map[uuid.UUID]*ClientSession      // SessionID -> Session (SSH auth done, awaiting first UDP packet)
	udpAddrToSessionID   map[string]uuid.UUID              // UDPAddr.String() -> SessionID
	assignedIPToSessionID map[string]uuid.UUID             // AssignedIP.String() -> SessionID
	usernameToSessionID  map[string]uuid.UUID              // Username -> SessionID
	sessionTimeout       time.Duration
	ipRelease            func(string) // Callback to release IP in IP pool
}

func NewSessionManager(timeoutSeconds int, ipReleaseCallback func(string)) *SessionManager {
	return &SessionManager{
		activeSessions:       make(map[uuid.UUID]*ClientSession),
		pendingSessions:      make(map[uuid.UUID]*ClientSession),
		udpAddrToSessionID:   make(map[string]uuid.UUID),
		assignedIPToSessionID: make(map[string]uuid.UUID),
		usernameToSessionID:  make(map[string]uuid.UUID),
		sessionTimeout:       time.Duration(timeoutSeconds) * time.Second,
		ipRelease:            ipReleaseCallback,
	}
}

// AddPending adds a session that has completed SSH authentication, awaiting first UDP packet.
func (sm *SessionManager) AddPending(session *ClientSession) {
	sm.Lock()
	defer sm.Unlock()

	// If a session for this user already exists, remove it first
	if oldSessionID, ok := sm.usernameToSessionID[session.Username]; ok {
		sm.removeSession(oldSessionID) // Remove old session state
		log.Printf("Replacing existing session for user %s (old ID: %s)", session.Username, oldSessionID)
	}

	sm.pendingSessions[session.SessionID] = session
	sm.usernameToSessionID[session.Username] = session.SessionID
	log.Printf("Added pending session for user %s (ID: %s)", session.Username, session.SessionID)
}

// Activate moves a pending session to active after the first UDP packet is received.
func (sm *SessionManager) Activate(sessionID uuid.UUID, clientUDPAddr *net.UDPAddr) (*ClientSession, error) {
	sm.Lock()
	defer sm.Unlock()

	session, ok := sm.pendingSessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session ID %s not found in pending sessions", sessionID)
	}

	delete(sm.pendingSessions, sessionID) // Remove from pending
	session.UDPAddr = clientUDPAddr
	session.LastActivity = time.Now()
	session.IsActive = true
	sm.activeSessions[sessionID] = session // Add to active

	sm.udpAddrToSessionID[clientUDPAddr.String()] = sessionID
	sm.assignedIPToSessionID[session.AssignedIP.String()] = sessionID

	log.Printf("Activated session for user %s (ID: %s) from pending, UDP addr: %s", session.Username, session.SessionID, clientUDPAddr)
	return session, nil
}

// GetBySessionID retrieves a session by its UUID.
func (sm *SessionManager) GetBySessionID(sessionID uuid.UUID) (*ClientSession, bool) {
	sm.RLock()
	defer sm.RUnlock()
	session, ok := sm.activeSessions[sessionID]
	if !ok {
		session, ok = sm.pendingSessions[sessionID] // Check pending too, for data_init
	}
	return session, ok
}

// GetByUDPAddr retrieves an active session by its UDP client address.
func (sm *SessionManager) GetByUDPAddr(addr *net.UDPAddr) (*ClientSession, bool) {
	sm.RLock()
	defer sm.RUnlock()
	sessionID, ok := sm.udpAddrToSessionID[addr.String()]
	if !ok {
		return nil, false
	}
	session, ok := sm.activeSessions[sessionID]
	if !ok {
		// This should theoretically not happen if udpAddrToSessionID only stores active sessions
		return nil, false
	}
	session.LastActivity = time.Now() // Update activity on read
	return session, true
}

// GetByAssignedIP retrieves an active session by its assigned VPN IP.
func (sm *SessionManager) GetByAssignedIP(ip net.IP) (*ClientSession, bool) {
	sm.RLock()
	defer sm.RUnlock()
	sessionID, ok := sm.assignedIPToSessionID[ip.String()]
	if !ok {
		return nil, false
	}
	session, ok := sm.activeSessions[sessionID]
	if !ok {
		return nil, false
	}
	session.LastActivity = time.Now() // Update activity on read
	return session, true
}

// removeSession is an internal helper to clean up all mappings for a session.
func (sm *SessionManager) removeSession(sessionID uuid.UUID) {
	session, ok := sm.activeSessions[sessionID]
	if !ok {
		session, ok = sm.pendingSessions[sessionID]
		if !ok {
			return // Session not found
		}
		delete(sm.pendingSessions, sessionID)
	} else {
		delete(sm.activeSessions, sessionID)
		delete(sm.udpAddrToSessionID, session.UDPAddr.String())
		delete(sm.assignedIPToSessionID, session.AssignedIP.String())
	}
	delete(sm.usernameToSessionID, session.Username)
	sm.ipRelease(session.Username) // Release IP back to pool
	log.Printf("Removed session for user %s (ID: %s), assigned IP %s", session.Username, sessionID, session.AssignedIP)
}

// CleanupInactiveSessions periodically removes expired sessions.
func (sm *SessionManager) CleanupInactiveSessions() {
	ticker := time.NewTicker(sm.sessionTimeout / 2) // Check every half timeout
	defer ticker.Stop()

	for range ticker.C {
		sm.Lock()
		now := time.Now()
		for id, s := range sm.activeSessions {
			if now.Sub(s.LastActivity) > sm.sessionTimeout {
				log.Printf("Session %s for user %s timed out due to inactivity.", id, s.Username)
				sm.removeSession(id)
			}
		}
		// Also clean up old pending sessions if they never activate (e.g., client crashed after SSH auth)
		for id, s := range sm.pendingSessions {
			if now.Sub(s.LastActivity) > sm.sessionTimeout*2 { // Give pending a bit more time
				log.Printf("Pending session %s for user %s timed out without activation.", id, s.Username)
				sm.removeSession(id)
			}
		}
		sm.Unlock()
	}
}
