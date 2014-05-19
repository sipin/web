package web

import (
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/sipin/web/randbo"
)

var SessionKey string = "ZQSESSID"
var sessionIDLen int = 36

type ISessionStorage interface {
	SetSession(sessionID string, key string, data []byte)
	GetSession(sessionID string, key string) []byte
	ClearSession(sessionID string, key string)
}

func newSessionID() string {
	return randbo.GenString(sessionIDLen / 2)
}

func (ctx *Context) SetSession(key string, data []byte) {
	ctx.Server.SessionStorage.SetSession(ctx.GetSessionID(), key, data)
}

func (ctx *Context) GetSession(key string) []byte {
	return ctx.Server.SessionStorage.GetSession(ctx.GetSessionID(), key)
}

func (ctx *Context) ClearSession(key string) {
	ctx.Server.SessionStorage.ClearSession(ctx.GetSessionID(), key)
}

func (ctx *Context) AbandonSession() {
	ctx.RemoveCookie(SessionKey)
	return
}

func (ctx *Context) SetNewSessionID() (sessionID string) {
	sessionID = newSessionID()
	ctx.newSessionID = sessionID
	ctx.SetCookie(NewSessionCookie(SessionKey, sessionID))
	return
}

// SetCookie adds a cookie header to the response.
func (ctx *Context) GetSessionID() (sessionID string) {
	cookie, _ := ctx.Request.Cookie(SessionKey)
	if cookie != nil && len(cookie.Value) == sessionIDLen {
		return cookie.Value
	}

	if ctx.newSessionID != "" {
		return ctx.newSessionID
	}

	return ctx.SetNewSessionID()
}

// Simple session storage using memory, handy for development
// **NEVER** use it in production!!!
type memoryStore struct {
	data map[string][]byte
}

var MemoryStore = &memoryStore{
	data: make(map[string][]byte),
}

func (ms *memoryStore) SetSession(sessionID string, key string, data []byte) {
	ms.data[sessionID+key] = data
}

func (ms *memoryStore) GetSession(sessionID string, key string) []byte {
	data, _ := ms.data[sessionID+key]
	return data
}

func (ms *memoryStore) ClearSession(sessionID string, key string) {
	delete(ms.data, sessionID+key)
}

// Memcache session storage
type memcacheStore struct {
	mc *memcache.Client
}

func NewMemcacheStore(servers ...string) *memcacheStore {
	ms := &memcacheStore{}
	ms.mc = memcache.New(servers...)
	return ms
}

func (ms *memcacheStore) SetSession(sessionID string, key string, data []byte) {
	item := &memcache.Item{Key: sessionID + key, Value: data}
	err := ms.mc.Set(item)
	if err != nil {
		panic(err)
	}
}

func (ms *memcacheStore) GetSession(sessionID string, key string) []byte {
	item, err := ms.mc.Get(sessionID + key)
	if err == memcache.ErrCacheMiss {
		return nil
	}
	if err != nil {
		panic(err)
	}
	return item.Value
}

func (ms *memcacheStore) ClearSession(sessionID string, key string) {
	err := ms.mc.Delete(sessionID + key)
	if err == memcache.ErrCacheMiss {
		return
	}
	panic(err)
}
