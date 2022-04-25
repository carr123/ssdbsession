package ssdbsession

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/carr123/batchwriter"
	"github.com/gomodule/redigo/redis"
	uuid "github.com/google/uuid"
)

/*
1. 登录一次产生一个会话, 用会话ID标识，同一个账号登录多次会产生多个不同的会话ID。会话ID采用随机数,长度固定,且保证不重复
2. cookie由 会话ID和userid组成。cookie=sessid+userid
3. 缓存存储

缓存内容1 (目的是存放cookie时间戳):
key name = SSDB_SESSION_KEEPALIVE
ZSET 存放所有 cookie 值，带心跳时间戳, 定期刷新时间戳。过期的cookie则用程序去删除。

缓存内容2 （目的是判断cookie有无）:
key name = SSDB_SESSION_USER_<userid>
Hashmap 存储，一个userid对应一个hashmap,  存储该用户下所有登录的会话ID。
hashmap没有过期时间

缓存内容3 (存储cookie 应用层数据):
key name = SSDB_SESSION_DATA_<sessid>
Hashmap 存储，一个会话id 对应一个hashmap, 存储应用数据。
hashmap没有过期时间
*/

//如果CookieLife设置为0， 则在浏览器进程存在期间cookie有效，浏览器关闭后cookie即失效

//后端存储层可以使用redis或者SSDB

//////////////////////////////////////////////////////////////////////////
const MIN_SESS_LEN int = 48
const SECRETKEY string = "AILTFG784084FPGVB"

type SessionMgr struct {
	CookieName      string
	CookieLifeTime  int
	SessionLifetime int
	Secure          bool
	Domain          string
	Pool            *redis.Pool
	memCache        gcache.Cache
	heartbeatwriter *batchwriter.AsyncBatchWriter
}

func New(RedisAddr string, Pass string, CookieName string, CookieLifeSeconds int, SessionLifeSeconds int, Secure bool, szdomain string) (*SessionMgr, error) {
	redispool := redisPoolInit(RedisAddr, Pass)
	conn := redispool.Get()
	defer conn.Close()
	_, err := redis.String(conn.Do("PING"))
	if err != nil {
		return nil, err
	}

	if SessionLifeSeconds < 60 || SessionLifeSeconds > 15552000 {
		return nil, fmt.Errorf("SessionLifeSeconds should between [60,15552000]")
	}

	bw := batchwriter.NewAsyncBatchWriter(20000, 20000, time.Second*60)
	bw.BatchWrite = func(arr []interface{}) {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
			}
		}()

		arglist := make([]interface{}, 0, 1+len(arr))
		arglist = append(arglist, "SSDB_SESSION_KEEPALIVE")
		for _, item := range arr {
			arglist = append(arglist, item.([]interface{})...)
		}

		c := redispool.Get()
		defer c.Close()
		c.Do("zadd", arglist...)
	}

	mgr := &SessionMgr{
		CookieName:      CookieName,
		CookieLifeTime:  CookieLifeSeconds,
		SessionLifetime: SessionLifeSeconds,
		Secure:          Secure,
		Domain:          szdomain,
		Pool:            redispool,
		memCache:        gcache.New(300000).LRU().Build(),
		heartbeatwriter: bw,
	}

	go mgr.__gc()

	return mgr, nil
}

func redisPoolInit(server, password string) *redis.Pool {
	pool := &redis.Pool{
		MaxIdle:     2,
		IdleTimeout: 50 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			if len(password) != 0 {
				if _, err := c.Do("AUTH", password); err != nil {
					c.Close()
					return nil, err
				}
			}
			return c, err
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}

	return pool
}

//登录后创建新cookie,存入缓存
//48 bytes + userid
func (s *SessionMgr) NewSession(userid string) (string, error) {
	id1, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	randstr := hex.EncodeToString(id1[:]) //32 bytes
	sessID := randstr + calcSig(randstr)  //32 bytes + 16 bytes

	if len(userid) == 0 {
		id2, err := uuid.NewUUID()
		if err != nil {
			return "", err
		}
		userid = hex.EncodeToString(id2[:])
	}

	session := sessID + userid //48 bytes + userid

	conn := s.Pool.Get()
	defer conn.Close()

	if _, err := conn.Do("zadd", "SSDB_SESSION_KEEPALIVE", time.Now().Unix(), session); err != nil {
		return "", err
	}

	if _, err := conn.Do("hset", "SSDB_SESSION_USER_"+userid, sessID, time.Now().Unix()); err != nil {
		return "", err
	}

	s.memCache.SetWithExpire(session, int64(1), time.Second*5)

	return session, nil
}

//校验session是否有效
func (s *SessionMgr) IsSessionValid(session string) (bool, error) {
	if len(session) == 0 {
		return false, nil
	}

	if s.memCache.Has(session) {
		return true, nil
	}

	if len(session) <= MIN_SESS_LEN {
		return false, nil
	}

	if calcSig(session[:32]) != session[32:48] {
		return false, nil
	}

	sessid := session[:MIN_SESS_LEN]
	userid := session[MIN_SESS_LEN:]

	conn := s.Pool.Get()
	defer conn.Close()

	bExist, err := redis.Bool(conn.Do("hexists", "SSDB_SESSION_USER_"+userid, sessid))
	if err != nil {
		return false, err
	}

	if bExist {
		s.memCache.SetWithExpire(session, int64(1), time.Second*5)
	}

	return bExist, nil
}

//每次访问后调用该函数，重新设置session生命期
func (s *SessionMgr) SessionKeepAlive(session string, lastAccessTime int64) {
	s.heartbeatwriter.PostMessageUnique(session, []interface{}{lastAccessTime, session})
}

//退出登录后删除session
func (s *SessionMgr) DelSession(session string) error {
	bExist, err := s.IsSessionValid(session)
	if err != nil {
		return err
	}
	if !bExist {
		return nil
	}

	var nTimeDue int64
	nTimeDue = time.Now().Unix() - int64(s.SessionLifetime) + 30 //延迟30秒后, GC会彻底删除登录信息

	conn := s.Pool.Get()
	defer conn.Close()

	sessID := session[:MIN_SESS_LEN]
	userid := session[MIN_SESS_LEN:]
	if _, err := conn.Do("hdel", "SSDB_SESSION_USER_"+userid, sessID); err != nil {
		return err
	}

	s.memCache.Remove(session)

	if _, err := conn.Do("zadd", "SSDB_SESSION_KEEPALIVE", nTimeDue, session); err != nil {
		return err
	}

	if err := s.__delSessionData(conn, session); err != nil {
		return err
	}

	s.SessionKeepAlive(session, nTimeDue)

	return nil
}

//从cookie中提取session
func (s *SessionMgr) GetCookie(r *http.Request) string {
	var szCookie string
	var err error

	cookie, err := r.Cookie(s.CookieName)
	if err != nil {
		return szCookie
	}

	szCookie, err = url.QueryUnescape(cookie.Value)
	if err != nil {
		return szCookie
	}

	return szCookie
}

func (s *SessionMgr) SetCookie(w http.ResponseWriter, r *http.Request, szCookie string) error {
	cookie := &http.Cookie{
		Name:     s.CookieName,
		Value:    url.QueryEscape(szCookie),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		Domain:   s.Domain,
	}

	if s.CookieLifeTime >= 0 {
		cookie.MaxAge = s.CookieLifeTime
	}

	http.SetCookie(w, cookie)
	r.AddCookie(cookie)

	return nil
}

//清除浏览器cookie
func (s *SessionMgr) DelCookie(w http.ResponseWriter, r *http.Request) {
	expiration := time.Now().AddDate(-1, 0, 0)
	cookie := &http.Cookie{
		Name:     s.CookieName,
		Path:     "/",
		Value:    "",
		HttpOnly: true,
		Expires:  expiration,
		MaxAge:   0}

	http.SetCookie(w, cookie)
}

func (s *SessionMgr) SetSessionValue(session string, kvs ...interface{}) error {
	if valid, err := s.IsSessionValid(session); err != nil {
		return err
	} else if !valid {
		return fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]
	args := make([]interface{}, 0, 1+len(kvs))
	args = append(args, szDataKey)
	args = append(args, kvs...)

	conn := s.Pool.Get()
	defer conn.Close()

	if _, err := conn.Do("hmset", args...); err != nil {
		return err
	}

	return nil
}

func (s *SessionMgr) DelSessionValue(session string, keys ...interface{}) error {
	if valid, err := s.IsSessionValid(session); err != nil {
		return err
	} else if !valid {
		return fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]
	args := make([]interface{}, 0, 1+len(keys))
	args = append(args, szDataKey)
	args = append(args, keys...)

	conn := s.Pool.Get()
	defer conn.Close()

	if _, err := conn.Do("hdel", args...); err != nil {
		return err
	}

	return nil
}

func (s *SessionMgr) GetSessionAllKeys(session string) ([]string, error) {
	if valid, err := s.IsSessionValid(session); err != nil {
		return nil, err
	} else if !valid {
		return nil, fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]
	conn := s.Pool.Get()
	defer conn.Close()

	return redis.Strings(conn.Do("hkeys", szDataKey))
}

func (s *SessionMgr) GetSessionString(session string, key string) (string, error) {
	if valid, err := s.IsSessionValid(session); err != nil {
		return "", err
	} else if !valid {
		return "", fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]

	conn := s.Pool.Get()
	defer conn.Close()

	return redis.String(conn.Do("hget", szDataKey, key))
}

func (s *SessionMgr) GetSessionInt64(session string, key string) (int64, error) {
	if valid, err := s.IsSessionValid(session); err != nil {
		return 0, err
	} else if !valid {
		return 0, fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]

	conn := s.Pool.Get()
	defer conn.Close()

	return redis.Int64(conn.Do("hget", szDataKey, key))
}

func (s *SessionMgr) GetSessionFloat64(session string, key string) (float64, error) {
	if valid, err := s.IsSessionValid(session); err != nil {
		return 0, err
	} else if !valid {
		return 0, fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]

	conn := s.Pool.Get()
	defer conn.Close()

	return redis.Float64(conn.Do("hget", szDataKey, key))
}

func (s *SessionMgr) GetSessionBool(session string, key string) (bool, error) {
	if valid, err := s.IsSessionValid(session); err != nil {
		return false, err
	} else if !valid {
		return false, fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]

	conn := s.Pool.Get()
	defer conn.Close()

	return redis.Bool(conn.Do("hget", szDataKey, key))
}

func (s *SessionMgr) GetSessionBytes(session string, key string) ([]byte, error) {
	if valid, err := s.IsSessionValid(session); err != nil {
		return nil, err
	} else if !valid {
		return nil, fmt.Errorf("invalid session:%s", session)
	}

	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]

	conn := s.Pool.Get()
	defer conn.Close()

	return redis.Bytes(conn.Do("hget", szDataKey, key))
}

func (s *SessionMgr) GetAllSessionByUserID(userid string) ([]string, error) {
	conn := s.Pool.Get()
	defer conn.Close()

	sid, err := redis.Strings(conn.Do("hkeys", "SSDB_SESSION_USER_"+userid))
	if err != nil {
		return nil, err
	}

	sessions := make([]string, 0, len(sid))
	for _, item := range sid {
		sessions = append(sessions, item+userid)
	}

	return sessions, nil
}

func (s *SessionMgr) DelAllSessionByUserID(userid string) error {
	var err error

	sessions, err := s.GetAllSessionByUserID(userid)
	if err != nil {
		return err
	}

	for _, item := range sessions {
		if e := s.DelSession(item); e != nil {
			err = e
		}
	}

	return err
}

func (s *SessionMgr) __delSessionData(conn redis.Conn, session string) error {
	szDataKey := "SSDB_SESSION_DATA_" + session[:MIN_SESS_LEN]

	fields, err := redis.Strings(conn.Do("hkeys", szDataKey))
	if err != nil {
		return err
	}

	if len(fields) == 0 {
		return nil
	}

	arglist := make([]interface{}, 0, 1+len(fields))
	arglist = append(arglist, szDataKey)
	for _, field := range fields {
		arglist = append(arglist, field)
	}

	if _, err := conn.Do("hdel", arglist...); err != nil {
		return err
	}
	return nil
}

func (s *SessionMgr) __gc() {

	cleanSession_batch := func() bool {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
			}
		}()

		var bContinue bool = false

		score_end := time.Now().Unix() - int64(s.SessionLifetime)
		nMaxCount := 2000

		conn := s.Pool.Get()
		defer conn.Close()

		keys, err := redis.Strings(conn.Do("zrangebyscore", "SSDB_SESSION_KEEPALIVE", 0, score_end, "limit", 0, nMaxCount))
		if err != nil {
			log.Println(err)
			return bContinue
		}

		if len(keys) == 0 {
			return bContinue
		}

		for _, session := range keys {
			sessID := session[:MIN_SESS_LEN]
			userid := session[MIN_SESS_LEN:]
			if _, err := conn.Do("hdel", "SSDB_SESSION_USER_"+userid, sessID); err != nil {
				log.Println(err)
				return bContinue
			}

			s.memCache.Remove(session)

			if err := s.__delSessionData(conn, session); err != nil {
				log.Println(err)
				return bContinue
			}
		}

		arglist := make([]interface{}, 0, 1+len(keys))
		arglist = append(arglist, "SSDB_SESSION_KEEPALIVE")
		for _, key := range keys {
			arglist = append(arglist, key)
		}

		if _, err := conn.Do("zrem", arglist...); err != nil {
			log.Println(err)
			return bContinue
		}

		if len(keys) == nMaxCount {
			bContinue = true
		}

		return bContinue
	}

	doclean := func() {
		for {
			if !cleanSession_batch() {
				return
			}
			time.Sleep(time.Second)
		}
	}

	time.Sleep(time.Second)
	for {
		doclean()
		time.Sleep(time.Second * 60)
	}
}

func getIP(r *http.Request) string {
	requester := r.Header.Get("X-Real-IP")
	// if the requester-header is empty, check the forwarded-header
	if len(requester) == 0 {
		requester = r.Header.Get("X-Forwarded-For")
	}
	// if the requester is still empty, use the hard-coded address from the socket
	if len(requester) == 0 {
		requester = strings.Split(r.RemoteAddr, ":")[0]
	}
	return requester
}

func calcSig(randstr string) string {
	t := sha1.New()
	t.Write([]byte(randstr + SECRETKEY))
	return hex.EncodeToString(t.Sum(nil))[:16]
}
