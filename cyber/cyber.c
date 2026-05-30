/*
 * cyber.c — Python C extension: libcurl with socketpair injection
 *
 * Feeds a crafted HTTP response directly to libcurl in-process,
 * so the full curl HTTP parser runs under ASan/UBSan.
 *
 * Debug logging: set CYBER_DEBUG=1 in the environment.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <curl/curl.h>

#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* debug logging                                                        */
/* ------------------------------------------------------------------ */

static int g_debug = 0;   /* set once at module init from CYBER_DEBUG */

#define CYBER_LOG(fmt, ...) \
    do { if (g_debug) fprintf(stderr, "[cyber] " fmt "\n", ##__VA_ARGS__); } while (0)

/* ------------------------------------------------------------------ */
/* growable write buffer                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char *data;
    size_t         len;
    size_t         cap;
} Buffer;

static void buf_init(Buffer *b)
{
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

static void buf_free(Buffer *b)
{
    free(b->data);
    buf_init(b);
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    Buffer *b   = (Buffer *)userdata;
    size_t  n   = size * nmemb;

    if (b->len + n > b->cap) {
        size_t newcap = (b->cap == 0) ? 4096 : b->cap * 2;
        while (newcap < b->len + n) newcap *= 2;
        unsigned char *tmp = realloc(b->data, newcap);
        if (!tmp) return 0;           /* signal error to curl */
        b->data = tmp;
        b->cap  = newcap;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    CYBER_LOG("write_cb: received %zu bytes (total %zu)", n, b->len);
    return n;
}

/* ------------------------------------------------------------------ */
/* socketpair writer thread                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    int            fd;          /* sv[1]: peer end of socketpair */
    const char    *data;
    size_t         len;
} WriterArgs;

static void *writer_thread(void *arg)
{
    WriterArgs *wa  = (WriterArgs *)arg;

    CYBER_LOG("writer: started on fd=%d, response_len=%zu", wa->fd, wa->len);

    /* First, drain whatever curl sends (its HTTP request).
     * We discard the request — we only care about exercising curl's
     * *response* parser.  Read until we see end-of-headers (\r\n\r\n)
     * or hit EOF / an error.  Use non-blocking peek so we don't stall
     * if curl sends a very short request or no body.                   */
    char drain[4096];
    int  found_eoh = 0;
    /* A short spin-drain: read until we see \r\n\r\n in the stream.
     * Cap at 128 KiB to avoid spinning forever on malformed input.     */
    size_t total_drained = 0;
    while (!found_eoh && total_drained < (128 * 1024)) {
        ssize_t n = read(wa->fd, drain, sizeof(drain));
        if (n <= 0) break;        /* EOF or error — proceed anyway */
        total_drained += (size_t)n;
        CYBER_LOG("writer: drained %zd bytes (total %zu)", n, total_drained);
        /* Crude scan: look for \r\n\r\n anywhere in the last chunk.    */
        if (n >= 4) {
            for (ssize_t i = 0; i <= n - 4; i++) {
                if (drain[i]   == '\r' && drain[i+1] == '\n' &&
                    drain[i+2] == '\r' && drain[i+3] == '\n') {
                    found_eoh = 1;
                    break;
                }
            }
        }
        if (found_eoh) break;
    }

    CYBER_LOG("writer: request drained (%zu bytes), found_eoh=%d; writing response",
              total_drained, found_eoh);

    /* Now write the crafted response back to curl. */
    size_t sent = 0;
    while (sent < wa->len) {
        ssize_t n = write(wa->fd, wa->data + sent, wa->len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            CYBER_LOG("writer: write error after %zu bytes: %s", sent, strerror(errno));
            break;
        }
        sent += (size_t)n;
    }
    CYBER_LOG("writer: wrote %zu/%zu response bytes; closing fd=%d", sent, wa->len, wa->fd);
    close(wa->fd);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* libcurl callbacks                                                    */
/* ------------------------------------------------------------------ */

/* curl asks us to open a socket — return the pre-created socketpair fd */
static curl_socket_t opensocket_cb(void *clientp,
                                   curlsocktype purpose,
                                   struct curl_sockaddr *address)
{
    (void)purpose;
    (void)address;
    curl_socket_t *fdp = (curl_socket_t *)clientp;
    CYBER_LOG("opensocket_cb: returning fd=%d", (int)*fdp);
    return *fdp;
}

/* curl asks us to set socket options — tell it the socket is already
 * connected so it skips the actual connect() call                     */
static int sockopt_cb(void *clientp, curl_socket_t curlfd,
                      curlsocktype purpose)
{
    (void)clientp;
    (void)curlfd;
    (void)purpose;
    CYBER_LOG("sockopt_cb: returning CURL_SOCKOPT_ALREADY_CONNECTED");
    return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/* curl asks us to close a socket — we already closed sv[0] after
 * handing it off, so this is a no-op                                  */
static int closesocket_cb(void *clientp, curl_socket_t item)
{
    (void)clientp;
    CYBER_LOG("closesocket_cb: no-op for fd=%d", (int)item);
    return 0;
}

/* ------------------------------------------------------------------ */
/* shared handle-setup helper                                           */
/* ------------------------------------------------------------------ */

/* Apply all standard options to an easy handle.
 * curl_fd must be the sv[0] end of a pre-created socketpair.
 * resolve_list is a caller-allocated slist (caller frees it).
 * body_buf must outlive the perform call.                             */
static void setup_easy(CURL *easy,
                       const char *url,
                       curl_socket_t *curl_fd_ptr,
                       struct curl_slist *resolve_list,
                       Buffer *body_buf)
{
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_RESOLVE,              resolve_list);
    curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION,   opensocket_cb);
    curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA,       curl_fd_ptr);
    curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION,      sockopt_cb);
    curl_easy_setopt(easy, CURLOPT_SOCKOPTDATA,          NULL);
    curl_easy_setopt(easy, CURLOPT_CLOSESOCKETFUNCTION,  closesocket_cb);
    curl_easy_setopt(easy, CURLOPT_CLOSESOCKETDATA,      NULL);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION,        write_cb);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA,            body_buf);
    curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING,      "");
    curl_easy_setopt(easy, CURLOPT_COOKIEFILE,           "");
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER,       0L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST,       0L);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION,       1L);
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS,            5L);
    curl_easy_setopt(easy, CURLOPT_UNRESTRICTED_AUTH,    1L);
    curl_easy_setopt(easy, CURLOPT_HTTPAUTH,             CURLAUTH_ANY);
    curl_easy_setopt(easy, CURLOPT_PROXYAUTH,            CURLAUTH_ANY);
    curl_easy_setopt(easy, CURLOPT_HSTS,                 "");
    curl_easy_setopt(easy, CURLOPT_ALTSVC,               "");
    curl_easy_setopt(easy, CURLOPT_ALTSVC_CTRL,
                     (long)(CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3));
    curl_easy_setopt(easy, CURLOPT_TRANSFER_ENCODING,    1L);
    curl_easy_setopt(easy, CURLOPT_VERBOSE,              1L);
    curl_easy_setopt(easy, CURLOPT_HTTP_VERSION,
                     (long)CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE,        1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPIDLE,         30L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL,        10L);
    curl_easy_setopt(easy, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
    curl_easy_setopt(easy, CURLOPT_WILDCARDMATCH,        0L);
    curl_easy_setopt(easy, CURLOPT_PATH_AS_IS,           1L);
    curl_easy_setopt(easy, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 200L);
}

/* Build a result dict from a completed perform.  Frees body_buf. */
static PyObject *make_result(CURLcode rc, Buffer *body_buf)
{
    const char *err_str = curl_easy_strerror(rc);
    PyObject *result = PyDict_New();
    if (!result) { buf_free(body_buf); return NULL; }

    PyObject *py_body = PyBytes_FromStringAndSize(
        body_buf->data ? (const char *)body_buf->data : "",
        (Py_ssize_t)body_buf->len);
    buf_free(body_buf);

    PyObject *py_rc  = PyLong_FromLong((long)rc);
    PyObject *py_err = PyUnicode_FromString(err_str);
    if (!py_body || !py_rc || !py_err) {
        Py_XDECREF(py_body); Py_XDECREF(py_rc); Py_XDECREF(py_err);
        Py_DECREF(result);
        return NULL;
    }
    PyDict_SetItemString(result, "body",      py_body);
    PyDict_SetItemString(result, "exit_code", py_rc);
    PyDict_SetItemString(result, "error",     py_err);
    Py_DECREF(py_body); Py_DECREF(py_rc); Py_DECREF(py_err);
    return result;
}

/* ------------------------------------------------------------------ */
/* cyber_fetch(url: str, response: bytes) -> dict                      */
/* ------------------------------------------------------------------ */

static PyObject *cyber_fetch(PyObject *self, PyObject *args)
{
    (void)self;

    const char *url      = NULL;
    const char *resp_buf = NULL;
    Py_ssize_t  resp_len = 0;

    if (!PyArg_ParseTuple(args, "sy#", &url, &resp_buf, &resp_len))
        return NULL;

    CYBER_LOG("fetch: url=%s response_len=%zd", url, (ssize_t)resp_len);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }
    CYBER_LOG("fetch: socketpair sv[0]=%d sv[1]=%d", sv[0], sv[1]);

    WriterArgs wa = { .fd = sv[1], .data = resp_buf, .len = (size_t)resp_len };
    pthread_t tid;
    if (pthread_create(&tid, NULL, writer_thread, &wa) != 0) {
        close(sv[0]); close(sv[1]);
        PyErr_SetString(PyExc_RuntimeError, "pthread_create failed"); return NULL;
    }

    CURL *easy = curl_easy_init();
    if (!easy) {
        pthread_join(tid, NULL); close(sv[0]);
        PyErr_SetString(PyExc_RuntimeError, "curl_easy_init failed"); return NULL;
    }

    Buffer body; buf_init(&body);
    curl_socket_t curl_fd = sv[0];

    struct curl_slist *resolve_list = NULL;
    resolve_list = curl_slist_append(resolve_list, "x.test:80:127.0.0.1");
    resolve_list = curl_slist_append(resolve_list, "x.test:443:127.0.0.1");

    setup_easy(easy, url, &curl_fd, resolve_list, &body);

    CYBER_LOG("fetch: calling curl_easy_perform");
    CURLcode rc = curl_easy_perform(easy);
    CYBER_LOG("fetch: rc=%d body=%zu", (int)rc, body.len);

    curl_easy_cleanup(easy);
    curl_slist_free_all(resolve_list);
    pthread_join(tid, NULL);
    close(sv[0]);

    return make_result(rc, &body);
}

/* ------------------------------------------------------------------ */
/* cyber_dupfetch(parent_url, parent_resp, clone_url, clone_resp)      */
/*   -> {"parent": dict, "clone": dict, "hsts_enforced": bool}         */
/*                                                                      */
/* Reproduces the curl_easy_duphandle HSTS-bypass:                     */
/*   1. parent handle receives a response with Strict-Transport-       */
/*      Security header → runtime entry added to data->hsts            */
/*   2. curl_easy_duphandle() is called — the clone's HSTS table is    */
/*      populated only via Curl_hsts_loadfile/Curl_hsts_loadcb, so     */
/*      the runtime-learned entry is absent in the clone               */
/*   3. clone handle fetches clone_url (plain HTTP) — if the bug is    */
/*      present, the request succeeds (hsts_enforced=false); after the */
/*      fix the request should be blocked/upgraded (hsts_enforced=true)*/
/* ------------------------------------------------------------------ */

static PyObject *cyber_dupfetch(PyObject *self, PyObject *args)
{
    (void)self;

    const char *parent_url = NULL,  *clone_url = NULL;
    const char *parent_buf = NULL,  *clone_buf = NULL;
    Py_ssize_t  parent_len = 0,      clone_len = 0;

    if (!PyArg_ParseTuple(args, "sy#sy#",
                          &parent_url, &parent_buf, &parent_len,
                          &clone_url,  &clone_buf,  &clone_len))
        return NULL;

    CYBER_LOG("dupfetch: parent=%s clone=%s", parent_url, clone_url);

    /* ── parent fetch ─────────────────────────────────────────────── */
    int psv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, psv) != 0) {
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }

    WriterArgs pwa = { .fd = psv[1], .data = parent_buf,
                       .len = (size_t)parent_len };
    pthread_t ptid;
    if (pthread_create(&ptid, NULL, writer_thread, &pwa) != 0) {
        close(psv[0]); close(psv[1]);
        PyErr_SetString(PyExc_RuntimeError, "pthread_create failed"); return NULL;
    }

    CURL *parent = curl_easy_init();
    if (!parent) {
        pthread_join(ptid, NULL); close(psv[0]);
        PyErr_SetString(PyExc_RuntimeError, "curl_easy_init failed"); return NULL;
    }

    Buffer pbody; buf_init(&pbody);
    curl_socket_t pfd = psv[0];

    struct curl_slist *pres = NULL;
    pres = curl_slist_append(pres, "x.test:80:127.0.0.1");
    pres = curl_slist_append(pres, "x.test:443:127.0.0.1");

    setup_easy(parent, parent_url, &pfd, pres, &pbody);

    CYBER_LOG("dupfetch: parent perform");
    CURLcode prc = curl_easy_perform(parent);
    CYBER_LOG("dupfetch: parent rc=%d body=%zu", (int)prc, pbody.len);

    pthread_join(ptid, NULL);
    close(psv[0]);

    PyObject *parent_result = make_result(prc, &pbody);
    curl_slist_free_all(pres);
    if (!parent_result) { curl_easy_cleanup(parent); return NULL; }

    /* ── duphandle ────────────────────────────────────────────────── */
    CURL *clone = curl_easy_duphandle(parent);
    curl_easy_cleanup(parent);
    if (!clone) {
        Py_DECREF(parent_result);
        PyErr_SetString(PyExc_RuntimeError, "curl_easy_duphandle failed");
        return NULL;
    }
    CYBER_LOG("dupfetch: duphandle done");

    /* ── clone fetch ──────────────────────────────────────────────── */
    int csv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, csv) != 0) {
        curl_easy_cleanup(clone);
        Py_DECREF(parent_result);
        PyErr_SetFromErrno(PyExc_OSError); return NULL;
    }

    WriterArgs cwa = { .fd = csv[1], .data = clone_buf,
                       .len = (size_t)clone_len };
    pthread_t ctid;
    if (pthread_create(&ctid, NULL, writer_thread, &cwa) != 0) {
        curl_easy_cleanup(clone);
        close(csv[0]); close(csv[1]);
        Py_DECREF(parent_result);
        PyErr_SetString(PyExc_RuntimeError, "pthread_create failed"); return NULL;
    }

    Buffer cbody; buf_init(&cbody);
    curl_socket_t cfd = csv[0];

    struct curl_slist *cres = NULL;
    cres = curl_slist_append(cres, "x.test:80:127.0.0.1");
    cres = curl_slist_append(cres, "x.test:443:127.0.0.1");

    /* Override only the options that must change for the clone fetch.
     * All other options (including CURLOPT_HSTS="") were copied by
     * curl_easy_duphandle and are already set on the clone handle.    */
    curl_easy_setopt(clone, CURLOPT_URL,               clone_url);
    curl_easy_setopt(clone, CURLOPT_RESOLVE,            cres);
    curl_easy_setopt(clone, CURLOPT_OPENSOCKETFUNCTION, opensocket_cb);
    curl_easy_setopt(clone, CURLOPT_OPENSOCKETDATA,     &cfd);
    curl_easy_setopt(clone, CURLOPT_SOCKOPTFUNCTION,    sockopt_cb);
    curl_easy_setopt(clone, CURLOPT_SOCKOPTDATA,        NULL);
    curl_easy_setopt(clone, CURLOPT_CLOSESOCKETFUNCTION, closesocket_cb);
    curl_easy_setopt(clone, CURLOPT_CLOSESOCKETDATA,    NULL);
    curl_easy_setopt(clone, CURLOPT_WRITEFUNCTION,      write_cb);
    curl_easy_setopt(clone, CURLOPT_WRITEDATA,          &cbody);
    /* Bug present:  clone sends plain HTTP → writer drains + responds → rc=0.
     * Bug absent:   clone upgrades to HTTPS → TLS ClientHello → drain loop
     *               never sees \r\n\r\n → blocks until this timeout → rc!=0. */
    curl_easy_setopt(clone, CURLOPT_TIMEOUT_MS,        2000L);

    CYBER_LOG("dupfetch: clone perform");
    CURLcode crc = curl_easy_perform(clone);
    CYBER_LOG("dupfetch: clone rc=%d body=%zu", (int)crc, cbody.len);

    /* Close csv[0] first so the writer's read() gets EOF and unblocks. */
    close(csv[0]);
    pthread_join(ctid, NULL);
    curl_slist_free_all(cres);
    curl_easy_cleanup(clone);

    PyObject *clone_result = make_result(crc, &cbody);
    if (!clone_result) { Py_DECREF(parent_result); return NULL; }

    /* hsts_enforced: HSTS is working correctly if the clone's plain-HTTP
     * request was blocked (non-zero CURLcode).  If the bug is present,
     * the request succeeds (rc==0) and hsts_enforced is false.         */
    int hsts_enforced = (crc != CURLE_OK);

    PyObject *result = PyDict_New();
    if (!result) {
        Py_DECREF(parent_result); Py_DECREF(clone_result); return NULL;
    }
    PyDict_SetItemString(result, "parent",        parent_result);
    PyDict_SetItemString(result, "clone",         clone_result);
    PyDict_SetItemString(result, "hsts_enforced", PyBool_FromLong(hsts_enforced));
    Py_DECREF(parent_result);
    Py_DECREF(clone_result);
    return result;
}

/* ------------------------------------------------------------------ */
/* module table                                                         */
/* ------------------------------------------------------------------ */

static PyMethodDef cyber_methods[] = {
    {"fetch", cyber_fetch, METH_VARARGS,
     "fetch(url, response) -> dict\n\n"
     "Drive libcurl with a fully crafted server response bytes object.\n"
     "Returns {'body': bytes, 'exit_code': int, 'error': str}."},
    {"dupfetch", cyber_dupfetch, METH_VARARGS,
     "dupfetch(parent_url, parent_resp, clone_url, clone_resp) -> dict\n\n"
     "Run parent_url fetch so libcurl learns an HSTS entry, then\n"
     "curl_easy_duphandle, then run clone_url fetch on the clone.\n"
     "Returns {'parent': dict, 'clone': dict, 'hsts_enforced': bool}.\n"
     "hsts_enforced=False means the clone accepted plain HTTP for an\n"
     "STS-pinned origin — the duphandle HSTS-bypass bug is present."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef cyber_module = {
    PyModuleDef_HEAD_INIT,
    "cyberext",
    "libcurl socket-injection fuzzing harness (internal)",
    -1,
    cyber_methods
};

PyMODINIT_FUNC PyInit_cyberext(void)
{
    const char *dbg = getenv("CYBER_DEBUG");
    g_debug = (dbg && dbg[0] != '0' && dbg[0] != '\0');
    if (g_debug)
        fprintf(stderr, "[cyber] debug logging enabled (pid=%d)\n", (int)getpid());
    return PyModule_Create(&cyber_module);
}
