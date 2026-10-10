/* PKCS#11 v2.40 module. It holds no key material.
 * C_Login and C_Sign talk to the hotbox socket in HOTBOX_TOKEN.
 * The frame layout matches token/protocol.go.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef long CK_LONG;
typedef CK_BYTE CK_BBOOL;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_CERTIFICATE_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_STATE;
typedef void *CK_VOID_PTR;

typedef struct CK_VERSION {
	CK_BYTE major;
	CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
	CK_VERSION cryptokiVersion;
	CK_UTF8CHAR manufacturerID[32];
	CK_FLAGS flags;
	CK_UTF8CHAR libraryDescription[32];
	CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
	CK_UTF8CHAR slotDescription[64];
	CK_UTF8CHAR manufacturerID[32];
	CK_FLAGS flags;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
	CK_UTF8CHAR label[32];
	CK_UTF8CHAR manufacturerID[32];
	CK_UTF8CHAR model[16];
	CK_CHAR serialNumber[16];
	CK_FLAGS flags;
	CK_ULONG ulMaxSessionCount;
	CK_ULONG ulSessionCount;
	CK_ULONG ulMaxRwSessionCount;
	CK_ULONG ulRwSessionCount;
	CK_ULONG ulMaxPinLen;
	CK_ULONG ulMinPinLen;
	CK_ULONG ulTotalPublicMemory;
	CK_ULONG ulFreePublicMemory;
	CK_ULONG ulTotalPrivateMemory;
	CK_ULONG ulFreePrivateMemory;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
	CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_SESSION_INFO {
	CK_SLOT_ID slotID;
	CK_STATE state;
	CK_FLAGS flags;
	CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_MECHANISM_INFO {
	CK_ULONG ulMinKeySize;
	CK_ULONG ulMaxKeySize;
	CK_ULONG flags;
} CK_MECHANISM_INFO;

typedef struct CK_C_INITIALIZE_ARGS {
	void *CreateMutex;
	void *DestroyMutex;
	void *LockMutex;
	void *UnlockMutex;
	CK_FLAGS flags;
	void *pReserved;
} CK_C_INITIALIZE_ARGS;

typedef CK_RV (*CK_FUNCTION_PTR)(void);
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;

#define CKR_OK 0x0
#define CKR_HOST_MEMORY 0x2
#define CKR_SLOT_ID_INVALID 0x3
#define CKR_GENERAL_ERROR 0x5
#define CKR_ARGUMENTS_BAD 0x7
#define CKR_ATTRIBUTE_SENSITIVE 0x11
#define CKR_ATTRIBUTE_TYPE_INVALID 0x12
#define CKR_DEVICE_ERROR 0x30
#define CKR_FUNCTION_NOT_SUPPORTED 0x54
#define CKR_KEY_HANDLE_INVALID 0x60
#define CKR_KEY_TYPE_INCONSISTENT 0x63
#define CKR_MECHANISM_INVALID 0x70
#define CKR_OBJECT_HANDLE_INVALID 0x82
#define CKR_OPERATION_ACTIVE 0x90
#define CKR_OPERATION_NOT_INITIALIZED 0x91
#define CKR_PIN_INCORRECT 0xa0
#define CKR_SESSION_HANDLE_INVALID 0xb3
#define CKR_USER_ALREADY_LOGGED_IN 0x100
#define CKR_USER_NOT_LOGGED_IN 0x101
#define CKR_USER_TYPE_INVALID 0x103
#define CKR_BUFFER_TOO_SMALL 0x150
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x191

#define CKF_TOKEN_PRESENT 0x1
#define CKF_LOGIN_REQUIRED 0x4
#define CKF_SERIAL_SESSION 0x4
#define CKF_RW_SESSION 0x2
#define CKF_USER_PIN_INITIALIZED 0x8
#define CKF_TOKEN_INITIALIZED 0x400
#define CKF_SIGN 0x800
#define CKU_USER 1
#define CK_UNAVAILABLE_INFORMATION (~(CK_ULONG)0)

#define CKA_CLASS 0x0
#define CKA_TOKEN 0x1
#define CKA_PRIVATE 0x2
#define CKA_LABEL 0x3
#define CKA_VALUE 0x11
#define CKA_CERTIFICATE_TYPE 0x80
#define CKA_ISSUER 0x81
#define CKA_SERIAL_NUMBER 0x82
#define CKA_KEY_TYPE 0x100
#define CKA_SUBJECT 0x101
#define CKA_ID 0x102
#define CKA_SENSITIVE 0x103
#define CKA_ENCRYPT 0x104
#define CKA_DECRYPT 0x105
#define CKA_SIGN 0x108
#define CKA_MODULUS 0x120
#define CKA_MODULUS_BITS 0x121
#define CKA_PUBLIC_EXPONENT 0x122
#define CKA_EXTRACTABLE 0x162
#define CKA_ALWAYS_SENSITIVE 0x165
#define CKA_NEVER_EXTRACTABLE 0x164
#define CKA_EC_PARAMS 0x180
#define CKA_EC_POINT 0x181

#define CKO_CERTIFICATE 0x1
#define CKO_PRIVATE_KEY 0x3
#define CKK_RSA 0x0
#define CKK_EC 0x3
#define CKC_X_509 0x0

#define MAX_CERTS 8
#define MAX_SESSIONS 4
#define MAX_FRAME (1u << 20)
#define KEY_HANDLE 1

struct cert {
	unsigned char *der;
	size_t der_len;
	unsigned char *subject;
	size_t subject_len;
	unsigned char *issuer;
	size_t issuer_len;
	unsigned char *serial;
	size_t serial_len;
	char label[160];
	size_t label_len;
};

struct session {
	int open;
	int rw;
	int finding;
	CK_OBJECT_HANDLE found[1 + MAX_CERTS];
	int nfound;
	int sent;
	int signing;
	CK_MECHANISM_TYPE mech;
	unsigned char *buf;
	size_t len;
	size_t cap;
};

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int initialized;
static int logged_in;
static char pin[64];
static size_t pin_len;
static char alias[129];
static size_t alias_len;
static int key_type;
static unsigned char *part_a;
static size_t part_a_len;
static unsigned char *part_b;
static size_t part_b_len;
static unsigned char *ec_point;
static size_t ec_point_len;
static struct cert certs[MAX_CERTS];
static int ncerts;
static struct session sessions[MAX_SESSIONS];

static const CK_MECHANISM_TYPE mechs[] = {
	0x00000001, 0x00000040, 0x00000041, 0x00000042,
	0x00000043, 0x00000044, 0x00000045,
	0x00001041, 0x00001044, 0x00001045, 0x00001046,
};

static void wipe(void *p, size_t n) {
	volatile unsigned char *b = p;
	for (size_t i = 0; i < n; i++)
		b[i] = 0;
}

static void pad(unsigned char *dst, size_t n, const char *s) {
	memset(dst, ' ', n);
	size_t i = 0;
	for (; s[i] && i < n; i++)
		dst[i] = (unsigned char)s[i];
}

static int rsa_mech(CK_MECHANISM_TYPE m) {
	return m == 0x1 || m == 0x40 || m == 0x41 || m == 0x42 || m == 0x43 || m == 0x44 || m == 0x45;
}

static int ec_mech(CK_MECHANISM_TYPE m) {
	return m == 0x1041 || m == 0x1044 || m == 0x1045 || m == 0x1046;
}

static int known_mech(CK_MECHANISM_TYPE m) { return rsa_mech(m) || ec_mech(m); }

static void free_cache(void) {
	free(part_a);
	free(part_b);
	free(ec_point);
	part_a = part_b = ec_point = NULL;
	part_a_len = part_b_len = ec_point_len = 0;
	for (int i = 0; i < ncerts; i++) {
		free(certs[i].der);
		free(certs[i].subject);
		free(certs[i].issuer);
		free(certs[i].serial);
	}
	memset(certs, 0, sizeof certs);
	ncerts = 0;
	key_type = 0;
	alias_len = 0;
	logged_in = 0;
	wipe(pin, sizeof pin);
	pin_len = 0;
}

static struct session *session_get(CK_SESSION_HANDLE h) {
	if (h == 0 || h > MAX_SESSIONS || !sessions[h - 1].open)
		return NULL;
	return &sessions[h - 1];
}

static void session_clear_sign(struct session *s) {
	free(s->buf);
	s->buf = NULL;
	s->len = s->cap = 0;
	s->signing = 0;
}

static int read_full(int fd, void *buf, size_t n) {
	unsigned char *p = buf;
	while (n) {
		ssize_t r = read(fd, p, n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;
		p += (size_t)r;
		n -= (size_t)r;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
	const unsigned char *p = buf;
	while (n) {
		ssize_t r = write(fd, p, n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += (size_t)r;
		n -= (size_t)r;
	}
	return 0;
}

/* status is the response kind. *out is malloc'd body. */
static CK_RV rpc(unsigned char op, const unsigned char *req, uint32_t req_len, unsigned char *status, unsigned char **out, uint32_t *out_len) {
	const char *path = getenv("HOTBOX_TOKEN");
	if (!path || !path[0])
		return CKR_DEVICE_ERROR;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return CKR_DEVICE_ERROR;
	struct timeval tv = {.tv_sec = 30};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof addr.sun_path) {
		close(fd);
		return CKR_DEVICE_ERROR;
	}
	memcpy(addr.sun_path, path, strlen(path));
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
		close(fd);
		return CKR_DEVICE_ERROR;
	}
	unsigned char hdr[6] = {1, op};
	hdr[2] = (unsigned char)(req_len >> 24);
	hdr[3] = (unsigned char)(req_len >> 16);
	hdr[4] = (unsigned char)(req_len >> 8);
	hdr[5] = (unsigned char)req_len;
	CK_RV rv = CKR_OK;
	if (write_full(fd, hdr, 6) || write_full(fd, req, req_len) || read_full(fd, hdr, 6))
		rv = CKR_DEVICE_ERROR;
	uint32_t n = 0;
	unsigned char *body = NULL;
	if (rv == CKR_OK) {
		if (hdr[0] != 1)
			rv = CKR_DEVICE_ERROR;
		n = ((uint32_t)hdr[2] << 24) | ((uint32_t)hdr[3] << 16) | ((uint32_t)hdr[4] << 8) | hdr[5];
		if (n > MAX_FRAME)
			rv = CKR_DEVICE_ERROR;
	}
	if (rv == CKR_OK && n) {
		body = malloc(n);
		if (!body)
			rv = CKR_HOST_MEMORY;
		else if (read_full(fd, body, n))
			rv = CKR_DEVICE_ERROR;
	}
	close(fd);
	if (rv != CKR_OK) {
		free(body);
		return rv;
	}
	*status = hdr[1];
	*out = body;
	*out_len = n;
	return CKR_OK;
}

static int u8(const unsigned char **p, size_t *n, unsigned int *v) {
	if (*n < 1)
		return -1;
	*v = (*p)[0];
	*p += 1;
	*n -= 1;
	return 0;
}

static int u16(const unsigned char **p, size_t *n, unsigned int *v) {
	if (*n < 2)
		return -1;
	*v = ((unsigned int)(*p)[0] << 8) | (*p)[1];
	*p += 2;
	*n -= 2;
	return 0;
}

static int u32(const unsigned char **p, size_t *n, unsigned int *v) {
	if (*n < 4)
		return -1;
	*v = ((unsigned int)(*p)[0] << 24) | ((unsigned int)(*p)[1] << 16) | ((unsigned int)(*p)[2] << 8) | (*p)[3];
	*p += 4;
	*n -= 4;
	return 0;
}

static int take(const unsigned char **p, size_t *n, size_t k, unsigned char **dst) {
	if (*n < k)
		return -1;
	unsigned char *b = malloc(k ? k : 1);
	if (!b)
		return -1;
	memcpy(b, *p, k);
	*p += k;
	*n -= k;
	*dst = b;
	return 0;
}

static int der_octet(const unsigned char *p, size_t n, unsigned char **out, size_t *outn) {
	size_t hdr = n < 128 ? 2 : n < 256 ? 3 : 4;
	unsigned char *b = malloc(hdr + n);
	if (!b)
		return -1;
	b[0] = 0x04;
	if (n < 128)
		b[1] = (unsigned char)n;
	else if (n < 256) {
		b[1] = 0x81;
		b[2] = (unsigned char)n;
	} else {
		b[1] = 0x82;
		b[2] = (unsigned char)(n >> 8);
		b[3] = (unsigned char)n;
	}
	memcpy(b + hdr, p, n);
	*out = b;
	*outn = hdr + n;
	return 0;
}

static CK_RV parse_info(const unsigned char *p, size_t n) {
	free_cache();
	unsigned int alen = 0, kind = 0, an = 0, bn = 0, count = 0;
	if (u16(&p, &n, &alen) || alen == 0 || alen > 128 || n < alen)
		return CKR_DEVICE_ERROR;
	memcpy(alias, p, alen);
	alias[alen] = 0;
	alias_len = alen;
	p += alen;
	n -= alen;
	if (u8(&p, &n, &kind) || (kind != 1 && kind != 2))
		return CKR_DEVICE_ERROR;
	key_type = (int)kind;
	if (u16(&p, &n, &an) || take(&p, &n, an, &part_a))
		return CKR_DEVICE_ERROR;
	part_a_len = an;
	if (u16(&p, &n, &bn) || take(&p, &n, bn, &part_b))
		return CKR_DEVICE_ERROR;
	part_b_len = bn;
	if (kind == 2 && der_octet(part_b, part_b_len, &ec_point, &ec_point_len))
		return CKR_HOST_MEMORY;
	if (u8(&p, &n, &count) || count == 0 || count > MAX_CERTS)
		return CKR_DEVICE_ERROR;
	for (unsigned int i = 0; i < count; i++) {
		unsigned int dn = 0, sn = 0, in = 0, rn = 0;
		if (u32(&p, &n, &dn) || take(&p, &n, dn, &certs[i].der))
			return CKR_DEVICE_ERROR;
		certs[i].der_len = dn;
		ncerts++;
		if (u16(&p, &n, &sn) || take(&p, &n, sn, &certs[i].subject))
			return CKR_DEVICE_ERROR;
		certs[i].subject_len = sn;
		if (u16(&p, &n, &in) || take(&p, &n, in, &certs[i].issuer))
			return CKR_DEVICE_ERROR;
		certs[i].issuer_len = in;
		if (u16(&p, &n, &rn) || take(&p, &n, rn, &certs[i].serial))
			return CKR_DEVICE_ERROR;
		certs[i].serial_len = rn;
		if (i == 0) {
			memcpy(certs[i].label, alias, alias_len);
			certs[i].label_len = alias_len;
		} else {
			int wrote = snprintf(certs[i].label, sizeof certs[i].label, "%.*s.ca%u", (int)alias_len, alias, i);
			if (wrote < 0)
				return CKR_DEVICE_ERROR;
			certs[i].label_len = (size_t)wrote;
		}
	}
	if (n != 0)
		return CKR_DEVICE_ERROR;
	logged_in = 1;
	return CKR_OK;
}

static CK_RV login_rpc(const unsigned char *pin_bytes, CK_ULONG pin_n) {
	if (pin_n != 32 || pin_n > sizeof pin)
		return CKR_PIN_INCORRECT;
	unsigned char *req = malloc(2 + pin_n);
	if (!req)
		return CKR_HOST_MEMORY;
	req[0] = 0;
	req[1] = (unsigned char)pin_n;
	memcpy(req + 2, pin_bytes, pin_n);
	unsigned char status = 0;
	unsigned char *body = NULL;
	uint32_t blen = 0;
	CK_RV rv = rpc(1, req, (uint32_t)(2 + pin_n), &status, &body, &blen);
	wipe(req, 2 + pin_n);
	free(req);
	if (rv != CKR_OK)
		return rv;
	if (status == 1) {
		free(body);
		return CKR_PIN_INCORRECT;
	}
	if (status != 0) {
		free(body);
		return CKR_DEVICE_ERROR;
	}
	rv = parse_info(body, blen);
	free(body);
	if (rv != CKR_OK) {
		free_cache();
		return rv;
	}
	memcpy(pin, pin_bytes, pin_n);
	pin_len = pin_n;
	return CKR_OK;
}

static CK_RV sign_rpc(CK_MECHANISM_TYPE mech, const unsigned char *data, size_t dlen, unsigned char **sig, size_t *siglen) {
	if (pin_len != 32 || dlen > MAX_FRAME)
		return CKR_ARGUMENTS_BAD;
	uint32_t req_len = (uint32_t)(2 + pin_len + 8 + dlen);
	unsigned char *req = malloc(req_len);
	if (!req)
		return CKR_HOST_MEMORY;
	req[0] = 0;
	req[1] = (unsigned char)pin_len;
	memcpy(req + 2, pin, pin_len);
	size_t o = 2 + pin_len;
	req[o] = (unsigned char)(mech >> 24);
	req[o + 1] = (unsigned char)(mech >> 16);
	req[o + 2] = (unsigned char)(mech >> 8);
	req[o + 3] = (unsigned char)mech;
	req[o + 4] = (unsigned char)(dlen >> 24);
	req[o + 5] = (unsigned char)(dlen >> 16);
	req[o + 6] = (unsigned char)(dlen >> 8);
	req[o + 7] = (unsigned char)dlen;
	memcpy(req + o + 8, data, dlen);
	unsigned char status = 0;
	unsigned char *body = NULL;
	uint32_t blen = 0;
	CK_RV rv = rpc(2, req, req_len, &status, &body, &blen);
	wipe(req, req_len);
	free(req);
	if (rv != CKR_OK)
		return rv;
	if (status == 1)
		rv = CKR_PIN_INCORRECT;
	else if (status == 2)
		rv = CKR_MECHANISM_INVALID;
	else if (status != 0)
		rv = CKR_GENERAL_ERROR;
	else if (blen < 4)
		rv = CKR_DEVICE_ERROR;
	if (rv != CKR_OK) {
		free(body);
		return rv;
	}
	uint32_t n = ((uint32_t)body[0] << 24) | ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | body[3];
	if ((uint32_t)(blen - 4) != n) {
		free(body);
		return CKR_DEVICE_ERROR;
	}
	*sig = malloc(n ? n : 1);
	if (!*sig) {
		free(body);
		return CKR_HOST_MEMORY;
	}
	memcpy(*sig, body + 4, n);
	*siglen = n;
	free(body);
	return CKR_OK;
}

static CK_ULONG sig_len(void) {
	if (key_type == 1)
		return (CK_ULONG)part_a_len;
	if (key_type == 2 && part_b_len > 0)
		return (CK_ULONG)(part_b_len - 1);
	return 0;
}

static CK_ULONG modulus_bits(const unsigned char *m, size_t n) {
	size_t i = 0;
	while (i < n && m[i] == 0)
		i++;
	if (i == n)
		return 0;
	CK_ULONG bits = (CK_ULONG)(n - i) * 8;
	unsigned char b = m[i];
	while ((b & 0x80) == 0) {
		bits--;
		b <<= 1;
	}
	return bits;
}

static const unsigned char key_id[] = {0x01};

static CK_RV put_mem(CK_ATTRIBUTE *a, const void *p, CK_ULONG n) {
	if (!a->pValue) {
		a->ulValueLen = n;
		return CKR_OK;
	}
	if (a->ulValueLen < n) {
		a->ulValueLen = n;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(a->pValue, p, n);
	a->ulValueLen = n;
	return CKR_OK;
}

static CK_RV put_ulong(CK_ATTRIBUTE *a, CK_ULONG v) { return put_mem(a, &v, sizeof v); }

static CK_RV put_bool(CK_ATTRIBUTE *a, int v) {
	CK_BBOOL b = v ? 1 : 0;
	return put_mem(a, &b, 1);
}

static int sensitive(CK_ATTRIBUTE_TYPE t) {
	return t == 0x123 || t == 0x124 || t == 0x125 || t == 0x126 || t == 0x127 || t == 0x128;
}

static CK_RV attr_key(CK_ATTRIBUTE *a) {
	if (sensitive(a->type)) {
		a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_SENSITIVE;
	}
	switch (a->type) {
	case CKA_CLASS:
		return put_ulong(a, CKO_PRIVATE_KEY);
	case CKA_KEY_TYPE:
		return put_ulong(a, key_type == 1 ? CKK_RSA : CKK_EC);
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_SENSITIVE:
	case CKA_SIGN:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
		return put_bool(a, 1);
	case CKA_EXTRACTABLE:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
		return put_bool(a, 0);
	case CKA_LABEL:
		return put_mem(a, alias, (CK_ULONG)alias_len);
	case CKA_ID:
		return put_mem(a, key_id, 1);
	case CKA_MODULUS:
		if (key_type != 1)
			break;
		return put_mem(a, part_a, (CK_ULONG)part_a_len);
	case CKA_PUBLIC_EXPONENT:
		if (key_type != 1)
			break;
		return put_mem(a, part_b, (CK_ULONG)part_b_len);
	case CKA_MODULUS_BITS:
		if (key_type != 1)
			break;
		return put_ulong(a, modulus_bits(part_a, part_a_len));
	case CKA_EC_PARAMS:
		if (key_type != 2)
			break;
		return put_mem(a, part_a, (CK_ULONG)part_a_len);
	case CKA_EC_POINT:
		if (key_type != 2)
			break;
		return put_mem(a, ec_point, (CK_ULONG)ec_point_len);
	default:
		break;
	}
	a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV attr_cert(CK_ATTRIBUTE *a, int idx) {
	struct cert *c = &certs[idx];
	switch (a->type) {
	case CKA_CLASS:
		return put_ulong(a, CKO_CERTIFICATE);
	case CKA_CERTIFICATE_TYPE:
		return put_ulong(a, CKC_X_509);
	case CKA_TOKEN:
		return put_bool(a, 1);
	case CKA_PRIVATE:
		return put_bool(a, 0);
	case CKA_LABEL:
		return put_mem(a, c->label, (CK_ULONG)c->label_len);
	case CKA_ID:
		return put_mem(a, key_id, 1);
	case CKA_VALUE:
		return put_mem(a, c->der, (CK_ULONG)c->der_len);
	case CKA_SUBJECT:
		return put_mem(a, c->subject, (CK_ULONG)c->subject_len);
	case CKA_ISSUER:
		return put_mem(a, c->issuer, (CK_ULONG)c->issuer_len);
	case CKA_SERIAL_NUMBER:
		return put_mem(a, c->serial, (CK_ULONG)c->serial_len);
	default:
		a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}

static int object_ok(CK_OBJECT_HANDLE h) {
	return h == KEY_HANDLE || (h >= 2 && h < 2 + (CK_OBJECT_HANDLE)ncerts);
}

static CK_RV attr_one(CK_OBJECT_HANDLE h, CK_ATTRIBUTE *a) {
	if (h == KEY_HANDLE)
		return attr_key(a);
	return attr_cert(a, (int)h - 2);
}

static int attr_equals(CK_OBJECT_HANDLE h, CK_ATTRIBUTE *a) {
	unsigned char tmp[512];
	CK_ATTRIBUTE q = *a;
	q.pValue = NULL;
	if (attr_one(h, &q) != CKR_OK)
		return 0;
	if (q.ulValueLen != a->ulValueLen)
		return 0;
	if (q.ulValueLen > sizeof tmp) {
		unsigned char *buf = malloc(q.ulValueLen);
		if (!buf)
			return 0;
		q.pValue = buf;
		CK_RV rv = attr_one(h, &q);
		int eq = rv == CKR_OK && a->pValue && memcmp(buf, a->pValue, q.ulValueLen) == 0;
		free(buf);
		return eq;
	}
	q.pValue = tmp;
	if (attr_one(h, &q) != CKR_OK)
		return 0;
	return a->pValue && memcmp(tmp, a->pValue, q.ulValueLen) == 0;
}

static int object_matches(CK_OBJECT_HANDLE h, CK_ATTRIBUTE *tmpl, CK_ULONG count) {
	for (CK_ULONG i = 0; i < count; i++) {
		if (!attr_equals(h, &tmpl[i]))
			return 0;
	}
	return 1;
}

static CK_RV append_sign(struct session *s, const unsigned char *p, CK_ULONG n) {
	if (s->len + n > MAX_FRAME)
		return CKR_GENERAL_ERROR;
	if (s->len + n > s->cap) {
		size_t cap = s->cap ? s->cap * 2 : 256;
		while (cap < s->len + n)
			cap *= 2;
		unsigned char *b = realloc(s->buf, cap);
		if (!b)
			return CKR_HOST_MEMORY;
		s->buf = b;
		s->cap = cap;
	}
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	return CKR_OK;
}

static CK_RV C_Initialize(void *args) {
	pthread_mutex_lock(&mu);
	CK_RV rv = CKR_OK;
	if (initialized)
		rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
	else if (args && ((CK_C_INITIALIZE_ARGS *)args)->pReserved)
		rv = CKR_ARGUMENTS_BAD;
	else
		initialized = 1;
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_Finalize(void *args) {
	pthread_mutex_lock(&mu);
	CK_RV rv = CKR_OK;
	if (args)
		rv = CKR_ARGUMENTS_BAD;
	else if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else {
		for (int i = 0; i < MAX_SESSIONS; i++) {
			session_clear_sign(&sessions[i]);
			sessions[i].open = 0;
		}
		free_cache();
		initialized = 0;
	}
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_GetInfo(CK_INFO *info) {
	pthread_mutex_lock(&mu);
	if (!initialized) {
		pthread_mutex_unlock(&mu);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	pthread_mutex_unlock(&mu);
	if (!info)
		return CKR_ARGUMENTS_BAD;
	memset(info, 0, sizeof *info);
	info->cryptokiVersion.major = 2;
	info->cryptokiVersion.minor = 40;
	pad(info->manufacturerID, 32, "Hotbox");
	pad(info->libraryDescription, 32, "Hotbox PKCS11");
	info->libraryVersion.major = 1;
	return CKR_OK;
}

static CK_RV C_GetSlotList(CK_BBOOL present, CK_SLOT_ID *list, CK_ULONG *count) {
	(void)present;
	pthread_mutex_lock(&mu);
	int ok = initialized;
	pthread_mutex_unlock(&mu);
	if (!ok)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!count)
		return CKR_ARGUMENTS_BAD;
	if (!list) {
		*count = 1;
		return CKR_OK;
	}
	if (*count < 1) {
		*count = 1;
		return CKR_BUFFER_TOO_SMALL;
	}
	list[0] = 0;
	*count = 1;
	return CKR_OK;
}

static CK_RV C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO *info) {
	pthread_mutex_lock(&mu);
	int ok = initialized;
	pthread_mutex_unlock(&mu);
	if (!ok)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slot != 0)
		return CKR_SLOT_ID_INVALID;
	if (!info)
		return CKR_ARGUMENTS_BAD;
	memset(info, 0, sizeof *info);
	pad(info->slotDescription, 64, "Hotbox");
	pad(info->manufacturerID, 32, "Hotbox");
	info->flags = CKF_TOKEN_PRESENT;
	info->hardwareVersion.major = 1;
	info->firmwareVersion.major = 1;
	return CKR_OK;
}

static CK_RV C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO *info) {
	pthread_mutex_lock(&mu);
	int ok = initialized;
	CK_ULONG sessions_open = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].open)
			sessions_open++;
	pthread_mutex_unlock(&mu);
	if (!ok)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slot != 0)
		return CKR_SLOT_ID_INVALID;
	if (!info)
		return CKR_ARGUMENTS_BAD;
	memset(info, 0, sizeof *info);
	pad(info->label, 32, "Hotbox");
	pad(info->manufacturerID, 32, "Hotbox");
	pad(info->model, 16, "PKCS11");
	pad((unsigned char *)info->serialNumber, 16, "1");
	info->flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	info->ulMaxSessionCount = MAX_SESSIONS;
	info->ulSessionCount = sessions_open;
	info->ulMaxRwSessionCount = MAX_SESSIONS;
	info->ulMaxPinLen = 32;
	info->ulMinPinLen = 32;
	info->hardwareVersion.major = 1;
	info->firmwareVersion.major = 1;
	return CKR_OK;
}

static CK_RV C_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE *list, CK_ULONG *count) {
	pthread_mutex_lock(&mu);
	int ok = initialized;
	pthread_mutex_unlock(&mu);
	if (!ok)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slot != 0)
		return CKR_SLOT_ID_INVALID;
	if (!count)
		return CKR_ARGUMENTS_BAD;
	CK_ULONG n = (CK_ULONG)(sizeof mechs / sizeof mechs[0]);
	if (!list) {
		*count = n;
		return CKR_OK;
	}
	if (*count < n) {
		*count = n;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(list, mechs, sizeof mechs);
	*count = n;
	return CKR_OK;
}

static CK_RV C_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *info) {
	pthread_mutex_lock(&mu);
	int ok = initialized;
	pthread_mutex_unlock(&mu);
	if (!ok)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slot != 0)
		return CKR_SLOT_ID_INVALID;
	if (!info || !known_mech(type))
		return CKR_MECHANISM_INVALID;
	memset(info, 0, sizeof *info);
	if (rsa_mech(type)) {
		info->ulMinKeySize = 2048;
		info->ulMaxKeySize = 4096;
	} else {
		info->ulMinKeySize = 256;
		info->ulMaxKeySize = 521;
	}
	info->flags = CKF_SIGN;
	return CKR_OK;
}

static CK_RV C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags, void *app, void *notify, CK_SESSION_HANDLE *out) {
	(void)app;
	(void)notify;
	pthread_mutex_lock(&mu);
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (slot != 0)
		rv = CKR_SLOT_ID_INVALID;
	else if (!out || (flags & CKF_SERIAL_SESSION) == 0)
		rv = CKR_ARGUMENTS_BAD;
	else {
		int slot_i = -1;
		for (int i = 0; i < MAX_SESSIONS; i++) {
			if (!sessions[i].open) {
				slot_i = i;
				break;
			}
		}
		if (slot_i < 0)
			rv = CKR_HOST_MEMORY;
		else {
			memset(&sessions[slot_i], 0, sizeof sessions[slot_i]);
			sessions[slot_i].open = 1;
			sessions[slot_i].rw = (flags & CKF_RW_SESSION) != 0;
			*out = (CK_SESSION_HANDLE)(slot_i + 1);
		}
	}
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_CloseSession(CK_SESSION_HANDLE h) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	if (!initialized) {
		pthread_mutex_unlock(&mu);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!s) {
		pthread_mutex_unlock(&mu);
		return CKR_SESSION_HANDLE_INVALID;
	}
	session_clear_sign(s);
	memset(s, 0, sizeof *s);
	pthread_mutex_unlock(&mu);
	return CKR_OK;
}

static CK_RV C_CloseAllSessions(CK_SLOT_ID slot) {
	pthread_mutex_lock(&mu);
	if (!initialized) {
		pthread_mutex_unlock(&mu);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (slot != 0) {
		pthread_mutex_unlock(&mu);
		return CKR_SLOT_ID_INVALID;
	}
	for (int i = 0; i < MAX_SESSIONS; i++) {
		session_clear_sign(&sessions[i]);
		memset(&sessions[i], 0, sizeof sessions[i]);
	}
	pthread_mutex_unlock(&mu);
	return CKR_OK;
}

static CK_RV C_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO *info) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	int user = logged_in;
	pthread_mutex_unlock(&mu);
	if (!initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	if (!info)
		return CKR_ARGUMENTS_BAD;
	memset(info, 0, sizeof *info);
	info->flags = CKF_SERIAL_SESSION;
	if (s->rw) {
		info->flags |= CKF_RW_SESSION;
		info->state = user ? 3 : 2;
	} else {
		info->state = user ? 1 : 0;
	}
	return CKR_OK;
}

static CK_RV C_Login(CK_SESSION_HANDLE h, CK_USER_TYPE user, CK_BYTE *pin_bytes, CK_ULONG pin_n) {
	pthread_mutex_lock(&mu);
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!session_get(h))
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (user != CKU_USER)
		rv = CKR_USER_TYPE_INVALID;
	else if (logged_in)
		rv = CKR_USER_ALREADY_LOGGED_IN;
	else if (!pin_bytes)
		rv = CKR_ARGUMENTS_BAD;
	else
		rv = login_rpc(pin_bytes, pin_n);
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_Logout(CK_SESSION_HANDLE h) {
	pthread_mutex_lock(&mu);
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!session_get(h))
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!logged_in)
		rv = CKR_USER_NOT_LOGGED_IN;
	else
		free_cache();
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_GetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE *tmpl, CK_ULONG count) {
	pthread_mutex_lock(&mu);
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!session_get(h))
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!logged_in)
		rv = CKR_USER_NOT_LOGGED_IN;
	else if (!object_ok(obj) || (count && !tmpl))
		rv = CKR_OBJECT_HANDLE_INVALID;
	else {
		for (CK_ULONG i = 0; i < count; i++) {
			CK_RV one = attr_one(obj, &tmpl[i]);
			if (one == CKR_ATTRIBUTE_SENSITIVE)
				rv = one;
			else if (one != CKR_OK && rv == CKR_OK)
				rv = one;
		}
	}
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE *tmpl, CK_ULONG count) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!s)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (s->finding)
		rv = CKR_OPERATION_ACTIVE;
	else if (count && !tmpl)
		rv = CKR_ARGUMENTS_BAD;
	else if (!logged_in) {
		s->finding = 1;
		s->nfound = 0;
		s->sent = 0;
	} else {
		s->nfound = 0;
		s->sent = 0;
		CK_OBJECT_HANDLE all[1 + MAX_CERTS];
		int n = 0;
		all[n++] = KEY_HANDLE;
		for (int i = 0; i < ncerts; i++)
			all[n++] = (CK_OBJECT_HANDLE)(i + 2);
		for (int i = 0; i < n; i++) {
			if (object_matches(all[i], tmpl, count))
				s->found[s->nfound++] = all[i];
		}
		s->finding = 1;
	}
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE *out, CK_ULONG max, CK_ULONG *count) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!s)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!s->finding)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	else if (!out || !count)
		rv = CKR_ARGUMENTS_BAD;
	else {
		CK_ULONG n = 0;
		while (n < max && s->sent < s->nfound)
			out[n++] = s->found[s->sent++];
		*count = n;
	}
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE h) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	if (!initialized) {
		pthread_mutex_unlock(&mu);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!s) {
		pthread_mutex_unlock(&mu);
		return CKR_SESSION_HANDLE_INVALID;
	}
	s->finding = 0;
	s->nfound = s->sent = 0;
	pthread_mutex_unlock(&mu);
	return CKR_OK;
}

static CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM *mech, CK_OBJECT_HANDLE key) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!s)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!logged_in)
		rv = CKR_USER_NOT_LOGGED_IN;
	else if (!mech)
		rv = CKR_ARGUMENTS_BAD;
	else if (s->signing)
		rv = CKR_OPERATION_ACTIVE;
	else if (key != KEY_HANDLE)
		rv = CKR_KEY_HANDLE_INVALID;
	else if (!known_mech(mech->mechanism))
		rv = CKR_MECHANISM_INVALID;
	else if ((key_type == 1 && !rsa_mech(mech->mechanism)) || (key_type == 2 && !ec_mech(mech->mechanism)))
		rv = CKR_KEY_TYPE_INCONSISTENT;
	else {
		s->signing = 1;
		s->mech = mech->mechanism;
		s->len = 0;
	}
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV finish_sign(struct session *s, const unsigned char *data, size_t n, CK_BYTE *sig, CK_ULONG *siglen) {
	CK_ULONG need = sig_len();
	if (!sig) {
		*siglen = need;
		return CKR_OK;
	}
	if (*siglen < need) {
		*siglen = need;
		return CKR_BUFFER_TOO_SMALL;
	}
	unsigned char *out = NULL;
	size_t outn = 0;
	CK_RV rv = sign_rpc(s->mech, data, n, &out, &outn);
	session_clear_sign(s);
	if (rv != CKR_OK)
		return rv;
	if ((CK_ULONG)outn > *siglen) {
		free(out);
		*siglen = need;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(sig, out, outn);
	*siglen = (CK_ULONG)outn;
	free(out);
	return CKR_OK;
}

static CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE *data, CK_ULONG data_len, CK_BYTE *sig, CK_ULONG *siglen) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!s)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!s->signing)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	else if (!siglen || (data_len && !data))
		rv = CKR_ARGUMENTS_BAD;
	else if (s->len)
		rv = CKR_OPERATION_ACTIVE;
	else
		rv = finish_sign(s, data, data_len, sig, siglen);
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE *part, CK_ULONG part_len) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!s)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!s->signing)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	else if (part_len && !part)
		rv = CKR_ARGUMENTS_BAD;
	else
		rv = append_sign(s, part, part_len);
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE *sig, CK_ULONG *siglen) {
	pthread_mutex_lock(&mu);
	struct session *s = initialized ? session_get(h) : NULL;
	CK_RV rv = CKR_OK;
	if (!initialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else if (!s)
		rv = CKR_SESSION_HANDLE_INVALID;
	else if (!s->signing)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	else if (!siglen)
		rv = CKR_ARGUMENTS_BAD;
	else
		rv = finish_sign(s, s->buf, s->len, sig, siglen);
	pthread_mutex_unlock(&mu);
	return rv;
}

static CK_RV unsupported(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

struct CK_FUNCTION_LIST {
	CK_VERSION version;
	CK_FUNCTION_PTR C_Initialize;
	CK_FUNCTION_PTR C_Finalize;
	CK_FUNCTION_PTR C_GetInfo;
	CK_FUNCTION_PTR C_GetFunctionList;
	CK_FUNCTION_PTR C_GetSlotList;
	CK_FUNCTION_PTR C_GetSlotInfo;
	CK_FUNCTION_PTR C_GetTokenInfo;
	CK_FUNCTION_PTR C_GetMechanismList;
	CK_FUNCTION_PTR C_GetMechanismInfo;
	CK_FUNCTION_PTR C_InitToken;
	CK_FUNCTION_PTR C_InitPIN;
	CK_FUNCTION_PTR C_SetPIN;
	CK_FUNCTION_PTR C_OpenSession;
	CK_FUNCTION_PTR C_CloseSession;
	CK_FUNCTION_PTR C_CloseAllSessions;
	CK_FUNCTION_PTR C_GetSessionInfo;
	CK_FUNCTION_PTR C_GetOperationState;
	CK_FUNCTION_PTR C_SetOperationState;
	CK_FUNCTION_PTR C_Login;
	CK_FUNCTION_PTR C_Logout;
	CK_FUNCTION_PTR C_CreateObject;
	CK_FUNCTION_PTR C_CopyObject;
	CK_FUNCTION_PTR C_DestroyObject;
	CK_FUNCTION_PTR C_GetObjectSize;
	CK_FUNCTION_PTR C_GetAttributeValue;
	CK_FUNCTION_PTR C_SetAttributeValue;
	CK_FUNCTION_PTR C_FindObjectsInit;
	CK_FUNCTION_PTR C_FindObjects;
	CK_FUNCTION_PTR C_FindObjectsFinal;
	CK_FUNCTION_PTR C_EncryptInit;
	CK_FUNCTION_PTR C_Encrypt;
	CK_FUNCTION_PTR C_EncryptUpdate;
	CK_FUNCTION_PTR C_EncryptFinal;
	CK_FUNCTION_PTR C_DecryptInit;
	CK_FUNCTION_PTR C_Decrypt;
	CK_FUNCTION_PTR C_DecryptUpdate;
	CK_FUNCTION_PTR C_DecryptFinal;
	CK_FUNCTION_PTR C_DigestInit;
	CK_FUNCTION_PTR C_Digest;
	CK_FUNCTION_PTR C_DigestUpdate;
	CK_FUNCTION_PTR C_DigestKey;
	CK_FUNCTION_PTR C_DigestFinal;
	CK_FUNCTION_PTR C_SignInit;
	CK_FUNCTION_PTR C_Sign;
	CK_FUNCTION_PTR C_SignUpdate;
	CK_FUNCTION_PTR C_SignFinal;
	CK_FUNCTION_PTR C_SignRecoverInit;
	CK_FUNCTION_PTR C_SignRecover;
	CK_FUNCTION_PTR C_VerifyInit;
	CK_FUNCTION_PTR C_Verify;
	CK_FUNCTION_PTR C_VerifyUpdate;
	CK_FUNCTION_PTR C_VerifyFinal;
	CK_FUNCTION_PTR C_VerifyRecoverInit;
	CK_FUNCTION_PTR C_VerifyRecover;
	CK_FUNCTION_PTR C_DigestEncryptUpdate;
	CK_FUNCTION_PTR C_DecryptDigestUpdate;
	CK_FUNCTION_PTR C_SignEncryptUpdate;
	CK_FUNCTION_PTR C_DecryptVerifyUpdate;
	CK_FUNCTION_PTR C_GenerateKey;
	CK_FUNCTION_PTR C_GenerateKeyPair;
	CK_FUNCTION_PTR C_WrapKey;
	CK_FUNCTION_PTR C_UnwrapKey;
	CK_FUNCTION_PTR C_DeriveKey;
	CK_FUNCTION_PTR C_SeedRandom;
	CK_FUNCTION_PTR C_GenerateRandom;
	CK_FUNCTION_PTR C_GetFunctionStatus;
	CK_FUNCTION_PTR C_CancelFunction;
	CK_FUNCTION_PTR C_WaitForSlotEvent;
};

__attribute__((visibility("default"))) CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR *pp);

static CK_FUNCTION_LIST functions = {
	{2, 40},
	(CK_FUNCTION_PTR)C_Initialize,
	(CK_FUNCTION_PTR)C_Finalize,
	(CK_FUNCTION_PTR)C_GetInfo,
	(CK_FUNCTION_PTR)C_GetFunctionList,
	(CK_FUNCTION_PTR)C_GetSlotList,
	(CK_FUNCTION_PTR)C_GetSlotInfo,
	(CK_FUNCTION_PTR)C_GetTokenInfo,
	(CK_FUNCTION_PTR)C_GetMechanismList,
	(CK_FUNCTION_PTR)C_GetMechanismInfo,
	unsupported,
	unsupported,
	unsupported,
	(CK_FUNCTION_PTR)C_OpenSession,
	(CK_FUNCTION_PTR)C_CloseSession,
	(CK_FUNCTION_PTR)C_CloseAllSessions,
	(CK_FUNCTION_PTR)C_GetSessionInfo,
	unsupported,
	unsupported,
	(CK_FUNCTION_PTR)C_Login,
	(CK_FUNCTION_PTR)C_Logout,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	(CK_FUNCTION_PTR)C_GetAttributeValue,
	unsupported,
	(CK_FUNCTION_PTR)C_FindObjectsInit,
	(CK_FUNCTION_PTR)C_FindObjects,
	(CK_FUNCTION_PTR)C_FindObjectsFinal,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	(CK_FUNCTION_PTR)C_SignInit,
	(CK_FUNCTION_PTR)C_Sign,
	(CK_FUNCTION_PTR)C_SignUpdate,
	(CK_FUNCTION_PTR)C_SignFinal,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
	unsupported,
};

__attribute__((visibility("default"))) CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR *pp) {
	if (!pp)
		return CKR_ARGUMENTS_BAD;
	*pp = &functions;
	return CKR_OK;
}
