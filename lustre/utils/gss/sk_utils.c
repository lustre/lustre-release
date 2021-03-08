/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 */

#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libcfs/util/string.h>
#include <sys/time.h>

#include "sk_utils.h"
#include "write_bytes.h"

#define SK_PBKDF2_ITERATIONS 10000

#ifdef _NEW_BUILD_
# include "lgss_utils.h"
#else
# include "gss_util.h"
# include "gss_oids.h"
# include "err_util.h"
#endif

#ifdef _ERR_UTIL_H_
/**
 * Initializes logging
 * \param[in]	program		Program name to output
 * \param[in]	verbose		Verbose flag
 * \param[in]	fg		Whether or not to run in foreground
 *
 */
void sk_init_logging(char *program, int verbose, int fg)
{
	initerr(program, verbose, fg);
}
#endif

/**
 * Loads the key from \a filename and returns the struct sk_keyfile_config.
 * It should be freed by the caller.
 *
 * \param[in]	filename		Disk or key payload data
 *
 * \return	sk_keyfile_config	sucess
 * \return	NULL			failure
 */
struct sk_keyfile_config *sk_read_file(char *filename)
{
	struct sk_keyfile_config *config;
	char *ptr;
	size_t rc;
	size_t remain;
	int fd;

	config = malloc(sizeof(*config));
	if (!config) {
		printerr(0, "Failed to allocate memory for config\n");
		return NULL;
	}

	/* allow standard input override */
	if (strcmp(filename, "-") == 0)
		fd = STDIN_FILENO;
	else
		fd = open(filename, O_RDONLY);

	if (fd == -1) {
		printerr(0, "Error opening key file '%s': %s\n", filename,
			 strerror(errno));
		goto out_free;
	} else if (fd != STDIN_FILENO) {
		struct stat st;

		rc = fstat(fd, &st);
		if (rc == 0 && (st.st_mode & ~(S_IFREG | 0600)))
			fprintf(stderr, "warning: "
				"secret key '%s' has insecure file mode %#o\n",
				filename, st.st_mode);
	}

	ptr = (char *)config;
	remain = sizeof(*config);
	while (remain > 0) {
		rc = read(fd, ptr, remain);
		if (rc == -1) {
			if (errno == EINTR)
				continue;
			printerr(0, "read() failed on %s: %s\n", filename,
				 strerror(errno));
			goto out_close;
		} else if (rc == 0) {
			printerr(0, "File %s does not have a complete key\n",
				 filename);
			goto out_close;
		}
		ptr += rc;
		remain -= rc;
	}

	if (fd != STDIN_FILENO)
		close(fd);
	sk_config_disk_to_cpu(config);
	return config;

out_close:
	close(fd);
out_free:
	free(config);
	return NULL;
}

/**
 * Checks if a key matching \a description is found in the keyring for
 * logging purposes and then attempts to load \a payload of \a psize into a key
 * with \a description.
 *
 * \param[in]	payload		Key payload
 * \param[in]	psize		Payload size
 * \param[in]	description	Description used for key in keyring
 *
 * \return	0	sucess
 * \return	-1	failure
 */
static key_serial_t sk_load_key(const struct sk_keyfile_config *skc,
				const char *description)
{
	struct sk_keyfile_config payload;
	key_serial_t key;

	memcpy(&payload, skc, sizeof(*skc));

	/* In the keyring use the disk layout so keyctl pipe can be used */
	sk_config_cpu_to_disk(&payload);

	/* Check to see if a key is already loaded matching description */
	key = keyctl_search(KEY_SPEC_USER_KEYRING, "user", description, 0);
	if (key != -1)
		printerr(2, "Key %d found in session keyring, replacing\n",
			 key);

	key = add_key("user", description, &payload, sizeof(payload),
		      KEY_SPEC_USER_KEYRING);
	if (key != -1) {
		key_perm_t perm = KEY_POS_ALL | KEY_USR_ALL |
			KEY_GRP_ALL | KEY_OTH_ALL;

		if (keyctl_setperm(key, perm) < 0)
			printerr(2, "Failed to set perm 0x%x on key %d\n",
				 perm, key);
		printerr(2, "Added key %d with description %s\n", key,
			 description);
	} else {
		printerr(0, "Failed to add key with %s\n", description);
	}

	return key;
}

/**
 * Reads the key from \a path, verifies it and loads into the session keyring
 * using a description determined by the the \a type.  Existing keys with the
 * same description are replaced.
 *
 * \param[in]	path	Path to key file
 * \param[in]	type	Type of key to load which determines the description
 *
 * \return	0	sucess
 * \return	-1	failure
 */
int sk_load_keyfile(char *path)
{
	struct sk_keyfile_config *config;
	char description[SK_DESCRIPTION_SIZE + 1];
	struct stat buf;
	int i;
	int rc;
	int rc2 = -1;

	rc = stat(path, &buf);
	if (rc == -1) {
		printerr(0, "stat() failed for file %s: %s\n", path,
			 strerror(errno));
		return rc2;
	}

	config = sk_read_file(path);
	if (!config)
		return rc2;

	/* Similar to ssh, require adequate care of key files */
	if (buf.st_mode & (S_IRGRP | S_IWGRP | S_IWOTH | S_IXOTH)) {
		printerr(0, "Shared key files must be read/writeable only by "
			 "owner\n");
		return -1;
	}

	if (sk_validate_config(config))
		goto out;

	/* The server side can have multiple key files per file system so
	 * the nodemap name is appended to the key description to uniquely
	 * identify it */
	if (config->skc_type & SK_TYPE_MGS) {
		/* Any key can be an MGS key as long as we are told to use it */
		rc = snprintf(description, SK_DESCRIPTION_SIZE, "lustre:MGS:%s",
			      config->skc_nodemap);
		if (rc >= SK_DESCRIPTION_SIZE)
			goto out;
		if (sk_load_key(config, description) == -1)
			goto out;
	}
	if (config->skc_type & SK_TYPE_SERVER) {
		/* Server keys need to have the file system name in the key */
		if (!config->skc_fsname) {
			printerr(0, "Key configuration has no file system "
				 "attribute.  Can't load as server type\n");
			goto out;
		}
		rc = snprintf(description, SK_DESCRIPTION_SIZE, "lustre:%s:%s",
			      config->skc_fsname, config->skc_nodemap);
		if (rc >= SK_DESCRIPTION_SIZE)
			goto out;
		if (sk_load_key(config, description) == -1)
			goto out;
	}
	if (config->skc_type & SK_TYPE_CLIENT) {
		/* Load client file system key */
		if (config->skc_fsname) {
			rc = snprintf(description, SK_DESCRIPTION_SIZE,
				      "lustre:%s", config->skc_fsname);
			if (rc >= SK_DESCRIPTION_SIZE)
				goto out;
			if (sk_load_key(config, description) == -1)
				goto out;
		}

		/* Load client MGC keys */
		for (i = 0; i < MAX_MGSNIDS; i++) {
			if (config->skc_mgsnids[i] == LNET_NID_ANY)
				continue;
			rc = snprintf(description, SK_DESCRIPTION_SIZE,
				      "lustre:MGC%s",
				      libcfs_nid2str(config->skc_mgsnids[i]));
			if (rc >= SK_DESCRIPTION_SIZE)
				goto out;
			if (sk_load_key(config, description) == -1)
				goto out;
		}
	}

	rc2 = 0;

out:
	free(config);
	return rc2;
}

/**
 * Byte swaps config from cpu format to disk
 *
 * \param[in,out]	config		sk_keyfile_config to swap
 */
void sk_config_cpu_to_disk(struct sk_keyfile_config *config)
{
	int i;

	if (!config)
		return;

	config->skc_version = htobe32(config->skc_version);
	config->skc_hmac_alg = htobe16(config->skc_hmac_alg);
	config->skc_crypt_alg = htobe16(config->skc_crypt_alg);
	config->skc_expire = htobe32(config->skc_expire);
	config->skc_shared_keylen = htobe32(config->skc_shared_keylen);
	config->skc_prime_bits = htobe32(config->skc_prime_bits);

	for (i = 0; i < MAX_MGSNIDS; i++)
		config->skc_mgsnids[i] = htobe64(config->skc_mgsnids[i]);
}

/**
 * Byte swaps config from disk format to cpu
 *
 * \param[in,out]	config		sk_keyfile_config to swap
 */
void sk_config_disk_to_cpu(struct sk_keyfile_config *config)
{
	int i;

	if (!config)
		return;

	config->skc_version = be32toh(config->skc_version);
	config->skc_hmac_alg = be16toh(config->skc_hmac_alg);
	config->skc_crypt_alg = be16toh(config->skc_crypt_alg);
	config->skc_expire = be32toh(config->skc_expire);
	config->skc_shared_keylen = be32toh(config->skc_shared_keylen);
	config->skc_prime_bits = be32toh(config->skc_prime_bits);

	for (i = 0; i < MAX_MGSNIDS; i++)
		config->skc_mgsnids[i] = be64toh(config->skc_mgsnids[i]);
}

/**
 * Verifies the on key payload format is valid
 *
 * \param[in]	config		sk_keyfile_config
 *
 * \return	-1	failure
 * \return	0	success
 */
int sk_validate_config(const struct sk_keyfile_config *config)
{
	int i;

	if (!config) {
		printerr(0, "Null configuration passed\n");
		return -1;
	}

	if (config->skc_version != SK_CONF_VERSION) {
		printerr(0, "Invalid version\n");
		return -1;
	}

	if (config->skc_hmac_alg == SK_HMAC_INVALID) {
		printerr(0, "Invalid HMAC algorithm\n");
		return -1;
	}

	if (config->skc_crypt_alg == SK_CRYPT_INVALID) {
		printerr(0, "Invalid crypt algorithm\n");
		return -1;
	}

	if (config->skc_expire < 60 || config->skc_expire > INT_MAX) {
		/* Try to limit key expiration to some reasonable minimum and
		 * also prevent values over INT_MAX because there appears
		 * to be a type conversion issue */
		printerr(0, "Invalid expiration time should be between %d "
			 "and %d\n", 60, INT_MAX);
		return -1;
	}
	if (config->skc_prime_bits % 8 != 0 ||
	    config->skc_prime_bits > SK_MAX_P_BYTES * 8) {
		printerr(0, "Invalid session key length must be a multiple of 8"
			 " and less then %d bits\n",
			 SK_MAX_P_BYTES * 8);
		return -1;
	}
	if (config->skc_shared_keylen % 8 != 0 ||
	    config->skc_shared_keylen > SK_MAX_KEYLEN_BYTES * 8){
		printerr(0, "Invalid shared key max length must be a multiple "
			 "of 8 and less then %d bits\n",
			 SK_MAX_KEYLEN_BYTES * 8);
		return -1;
	}

	/* Check for terminating nulls on strings */
	for (i = 0; i < sizeof(config->skc_fsname) &&
	     config->skc_fsname[i] != '\0';  i++)
		; /* empty loop */
	if (i == sizeof(config->skc_fsname)) {
		printerr(0, "File system name not null terminated\n");
		return -1;
	}

	for (i = 0; i < sizeof(config->skc_nodemap) &&
	     config->skc_nodemap[i] != '\0';  i++)
		; /* empty loop */
	if (i == sizeof(config->skc_nodemap)) {
		printerr(0, "Nodemap name not null terminated\n");
		return -1;
	}

	if (config->skc_type == SK_TYPE_INVALID) {
		printerr(0, "Invalid key type\n");
		return -1;
	}

	return 0;
}

/**
 * Hashes \a string and places the hash in \a hash
 * at \a hash
 *
 * \param[in]		string		Null terminated string to hash
 * \param[in]		hash_alg	OpenSSL EVP_MD to use for hash
 * \param[in,out]	hash		gss_buffer_desc to hold the result
 *
 * \return	-1	failure
 * \return	0	success
 */
static int sk_hash_string(const char *string, const EVP_MD *hash_alg,
			  gss_buffer_desc *hash)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	size_t len = strlen(string);
	unsigned int hashlen;

	if (!hash->value || hash->length < EVP_MD_size(hash_alg))
		goto out_err;
	if (!EVP_DigestInit_ex(ctx, hash_alg, NULL))
		goto out_err;
	if (!EVP_DigestUpdate(ctx, string, len))
		goto out_err;
	if (!EVP_DigestFinal_ex(ctx, hash->value, &hashlen))
		goto out_err;

	EVP_MD_CTX_destroy(ctx);
	hash->length = hashlen;
	return 0;

out_err:
	EVP_MD_CTX_destroy(ctx);
	return -1;
}

/**
 * Hashes \a string and verifies the resulting hash matches the value
 * in \a current_hash
 *
 * \param[in]		string		Null terminated string to hash
 * \param[in]		hash_alg	OpenSSL EVP_MD to use for hash
 * \param[in,out]	current_hash	gss_buffer_desc to compare to
 *
 * \return	gss error	failure
 * \return	GSS_S_COMPLETE	success
 */
uint32_t sk_verify_hash(const char *string, const EVP_MD *hash_alg,
			const gss_buffer_desc *current_hash)
{
	gss_buffer_desc hash;
	unsigned char hashbuf[EVP_MAX_MD_SIZE];

	hash.value = hashbuf;
	hash.length = sizeof(hashbuf);

	if (sk_hash_string(string, hash_alg, &hash))
		return GSS_S_FAILURE;
	if (current_hash->length != hash.length)
		return GSS_S_DEFECTIVE_TOKEN;
	if (memcmp(current_hash->value, hash.value, hash.length))
		return GSS_S_BAD_SIG;

	return GSS_S_COMPLETE;
}

static inline int sk_config_has_mgsnid(struct sk_keyfile_config *config,
				       const char *mgsnid)
{
	lnet_nid_t nid;
	int i;

	nid = libcfs_str2nid(mgsnid);
	if (nid == LNET_NID_ANY)
		return 0;

	for (i = 0; i < MAX_MGSNIDS; i++)
		if  (config->skc_mgsnids[i] == nid)
			return 1;
	return 0;
}

/**
 * Create an sk_cred structure populated with initial configuration info and the
 * key.  \a tgt and \a nodemap are used in determining the expected key
 * description so the key can be found by searching the keyring.
 * This is done because there is no easy way to pass keys from the mount command
 * all the way to the request_key call.  In addition any keys can be dynamically
 * added to the keyrings and still found.  The keyring that needs to be used
 * must be the session keyring.
 *
 * \param[in]	tgt		Target file system
 * \param[in]	nodemap		Cluster name for the key.  This correlates to
 *				the nodemap name and is used by the server side.
 *				For the client this will be NULL.
 * \param[in]	flags		Flags for the credentials
 *
 * \return	sk_cred Allocated struct sk_cred on success
 * \return	NULL	failure
 */
struct sk_cred *sk_create_cred(const char *tgt, const char *nodemap,
			       const uint32_t flags)
{
	struct sk_keyfile_config *config;
	struct sk_kernel_ctx *kctx;
	struct sk_cred *skc = NULL;
	char description[SK_DESCRIPTION_SIZE + 1];
	char fsname[MTI_NAME_MAXLEN + 1];
	const char *mgsnid = NULL;
	char *ptr;
	long sk_key;
	int keylen;
	int len;
	int rc;

	printerr(2, "Creating credentials for target: %s with nodemap: %s\n",
		 tgt, nodemap);

	memset(description, 0, sizeof(description));
	memset(fsname, 0, sizeof(fsname));

	/* extract the file system name from target */
	ptr = index(tgt, '-');
	if (!ptr) {
		len = strlen(tgt);

		/* This must be an MGC target */
		if (strncmp(tgt, "MGC", 3) || len <= 3) {
			printerr(0, "Invalid target name\n");
			return NULL;
		}
		mgsnid = tgt + 3;
	} else {
		len = ptr - tgt;
	}

	if (len > MTI_NAME_MAXLEN) {
		printerr(0, "Invalid target name\n");
		return NULL;
	}
	memcpy(fsname, tgt, len);

	if (nodemap) {
		if (mgsnid)
			rc = snprintf(description, SK_DESCRIPTION_SIZE,
				      "lustre:MGS:%s", nodemap);
		else
			rc = snprintf(description, SK_DESCRIPTION_SIZE,
				      "lustre:%s:%s", fsname, nodemap);
	} else {
		rc = snprintf(description, SK_DESCRIPTION_SIZE, "lustre:%s",
			      fsname);
	}

	if (rc >= SK_DESCRIPTION_SIZE) {
		printerr(0, "Invalid key description\n");
		return NULL;
	}

	/* It may be a good idea to move Lustre keys to the gss_keyring
	 * (lgssc) type so that they expire when Lustre modules are removed.
	 * Unfortunately it can't be done at mount time because the mount
	 * syscall could trigger the Lustre modules to load and until that
	 * point we don't have a lgssc key type.
	 *
	 * TODO: Query the community for a consensus here  */
	printerr(2, "Searching for key with description: %s\n", description);
	sk_key = keyctl_search(KEY_SPEC_USER_KEYRING, "user",
			       description, 0);
	if (sk_key == -1) {
		printerr(1, "No key found for %s\n", description);
		return NULL;
	}

	keylen = keyctl_read_alloc(sk_key, (void **)&config);
	if (keylen == -1) {
		printerr(0, "keyctl_read() failed for key %ld: %s\n", sk_key,
			 strerror(errno));
		return NULL;
	} else if (keylen != sizeof(*config)) {
		printerr(0, "Unexpected key size: %d returned for key %ld, "
			 "expected %zu bytes\n",
			 keylen, sk_key, sizeof(*config));
		goto out_err;
	}

	sk_config_disk_to_cpu(config);

	if (sk_validate_config(config)) {
		printerr(0, "Invalid key configuration for key: %ld\n", sk_key);
		goto out_err;
	}

	if (mgsnid && !sk_config_has_mgsnid(config, mgsnid)) {
		printerr(0, "Target name does not match key's MGS NIDs\n");
		goto out_err;
	}

	if (!mgsnid && strcmp(fsname, config->skc_fsname)) {
		printerr(0, "Target name does not match key's file system\n");
		goto out_err;
	}

	skc = malloc(sizeof(*skc));
	if (!skc) {
		printerr(0, "Failed to allocate memory for sk_cred\n");
		goto out_err;
	}

	/* this initializes all gss_buffer_desc to empty as well */
	memset(skc, 0, sizeof(*skc));

	skc->sc_flags = flags;
	skc->sc_tgt.length = strlen(tgt) + 1;
	skc->sc_tgt.value = malloc(skc->sc_tgt.length);
	if (!skc->sc_tgt.value) {
		printerr(0, "Failed to allocate memory for target\n");
		goto out_err;
	}
	memcpy(skc->sc_tgt.value, tgt, skc->sc_tgt.length);

	skc->sc_nodemap_hash.length = EVP_MD_size(EVP_sha256());
	skc->sc_nodemap_hash.value = malloc(skc->sc_nodemap_hash.length);
	if (!skc->sc_nodemap_hash.value) {
		printerr(0, "Failed to allocate memory for nodemap hash\n");
		goto out_err;
	}

	if (sk_hash_string(config->skc_nodemap, EVP_sha256(),
			   &skc->sc_nodemap_hash)) {
		printerr(0, "Failed to generate hash for nodemap name\n");
		goto out_err;
	}

	kctx = &skc->sc_kctx;
	kctx->skc_version = config->skc_version;
	strcpy(kctx->skc_hmac_alg, sk_hmac2name(config->skc_hmac_alg));
	strcpy(kctx->skc_crypt_alg, sk_crypt2name(config->skc_crypt_alg));
	kctx->skc_expire = config->skc_expire;

	/* key payload format is in bits, convert to bytes */
	kctx->skc_shared_key.length = config->skc_shared_keylen / 8;
	kctx->skc_shared_key.value = malloc(kctx->skc_shared_key.length);
	if (!kctx->skc_shared_key.value) {
		printerr(0, "Failed to allocate memory for shared key\n");
		goto out_err;
	}
	memcpy(kctx->skc_shared_key.value, config->skc_shared_key,
	       kctx->skc_shared_key.length);

	skc->sc_p.length = config->skc_prime_bits / 8;
	skc->sc_p.value = malloc(skc->sc_p.length);
	if (!skc->sc_p.value) {
		printerr(0, "Failed to allocate p\n");
		goto out_err;
	}
	memcpy(skc->sc_p.value, config->skc_p, skc->sc_p.length);

	free(config);

	return skc;

out_err:
	sk_free_cred(skc);

	free(config);
	return NULL;
}

#define SK_GENERATOR 2
#define DH_NUMBER_ITERATIONS_FOR_PRIME 64

/* OpenSSL 1.1.1c increased the number of rounds used for Miller-Rabin testing
 * of the prime provided as input parameter to DH_check(). This makes the check
 * roughly x10 longer, and causes request timeouts when an SSK flavor is being
 * used.
 *
 * Instead, use a dynamic number Miller-Rabin rounds based on the speed of the
 * check on the current system, evaluated when the lsvcgssd daemon starts, but
 * at least as many as OpenSSL 1.1.1b used for the same key size. If default
 * DH_check() duration is OK, use it directly instead of limiting the rounds.
 *
 * If \a num_rounds == 0, we just call original DH_check() directly.
 */
static bool sk_is_dh_valid(const DH *dh, int num_rounds)
{
	const BIGNUM *p, *g;
	BN_ULONG word;
	BN_CTX *ctx;
	BIGNUM *r;
	bool valid = false;
	int rc;

	if (num_rounds == 0) {
		int codes = 0;

		rc = DH_check(dh, &codes);
		if (rc != 1 || codes) {
			printerr(0, "DH_check(0) failed: codes=%#x: rc=%d\n",
				 codes, rc);
			return false;
		}
		return true;
	}

	DH_get0_pqg(dh, &p, NULL, &g);

	if (!BN_is_word(g, SK_GENERATOR)) {
		printerr(0, "%s: Diffie-Hellman generator is not %u\n",
			 program_invocation_short_name, SK_GENERATOR);
		return false;
	}

	word = BN_mod_word(p, 24);
	if (word != 11) {
		printerr(0, "%s: Diffie-Hellman prime modulo=%lu unsuitable\n",
			 program_invocation_short_name, word);
		return false;
	}

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		printerr(0, "%s: Diffie-Hellman error allocating context\n",
			 program_invocation_short_name);
		return false;
	}
	BN_CTX_start(ctx);
	r = BN_CTX_get(ctx); /* must be called before "ctx" used elsewhere */

	rc = BN_is_prime_ex(p, num_rounds, ctx, NULL);
	if (rc == 0)
		printerr(0, "%s: Diffie-Hellman 'p' not prime in %u rounds\n",
			 program_invocation_short_name, num_rounds);
	if (rc <= 0)
		goto out_free;

	if (!BN_rshift1(r, p)) {
		printerr(0, "%s: error shifting BigNum 'r' by 'p'\n",
			 program_invocation_short_name);
		goto out_free;
	}
	rc = BN_is_prime_ex(r, num_rounds, ctx, NULL);
	if (rc == 0)
		printerr(0, "%s: Diffie-Hellman 'r' not prime in %u rounds\n",
			 program_invocation_short_name, num_rounds);
	if (rc <= 0)
		goto out_free;

	valid = true;

out_free:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return valid;
}

#define VALUE_LENGTH 256
static unsigned char test_prime[VALUE_LENGTH] =
	"\xf7\xfa\x49\xd8\xec\xb1\x3b\xff\x26\x10\x3f\xc5\x3a\xc5\xcc\x40"
	"\x4f\xbf\x92\xe1\x8b\x83\xe7\xa2\xba\x0f\x51\x5a\x91\x48\xe0\xa3"
	"\xf1\x4d\xbc\xbb\x8a\x28\x14\xac\x02\x23\x76\x42\x17\x4d\x3c\xdc"
	"\x5e\x4f\x80\x1f\xd7\x54\x1c\x50\xac\x3b\x28\x68\x8d\x71\x41\x7f"
	"\xa7\x1c\x2f\x22\xd3\xa8\x91\xb2\x64\xb6\x84\xa6\xcf\x06\x16\x91"
	"\x2f\xb8\xb4\x42\x1d\x3a\x4e\x3a\x0c\x7f\x04\x69\x78\xb5\x8f\x92"
	"\x07\x89\xac\x24\x06\x53\x2c\x23\xec\xaa\x5c\xb4\x7b\x49\xbc\xf4"
	"\x90\x67\x71\x9c\x24\x2c\x1d\x8d\x76\xc8\x85\x4e\x19\xf1\xf9\x33"
	"\x45\xbd\x9f\x7d\x0a\x08\x8c\x22\xcc\x35\xf3\x5b\xab\x3f\x24\x9d"
	"\x61\x70\x86\xbb\xbe\xd8\xb0\xf8\x34\xfa\xeb\x5b\x8e\xf2\x62\x23"
	"\xd1\xfb\xbb\xb8\x21\x71\x1e\x39\x39\x59\xe0\x82\x98\x41\x84\x40"
	"\x1f\xd3\x9b\xa3\x73\xdb\xec\xe0\xc0\xde\x2d\x1c\xea\x43\x40\x93"
	"\x98\x38\x03\x36\x1e\xe1\xe7\x39\x7b\x35\x92\x4a\x51\xa5\x91\x63"
	"\xd5\x31\x98\x3d\x89\x27\x6f\xcc\x69\xff\xbe\x31\x13\xdc\x2f\x72"
	"\x2d\xab\x6a\xb7\x13\xd3\x47\xda\xaa\xf3\x3c\xa0\xfd\xaa\x0f\x02"
	"\x96\x81\x1a\x26\xe8\xf7\x25\x65\x33\x78\xd9\x6b\x6d\xb0\xd9\xfb";

/**
 * Measure time taken by prime testing routine for a 2048 bit long prime,
 * depending on the number of check rounds.
 *
 * \param[in]	usec_check_max    max time allowed for DH_check completion
 *
 * \retval	max number of rounds to keep prime testing under usec_check_max
 *		return 0 if we should use the default DH_check rounds
 */
int sk_speedtest_dh_valid(unsigned int usec_check_max)
{
	DH *dh;
	BIGNUM *p, *g;
	int num_rounds, prev_rounds = 0;

	dh = DH_new();
	if (!dh)
		return 0;

	p = BN_bin2bn(test_prime, VALUE_LENGTH, NULL);
	if (!p)
		goto free_dh;

	g = BN_new();
	if (!g)
		goto free_p;

	if (!BN_set_word(g, SK_GENERATOR))
		goto free_g;

	/* "dh" takes over freeing of 'p' and 'g' if this succeeds */
	if (!DH_set0_pqg(dh, p, NULL, g)) {
	free_g:
		BN_free(g);
	free_p:
		BN_free(p);
		goto free_dh;
	}

	for (num_rounds = 0;
	     num_rounds <= DH_NUMBER_ITERATIONS_FOR_PRIME;
	     num_rounds += (num_rounds <= 4 ? 4 : 8)) {
		unsigned int usec_this;
		int j;

		/* get max duration of 4 runs at current number of rounds */
		usec_this = 0;
		for (j = 0; j < 4; j++) {
			struct timeval now, prev;
			unsigned int usec_curr;

			gettimeofday(&prev, NULL);
			if (!sk_is_dh_valid(dh, num_rounds)) {
				/* if test_prime is found bad, use default */
				prev_rounds = 0;
				goto free_dh;
			}
			gettimeofday(&now, NULL);
			usec_curr = (now.tv_sec - prev.tv_sec) * 1000000 +
				    now.tv_usec - prev.tv_usec;
			if (usec_curr > usec_this)
				usec_this = usec_curr;
		}
		printerr(2, "%s: %d rounds: %d usec\n",
			 program_invocation_short_name, num_rounds, usec_this);
		if (num_rounds == 0) {
			if (usec_this <= usec_check_max)
			/* using original check rounds as implemented in
			 * DH_check() took less time than the max allowed,
			 * so just use original DH_check()
			 */
				break;
		} else if (usec_this >= usec_check_max) {
			break;
		}
		prev_rounds = num_rounds;
	}

free_dh:
	DH_free(dh);

	return prev_rounds;
}

/**
 * Populates the DH parameters for the DHKE
 *
 * \param[in,out]	skc		Shared key credentials structure to
 *					populate with DH parameters
 *
 * \retval	GSS_S_COMPLETE	success
 * \retval	GSS_S_FAILURE	failure
 */
uint32_t sk_gen_params(struct sk_cred *skc, int num_rounds)
{
	uint32_t random;
	BIGNUM *p, *g;
	const BIGNUM *pub_key;

	/* Random value used by both the request and response as part of the
	 * key binding material.  This also should ensure we have unqiue
	 * tokens that are sent to the remote server which is important because
	 * the token is hashed for the sunrpc cache lookups and a failure there
	 * would cause connection attempts to fail indefinitely due to the large
	 * timeout value on the server side */
	if (RAND_bytes((unsigned char *)&random, sizeof(random)) != 1) {
		printerr(0, "Failed to get data for random parameter: %s\n",
			 ERR_error_string(ERR_get_error(), NULL));
		return GSS_S_FAILURE;
	}

	/* The random value will always be used in byte range operations
	 * so we keep it as big endian from this point on */
	skc->sc_kctx.skc_host_random = random;

	/* Populate DH parameters */
	skc->sc_params = DH_new();
	if (!skc->sc_params) {
		printerr(0, "Failed to allocate DH\n");
		return GSS_S_FAILURE;
	}

	p = BN_bin2bn(skc->sc_p.value, skc->sc_p.length, NULL);
	if (!p) {
		printerr(0, "Failed to convert binary to BIGNUM\n");
		return GSS_S_FAILURE;
	}

	/* We use a static generator for shared key */
	g = BN_new();
	if (!g) {
		printerr(0, "Failed to allocate new BIGNUM\n");
		return GSS_S_FAILURE;
	}
	if (BN_set_word(g, SK_GENERATOR) != 1) {
		printerr(0, "Failed to set g value for DH params\n");
		return GSS_S_FAILURE;
	}

	if (!DH_set0_pqg(skc->sc_params, p, NULL, g)) {
		printerr(0, "Failed to set pqg\n");
		return GSS_S_FAILURE;
	}

	/* Verify that we have a safe prime and valid generator */
	if (!sk_is_dh_valid(skc->sc_params, num_rounds))
		return GSS_S_FAILURE;

	if (DH_generate_key(skc->sc_params) != 1) {
		printerr(0, "Failed to generate public DH key: %s\n",
			 ERR_error_string(ERR_get_error(), NULL));
		return GSS_S_FAILURE;
	}

	DH_get0_key(skc->sc_params, &pub_key, NULL);
	skc->sc_pub_key.length = BN_num_bytes(pub_key);
	skc->sc_pub_key.value = malloc(skc->sc_pub_key.length);
	if (!skc->sc_pub_key.value) {
		printerr(0, "Failed to allocate memory for public key\n");
		return GSS_S_FAILURE;
	}

	BN_bn2bin(pub_key, skc->sc_pub_key.value);

	return GSS_S_COMPLETE;
}

/**
 * Convert SK hash algorithm into openssl message digest
 *
 * \param[in,out]	alg		SK hash algorithm
 *
 * \retval		EVP_MD
 */
static inline const EVP_MD *sk_hash_to_evp_md(enum cfs_crypto_hash_alg alg)
{
	switch (alg) {
	case CFS_HASH_ALG_SHA256:
		return EVP_sha256();
	case CFS_HASH_ALG_SHA512:
		return EVP_sha512();
	default:
		return EVP_md_null();
	}
}

/**
 * Signs (via HMAC) the parameters used only in the key initialization protocol.
 *
 * \param[in]		key		Key to use for HMAC
 * \param[in]		bufs		Array of gss_buffer_desc to generate
 *					HMAC for
 * \param[in]		numbufs		Number of buffers in array
 * \param[in]		hash_alg	OpenSSL EVP_MD to use for hash
 * \param[in,out]	hmac		HMAC of buffers is allocated and placed
 *					in this gss_buffer_desc.  Caller must
 *					free this.
 *
 * \retval	0	success
 * \retval	-1	failure
 */
int sk_sign_bufs(gss_buffer_desc *key, gss_buffer_desc *bufs, const int numbufs,
		 const EVP_MD *hash_alg, gss_buffer_desc *hmac)
{
	HMAC_CTX *hctx;
	unsigned int hashlen = EVP_MD_size(hash_alg);
	int i;
	int rc = -1;

	if (hash_alg == EVP_md_null()) {
		printerr(0, "Invalid hash algorithm\n");
		return -1;
	}

	hctx = HMAC_CTX_new();

	hmac->length = hashlen;
	hmac->value = malloc(hashlen);
	if (!hmac->value) {
		printerr(0, "Failed to allocate memory for HMAC\n");
		goto out;
	}

	if (HMAC_Init_ex(hctx, key->value, key->length, hash_alg, NULL) != 1) {
		printerr(0, "Failed to init HMAC\n");
		goto out;
	}

	for (i = 0; i < numbufs; i++) {
		if (HMAC_Update(hctx, bufs[i].value, bufs[i].length) != 1) {
			printerr(0, "Failed to update HMAC\n");
			goto out;
		}
	}

	/* The result gets populated in hmac */
	if (HMAC_Final(hctx, hmac->value, &hashlen) != 1) {
		printerr(0, "Failed to finalize HMAC\n");
		goto out;
	}

	if (hmac->length != hashlen) {
		printerr(0, "HMAC size does not match expected\n");
		goto out;
	}

	rc = 0;
out:
	HMAC_CTX_free(hctx);
	return rc;
}

/**
 * Generates an HMAC for gss_buffer_desc array in \a bufs of \a numbufs
 * and verifies against \a hmac.
 *
 * \param[in]	skc		Shared key credentials
 * \param[in]	bufs		Array of gss_buffer_desc to generate HMAC for
 * \param[in]	numbufs		Number of buffers in array
 * \param[in]	hash_alg	OpenSSL EVP_MD to use for hash
 * \param[in]	hmac		HMAC to verify against
 *
 * \retval	GSS_S_COMPLETE	success (match)
 * \retval	gss error	failure
 */
uint32_t sk_verify_hmac(struct sk_cred *skc, gss_buffer_desc *bufs,
			const int numbufs, const EVP_MD *hash_alg,
			gss_buffer_desc *hmac)
{
	gss_buffer_desc bufs_hmac;
	int rc;

	if (sk_sign_bufs(&skc->sc_kctx.skc_shared_key, bufs, numbufs, hash_alg,
			 &bufs_hmac)) {
		printerr(0, "Failed to sign buffers to verify HMAC\n");
		if (bufs_hmac.value)
			free(bufs_hmac.value);
		return GSS_S_FAILURE;
	}

	if (hmac->length != bufs_hmac.length) {
		printerr(0, "Invalid HMAC size\n");
		free(bufs_hmac.value);
		return GSS_S_BAD_SIG;
	}

	rc = memcmp(hmac->value, bufs_hmac.value, bufs_hmac.length);
	free(bufs_hmac.value);

	if (rc)
		return GSS_S_BAD_SIG;

	return GSS_S_COMPLETE;
}

/**
 * Cleanup an sk_cred freeing any resources
 *
 * \param[in,out]	skc	Shared key credentials to free
 */
void sk_free_cred(struct sk_cred *skc)
{
	if (!skc)
		return;

	if (skc->sc_p.value)
		free(skc->sc_p.value);
	if (skc->sc_pub_key.value)
		free(skc->sc_pub_key.value);
	if (skc->sc_tgt.value)
		free(skc->sc_tgt.value);
	if (skc->sc_nodemap_hash.value)
		free(skc->sc_nodemap_hash.value);
	if (skc->sc_hmac.value)
		free(skc->sc_hmac.value);

	/* Overwrite keys and IV before freeing */
	if (skc->sc_dh_shared_key.value) {
		memset(skc->sc_dh_shared_key.value, 0,
		       skc->sc_dh_shared_key.length);
		free(skc->sc_dh_shared_key.value);
	}
	if (skc->sc_kctx.skc_hmac_key.value) {
		memset(skc->sc_kctx.skc_hmac_key.value, 0,
		       skc->sc_kctx.skc_hmac_key.length);
		free(skc->sc_kctx.skc_hmac_key.value);
	}
	if (skc->sc_kctx.skc_encrypt_key.value) {
		memset(skc->sc_kctx.skc_encrypt_key.value, 0,
		       skc->sc_kctx.skc_encrypt_key.length);
		free(skc->sc_kctx.skc_encrypt_key.value);
	}
	if (skc->sc_kctx.skc_shared_key.value) {
		memset(skc->sc_kctx.skc_shared_key.value, 0,
		       skc->sc_kctx.skc_shared_key.length);
		free(skc->sc_kctx.skc_shared_key.value);
	}
	if (skc->sc_kctx.skc_session_key.value) {
		memset(skc->sc_kctx.skc_session_key.value, 0,
		       skc->sc_kctx.skc_session_key.length);
		free(skc->sc_kctx.skc_session_key.value);
	}

	if (skc->sc_params)
		DH_free(skc->sc_params);

	free(skc);
	skc = NULL;
}

/* This function handles key derivation using the hash algorithm specified in
 * \a hash_alg, buffers in \a key_binding_bufs, and original key in
 * \a origin_key to produce a \a derived_key.  The first element of the
 * key_binding_bufs array is reserved for the counter used in the KDF.  The
 * derived key in \a derived_key could differ in size from \a origin_key and
 * must be populated with the expected size and a valid buffer to hold the
 * contents.
 *
 * If the derived key size is greater than the HMAC algorithm size it will be
 * a done using several iterations of a counter and the key binding bufs.
 *
 * If the size is smaller it will take copy the first N bytes necessary to
 * fill the derived key. */
int sk_kdf(gss_buffer_desc *derived_key , gss_buffer_desc *origin_key,
	   gss_buffer_desc *key_binding_bufs, int numbufs,
	   enum cfs_crypto_hash_alg hmac_alg)
{
	size_t remain;
	size_t bytes;
	uint32_t counter;
	char *keydata;
	gss_buffer_desc tmp_hash;
	int i;
	int rc;

	if (numbufs < 1)
		return -EINVAL;

	/* Use a counter as the first buffer followed by the key binding
	 * buffers in the event we need more than one a single cycle to
	 * produced a symmetric key large enough in size */
	key_binding_bufs[0].value = &counter;
	key_binding_bufs[0].length = sizeof(counter);

	remain = derived_key->length;
	keydata = derived_key->value;
	i = 0;
	while (remain > 0) {
		counter = htobe32(i++);
		rc = sk_sign_bufs(origin_key, key_binding_bufs, numbufs,
				  sk_hash_to_evp_md(hmac_alg), &tmp_hash);
		if (rc) {
			if (tmp_hash.value)
				free(tmp_hash.value);
			return rc;
		}

		if (cfs_crypto_hash_digestsize(hmac_alg) != tmp_hash.length) {
			free(tmp_hash.value);
			return -EINVAL;
		}

		bytes = (remain < tmp_hash.length) ? remain : tmp_hash.length;
		memcpy(keydata, tmp_hash.value, bytes);
		free(tmp_hash.value);
		remain -= bytes;
		keydata += bytes;
	}

	return 0;
}

/* Populates the sk_cred's session_key using the a Key Derviation Function (KDF)
 * based on the recommendations in NIST Special Publication SP 800-56B Rev 1
 * (Sep 2014) Section 5.5.1
 *
 * \param[in,out]	skc		Shared key credentials structure with
 *
 * \return	-1		failure
 * \return	0		success
 */
int sk_session_kdf(struct sk_cred *skc, lnet_nid_t client_nid,
		   gss_buffer_desc *client_token, gss_buffer_desc *server_token)
{
	struct sk_kernel_ctx *kctx = &skc->sc_kctx;
	gss_buffer_desc *session_key = &kctx->skc_session_key;
	gss_buffer_desc bufs[5];
	enum cfs_crypto_crypt_alg crypt_alg;
	int rc = -1;

	crypt_alg = cfs_crypto_crypt_alg(kctx->skc_crypt_alg);
	session_key->length = cfs_crypto_crypt_keysize(crypt_alg);
	session_key->value = malloc(session_key->length);
	if (!session_key->value) {
		printerr(0, "Failed to allocate memory for session key\n");
		return rc;
	}

	/* Key binding info ordering
	 * 1. Reserved for counter
	 * 1. DH shared key
	 * 2. Client's NIDs
	 * 3. Client's token
	 * 4. Server's token */
	bufs[0].value = NULL;
	bufs[0].length = 0;
	bufs[1] = skc->sc_dh_shared_key;
	bufs[2].value = &client_nid;
	bufs[2].length = sizeof(client_nid);
	bufs[3] = *client_token;
	bufs[4] = *server_token;

	return sk_kdf(&kctx->skc_session_key, &kctx->skc_shared_key, bufs,
		      5, cfs_crypto_hash_alg(kctx->skc_hmac_alg));
}

/* Uses the session key to create an HMAC key and encryption key.  In
 * integrity mode the session key used to generate the HMAC key uses
 * session information which is available on the wire but by creating
 * a session based HMAC key we can prevent potential replay as both the
 * client and server have random numbers used as part of the key creation.
 *
 * The keys used for integrity and privacy are formulated as below using
 * the session key that is the output of the key derivation function.  The
 * HMAC algorithm is determined by the shared key algorithm selected in the
 * key file.
 *
 * For ski mode:
 * Session HMAC Key = PBKDF2("Integrity", KDF derived Session Key)
 *
 * For skpi mode:
 * Session HMAC Key = PBKDF2("Integrity", KDF derived Session Key)
 * Session Encryption Key = PBKDF2("Encrypt", KDF derived Session Key)
 *
 * \param[in,out]	skc		Shared key credentials structure with
 *
 * \return	-1		failure
 * \return	0		success
 */
int sk_compute_keys(struct sk_cred *skc)
{
	struct sk_kernel_ctx *kctx = &skc->sc_kctx;
	gss_buffer_desc *session_key = &kctx->skc_session_key;
	gss_buffer_desc *hmac_key = &kctx->skc_hmac_key;
	gss_buffer_desc *encrypt_key = &kctx->skc_encrypt_key;
	enum cfs_crypto_hash_alg hmac_alg;
	enum cfs_crypto_crypt_alg crypt_alg;
	char *encrypt = "Encrypt";
	char *integrity = "Integrity";
	int rc;

	hmac_alg = cfs_crypto_hash_alg(kctx->skc_hmac_alg);
	hmac_key->length = cfs_crypto_hash_digestsize(hmac_alg);
	hmac_key->value = malloc(hmac_key->length);
	if (!hmac_key->value)
		return -ENOMEM;

	rc = PKCS5_PBKDF2_HMAC(integrity, -1, session_key->value,
			       session_key->length, SK_PBKDF2_ITERATIONS,
			       sk_hash_to_evp_md(hmac_alg),
			       hmac_key->length, hmac_key->value);
	if (rc == 0)
		return -EINVAL;

	/* Encryption key is only populated in privacy mode */
	if ((skc->sc_flags & LGSS_SVC_PRIV) == 0)
		return 0;

	crypt_alg = cfs_crypto_crypt_alg(kctx->skc_crypt_alg);
	encrypt_key->length = cfs_crypto_crypt_keysize(crypt_alg);
	encrypt_key->value = malloc(encrypt_key->length);
	if (!encrypt_key->value)
		return -ENOMEM;

	rc = PKCS5_PBKDF2_HMAC(encrypt, -1, session_key->value,
			       session_key->length, SK_PBKDF2_ITERATIONS,
			       sk_hash_to_evp_md(hmac_alg),
			       encrypt_key->length, encrypt_key->value);
	if (rc == 0)
		return -EINVAL;

	return 0;
}

/**
 * Computes a session key based on the DH parameters from the host and its peer
 *
 * \param[in,out]	skc		Shared key credentials structure with
 *					the session key populated with the
 *					compute key
 * \param[in]		pub_key		Public key returned from peer in
 *					gss_buffer_desc
 * \return	gss error		failure
 * \return	GSS_S_COMPLETE		success
 */
uint32_t sk_compute_dh_key(struct sk_cred *skc, const gss_buffer_desc *pub_key)
{
	gss_buffer_desc *dh_shared = &skc->sc_dh_shared_key;
	BIGNUM *remote_pub_key;
	int status;
	uint32_t rc = GSS_S_FAILURE;

	remote_pub_key = BN_bin2bn(pub_key->value, pub_key->length, NULL);
	if (!remote_pub_key) {
		printerr(0, "Failed to convert binary to BIGNUM\n");
		return rc;
	}

	dh_shared->length = DH_size(skc->sc_params);
	dh_shared->value = malloc(dh_shared->length);
	if (!dh_shared->value) {
		printerr(0, "Failed to allocate memory for computed shared "
			 "secret key\n");
		goto out_err;
	}

	/* This compute the shared key from the DHKE */
	status = DH_compute_key(dh_shared->value, remote_pub_key,
				skc->sc_params);
	if (status == -1) {
		printerr(0, "DH_compute_key() failed: %s\n",
			 ERR_error_string(ERR_get_error(), NULL));
		goto out_err;
	} else if (status < dh_shared->length) {
		/* there is around 1 chance out of 256 that the returned
		 * shared key is shorter than expected
		 */
		if (status >= dh_shared->length - 2) {
			int shift = dh_shared->length - status;
			/* if the key is short by only 1 or 2 bytes, just
			 * prepend it with 0s
			 */
			memmove((void *)(dh_shared->value + shift),
				dh_shared->value, status);
			memset(dh_shared->value, 0, shift);
		} else {
			/* if the key is really too short, return GSS_S_BAD_QOP
			 * so that the caller can retry to generate
			 */
			printerr(0, "DH_compute_key() returned a short key of %d bytes, expected: %zu\n",
				 status, dh_shared->length);
			rc = GSS_S_BAD_QOP;
			goto out_err;
		}
	}

	rc = GSS_S_COMPLETE;

out_err:
	BN_free(remote_pub_key);
	return rc;
}

/**
 * Creates a serialized buffer for the kernel in the order of struct
 * sk_kernel_ctx.
 *
 * \param[in,out]	skc		Shared key credentials structure
 * \param[in,out]	ctx_token	Serialized buffer for kernel.
 *					Caller must free this buffer.
 *
 * \return	0	success
 * \return	-1	failure
 */
int sk_serialize_kctx(struct sk_cred *skc, gss_buffer_desc *ctx_token)
{
	struct sk_kernel_ctx *kctx = &skc->sc_kctx;
	char *p, *end;
	size_t bufsize;

	bufsize = sizeof(*kctx) + kctx->skc_hmac_key.length +
		  kctx->skc_encrypt_key.length;

	ctx_token->value = malloc(bufsize);
	if (!ctx_token->value)
		return -1;
	ctx_token->length = bufsize;

	p = ctx_token->value;
	end = p + ctx_token->length;

	if (WRITE_BYTES(&p, end, kctx->skc_version))
		return -1;
	if (WRITE_BYTES(&p, end, kctx->skc_hmac_alg))
		return -1;
	if (WRITE_BYTES(&p, end, kctx->skc_crypt_alg))
		return -1;
	if (WRITE_BYTES(&p, end, kctx->skc_expire))
		return -1;
	if (WRITE_BYTES(&p, end, kctx->skc_host_random))
		return -1;
	if (WRITE_BYTES(&p, end, kctx->skc_peer_random))
		return -1;
	if (write_buffer(&p, end, &kctx->skc_hmac_key))
		return -1;
	if (write_buffer(&p, end, &kctx->skc_encrypt_key))
		return -1;

	printerr(2, "Serialized buffer of %zu bytes for kernel\n", bufsize);

	return 0;
}

/**
 * Decodes a netstring \a ns into array of gss_buffer_descs at \a bufs
 * up to \a numbufs.  Memory is allocated for each value and length
 * will be populated with the length
 *
 * \param[in,out]	bufs	Array of gss_buffer_descs
 * \param[in,out]	numbufs	number of gss_buffer_desc in array
 * \param[in]		ns	netstring to decode
 *
 * \return	buffers populated	success
 * \return	-1			failure
 */
int sk_decode_netstring(gss_buffer_desc *bufs, int numbufs, gss_buffer_desc *ns)
{
	char *ptr = ns->value;
	size_t remain = ns->length;
	unsigned int size;
	int digits;
	int sep;
	int rc;
	int i;

	for (i = 0; i < numbufs; i++) {
		/* read the size of first buffer */
		rc = sscanf(ptr, "%9u", &size);
		if (rc < 1)
			goto out_err;
		digits = (size) ? ceil(log10(size + 1)) : 1;

		/* sep of current string */
		sep = size + digits + 2;

		/* check to make sure it's valid */
		if (remain < sep || ptr[digits] != ':' ||
		    ptr[sep - 1] != ',')
			goto out_err;

		bufs[i].length = size;
		if (size == 0) {
			bufs[i].value = NULL;
		} else {
			bufs[i].value = malloc(size);
			if (!bufs[i].value)
				goto out_err;
			memcpy(bufs[i].value, &ptr[digits + 1], size);
		}

		remain -= sep;
		ptr += sep;
	}

	printerr(2, "Decoded netstring of %zu bytes\n", ns->length);
	return i;

out_err:
	while (i-- > 0) {
		if (bufs[i].value)
			free(bufs[i].value);
		bufs[i].length = 0;
	}
	return -1;
}

/**
 * Creates a netstring in a gss_buffer_desc that consists of all
 * the gss_buffer_desc found in \a bufs.  The netstring should be treated
 * as binary as it can contain null characters.
 *
 * \param[in]		bufs		Array of gss_buffer_desc to use as input
 * \param[in]		numbufs		Number of buffers in array
 * \param[in,out]	ns		Destination gss_buffer_desc to hold
 *					netstring
 *
 * \return	-1	failure
 * \return	0	success
 */
int sk_encode_netstring(gss_buffer_desc *bufs, int numbufs,
			gss_buffer_desc *ns)
{
	unsigned char *ptr;
	int size = 0;
	int rc;
	int i;

	/* size of string in decimal, string size, colon, and comma */
	for (i = 0; i < numbufs; i++) {

		if (bufs[i].length == 0)
			size += 3;
		else
			size += ceil(log10(bufs[i].length + 1)) +
				bufs[i].length + 2;
	}

	ns->length = size;
	ns->value = malloc(ns->length);
	if (!ns->value) {
		ns->length = 0;
		return -1;
	}

	ptr = ns->value;
	for (i = 0; i < numbufs; i++) {
		/* size */
		rc = scnprintf((char *) ptr, size, "%zu:", bufs[i].length);
		ptr += rc;

		/* contents */
		memcpy(ptr, bufs[i].value, bufs[i].length);
		ptr += bufs[i].length;

		/* delimeter */
		*ptr++ = ',';

		size -= bufs[i].length + rc + 1;

		/* should not happen */
		if (size < 0)
			abort();
	}

	printerr(2, "Encoded netstring of %zu bytes\n", ns->length);
	return 0;
}
