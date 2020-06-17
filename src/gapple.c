#include <logging/log.h>

#include <tinycrypt/sha256.h>
#include <tinycrypt/hmac.h>
#include <bluetooth/crypto.h>
#include <tinycrypt/constants.h>

#include <fs/fs.h>

#include <posix/time.h>
#include <time.h>

LOG_MODULE_REGISTER(dp3t);

#include "set.h"

extern int have_fs, have_logfile;
extern u8_t *token;
extern struct fs_file_t logfile;

static struct fs_file_t ctxfile;
static int have_ctxfile;

#define TEKRollingPeriod 144

static uint32_t ENIntervalNumber(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  // TODO must be little endian
  return ts.tv_sec / 600;
}

// store 14 {tek, i} pairs
void next_tek(uint8_t *tek) {
  sys_csrand_get(tek,16);
}

int hkdf(const uint8_t *key, const size_t key_len,
         const uint8_t *salt, const size_t salt_len,
         const uint8_t *info, const size_t info_len,
         uint8_t *okm, const size_t okm_len) {
  LOG_HEXDUMP_INF(key, key_len, "key");
  LOG_HEXDUMP_INF(salt, salt_len, "salt");
  LOG_HEXDUMP_INF(info, info_len, "info");
  struct tc_hmac_state_struct ctx;

  // extract
  if(salt && salt_len>0) {
    LOG_INF("adding salt");
    if(TC_CRYPTO_FAIL==tc_hmac_set_key(&ctx, salt, salt_len)) {
        LOG_ERR("failed to hmac salt (update)");
        return -1;
    }
  } else {
    uint8_t zero_salt[TC_SHA256_DIGEST_SIZE]={0};
    LOG_INF("adding zero salt");
    if(TC_CRYPTO_FAIL==tc_hmac_set_key(&ctx, zero_salt, sizeof zero_salt)) {
        LOG_ERR("failed to hmac zero_salt (update)");
        return -1;
    }
  }

  if(TC_CRYPTO_FAIL==tc_hmac_init(&ctx)) {
    LOG_ERR("failed to init extractor HMAC");
    return -1;
  }

  if(TC_CRYPTO_FAIL==tc_hmac_update(&ctx, key, key_len)) {
    LOG_ERR("failed to set key of extractor HMAC");
    return -1;
  }


  uint8_t prk[TC_SHA256_DIGEST_SIZE];
  if(TC_CRYPTO_FAIL==tc_hmac_final(prk, TC_SHA256_DIGEST_SIZE, &ctx)) {
    LOG_ERR("failed to hmac prk (final)");
    return -1;
  }
  LOG_HEXDUMP_INF(prk, sizeof prk, "prk");

  // expand
  size_t i,L;
  uint8_t T[TC_SHA256_DIGEST_SIZE], c=1, *dptr=okm;
  for(L=okm_len;L>0;i++) {
    if(TC_CRYPTO_FAIL==tc_hmac_set_key(&ctx, prk, sizeof prk)) {
      LOG_ERR("failed to set key of HMAC");
      return -1;
    }
    if(TC_CRYPTO_FAIL==tc_hmac_init(&ctx)) {
      LOG_ERR("failed to init HMAC");
      return -1;
    }
    if(TC_CRYPTO_FAIL==tc_hmac_update (&ctx, T, c==1?0:sizeof T)) {
      LOG_ERR("failed to hmac (update)");
      return -1;
    }
    if(info && info_len>0) {
      if(TC_CRYPTO_FAIL==tc_hmac_update (&ctx, info, info_len)) {
        LOG_ERR("failed to hmac (update)");
        return -1;
      }
    }
    if(TC_CRYPTO_FAIL==tc_hmac_update (&ctx, &c, sizeof c)) {
      LOG_ERR("failed to hmac (update)");
      return -1;
    }
    c++;
    if(TC_CRYPTO_FAIL==tc_hmac_final(T, sizeof T, &ctx)) {
      LOG_ERR("failed to hmac (final)");
      return -1;
    }
    int len = (L>TC_SHA256_DIGEST_SIZE)?TC_SHA256_DIGEST_SIZE:L;
    memcpy(dptr,T,len);
    dptr+=len;
    L-=len;
  }
  return 0;
}

// Rolling Proximity Identifier Key 
int next_rpid(const uint8_t tek[16], uint8_t rpid[16]) {
  return hkdf(tek, sizeof tek, NULL, 0, "EN-RPIK", 7, rpid, 16);
}

void next_rpi(const uint8_t rpik[16], uint8_t rpi[16]) {
  uint8_t padded[16]="EN-RPI\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
  *((uint32_t*) (padded+12))=ENIntervalNumber();
  bt_encrypt_le(rpik, padded, rpi);
}

int next_aemk(const uint8_t tek[16], uint8_t aemk[16]) {
  return hkdf(tek, sizeof tek, NULL, 0, "EN-AEMK", 7, aemk, 16);
}

void get_aem(const uint8_t aemk[16], const uint8_t rpi[16], const uint8_t metadata[16], uint8_t aem[16]) {
  uint8_t ct[16];
  bt_encrypt_le(aemk, rpi, ct);
  int i;
  for(i=0;i<16;i++) aem[i]=metadata[i]^ct[i];
}

// a new day, a new SK
// SK = SHA256(SK)
static int next_sk(u8_t *SK) {
  struct tc_sha256_state_struct ctx;
  tc_sha256_init(&ctx);
  if(TC_CRYPTO_FAIL==tc_sha256_update (&ctx, SK, 32)) {
    LOG_ERR("failed to gen next SK (update)");
    return -1;
  }
  if(TC_CRYPTO_FAIL==tc_sha256_final(SK, &ctx)) {
    LOG_ERR("failed to gen next SK (final)");
    return -1;
  }
  return 0;
}

// tag is derived from SK and used as key in the AESCTR DBRG
// tag = HMAC-SHA256(SK, "broadcast key")
static int get_tag(const u8_t *SK, u8_t *tag) {
  struct tc_hmac_state_struct ctx;
  (void)memset(&ctx, 0x00, sizeof(ctx));
  if(TC_CRYPTO_FAIL==tc_hmac_set_key(&ctx, SK, 32)) {
    LOG_ERR("failed to set key of HMAC");
    return -1;
  }
  if(TC_CRYPTO_FAIL==tc_hmac_init(&ctx)) {
    LOG_ERR("failed to init HMAC");
    return -1;
  }
  if(TC_CRYPTO_FAIL==tc_hmac_update (&ctx, "broadcast key", 13)) {
    LOG_ERR("failed to hmac (update)");
    return -1;
  }
  if(TC_CRYPTO_FAIL==tc_hmac_final(tag, TC_SHA256_DIGEST_SIZE, &ctx)) {
    LOG_ERR("failed to hmac (final)");
    return -1;
  }
  return 0;
}

// get_ephid implements the PRG which derives the ith ephid using AES CTR
// ephid_i = AESCTR(tag, i)
static int get_ephid(const u8_t *tag, const u32_t i, u8_t *ephid) {
  u8_t ctr[16]={0};
  memcpy(ctr+12,&i,4);
  if(0!=bt_encrypt_le(tag, ctr, ephid)) {
    LOG_ERR("failed to aes-ctr ephid");
    return -1;
  }
  return 0;
}

static struct {
  time_t SK0_ts;      // counts the age of SK0 in days
  u8_t SK0[32];       // the oldest sk younger than 14 days
  u8_t SK[32];        // the current SK
  u8_t tag[TC_SHA256_DIGEST_SIZE];
  ephids_set ephids;
  time_t ephid_ts;
  u8_t ephid[16];
} ctx;

static void logctx(void) {
  struct tm t;
  if(&t!=gmtime_r(&ctx.SK0_ts, &t)) {
    LOG_ERR("cannot convert to time from SK0_ts");
  } else {
    LOG_INF("sk0_ts: %d-%d-%dT%d:%d:%d", 1900+t.tm_year, 1+t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
  }
  LOG_HEXDUMP_INF(ctx.SK0, sizeof ctx.SK0, "sk0");
  LOG_HEXDUMP_INF(ctx.SK, sizeof ctx.SK, "sk");
  LOG_HEXDUMP_INF(ctx.tag, sizeof ctx.tag, "tag");
  LOG_HEXDUMP_INF(&ctx.ephids, sizeof ctx.ephids, "ephids");
  if(&t!=gmtime_r(&ctx.ephid_ts, &t)) {
    LOG_ERR("cannot convert to time from ephid_ts");
  } else {
    LOG_INF("ephid_ts: %d-%d-%dT%d:%d:%d", 1900+t.tm_year, 1+t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
  }
  LOG_HEXDUMP_INF(ctx.ephid, sizeof ctx.ephid, "ephid");
}

static int savectx(void) {
  if(!have_fs || !have_ctxfile) return 1;
  LOG_INF("Saving dp3t ctx");
  // try to load last state from fs

  if(sizeof ctx != fs_write(&ctxfile, &ctx, sizeof ctx)) {
    LOG_ERR("failed to write dp3t.ctx");
    fs_close(&ctxfile);
    return 1;
  }

  if(0!=fs_sync(&ctxfile)) {
    LOG_ERR("Failed to sync ctxfile");
  }

  if(sizeof ctx != fs_seek(&ctxfile, 0, FS_SEEK_SET)) {
    LOG_ERR("failed to seek dp3t.ctxnew");
    fs_close(&ctxfile);
    have_ctxfile=0;
    return 1;
  }

  LOG_INF("Successfully saved dp3t.ctx");
  return 0;
}

static int advance_sk(void) {
  // generate next SK
  if(0!=next_sk(ctx.SK)) {
    LOG_ERR("failed to derive next SK");
    k_fatal_halt(4);
  }
  // while if SK0 is older than 14 days advance it
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  while(ctx.SK0_ts + 14*24*60*60 < ts.tv_sec) {
    next_sk(ctx.SK0);
    ctx.SK0_ts+=24*60*60;
  }
  // recalculate tag
  LOG_INF("recalculating tag");
  if(0!=get_tag(ctx.SK,ctx.tag)) {
    LOG_ERR("failed to derive tag from SK");
    k_fatal_halt(5);
  }

  // reset set of available ephids
  init_set(&ctx.ephids);
  return 0;
}

static void update_timer_handler(struct k_timer *dummy) {
  LOG_INF("dp3t update timer triggered");
  // get absolute time
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm t;
  if(&t!=gmtime_r(&ts.tv_sec, &t)) {
    LOG_ERR("cannot convert time from seconds since epoch");
    k_fatal_halt(2);
  }

  int advanced = 0;
  // check if close to midnight, if so, advance sk
  if((t.tm_hour==23 && t.tm_min > 60-DP3T_EPOCH/2) ||  (t.tm_hour==0 && t.tm_min < DP3T_EPOCH/2)) {
    LOG_INF("midnight advance SK");
    if(0!=advance_sk()) {
      LOG_ERR("failed to advance SK");
      k_fatal_halt(9);
    }
    advanced=1;
  }

  // get next ephid
  int ephid_idx = nextid(&ctx.ephids);
  // oops? invalid ephid idx from shuffled set?
  if(ephid_idx>=DP3T_EPIDS_PER_DAY) {
    LOG_ERR("invalid ephid idx from nextid: %d", ephid_idx);
    k_fatal_halt(1);
  }
  // nextid returned an error? probably the shuffled set is empty?
  if(ephid_idx==-1) {
    LOG_INF("nextid returned -1, empty set?");
    if(advanced) {
      LOG_ERR("failed to get next ephid directly after advancing SK");
      k_fatal_halt(10);
    }
    // most probably we have no more ids to chose from,
    // so we might want to check if we are close to midnight, if so advance SK
    if(!((t.tm_hour==23 && t.tm_min > 60-DP3T_EPOCH) ||  (t.tm_hour==0 && t.tm_min < DP3T_EPOCH))) {
      LOG_ERR("Error ran out of ephids and not close enough to midnight: %d-%d-%dT%d:%d:%d", 1900+t.tm_year, 1+t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
      k_fatal_halt(3);
    }
    if(0!=advance_sk()) {
      LOG_ERR("failed to advance SK after failing to get ephid the 1st time");
      k_fatal_halt(11);
    }
    ephid_idx = nextid(&ctx.ephids);
    LOG_INF("next id: %d", ephid_idx);
    if(ephid_idx>=DP3T_EPIDS_PER_DAY) {
      LOG_ERR("invalid ephid idx from nextid: %d", ephid_idx);
      k_fatal_halt(6);
    }
    if(ephid_idx==-1) {
      LOG_ERR("invalid ephid idx from nextid: %d - even after advancing SK!", ephid_idx);
      k_fatal_halt(7);
    }
  }
  if(0!=get_ephid(ctx.tag,ephid_idx,ctx.ephid)) {
    LOG_ERR("fatal error: failed to do aesctr for PRG");
    k_fatal_halt(8);
  }
  memcpy(token,ctx.ephid, sizeof ctx.ephid);
  memcpy(&ctx.ephid_ts, &ts.tv_sec, sizeof ctx.ephid_ts);
  logctx();
  savectx();
}

K_TIMER_DEFINE(update_timer, update_timer_handler, NULL);

static int loadctx(void) {
  if(!have_fs) return 1;

  if(0!=fs_open(&ctxfile, "/SD:/dp3t.ctx")) {
    LOG_ERR("Unable to open dp3t.ctx");
    have_ctxfile=0;
    return 1;
  } else {
    have_ctxfile=1;
  }

  // try to load last state from fs
  LOG_INF("attempting to load last dp3t ctx");

  if(sizeof ctx != fs_read(&ctxfile, &ctx, sizeof ctx)) {
    LOG_ERR("failed to load dp3t.ctx");
    return 1;
  }
  LOG_INF("loaded ctx, checking sanity");

  // do a sanity check that SK0 is a predecessor of SK within 14 days
  int i;
  uint8_t sk[sizeof ctx.SK];
  memcpy(sk,ctx.SK0,sizeof ctx.SK0);
  for(i=0;i<14;i++) {
    if(memcmp(sk,ctx.SK0,sizeof ctx.SK)==0) {
      break;
    }
    next_sk(sk);
  }
  if(i>=14) {
    LOG_ERR("loaded SK is not within 14 hashes of SK0, ctx is invalid");
    return 1;
  }
  if(ctx.SK0_ts<1591384118) {
    LOG_ERR("loaded SK0 is older than expected, ctx is invalid");
    return 1;
  }

  if(ctx.ephid_ts < ctx.SK0_ts) {
    LOG_ERR("loaded ephid is older than expected, ctx is invalid");
    return 1;
  }

  LOG_INF("verifying tag");
  u8_t tag[sizeof ctx.tag];
  if(0!=get_tag(ctx.SK,tag)) {
    LOG_ERR("failed to derive tag from SK");
    return 1;
  }
  if(memcmp(&ctx.tag,tag,sizeof tag)!=0) {
    LOG_ERR("tag in ctx is not derived from SK in ctx");
    return 1;
  }

  LOG_INF("Successfully verified dp3t.ctx");

  logctx();

  return 0;
}

int dp3t_init(void) {
  LOG_INF("Initializing DP3T");
  if(0!=loadctx()) {
    // no context found, start from scratch
    // initialize SK
    LOG_INF("Loading previous dp3t ctx failed, initializing SK");
    sys_csrand_get(ctx.SK,32);
    // make a copy of it to keep it for 14 "days"
    memcpy(ctx.SK0,ctx.SK,32);

    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    memcpy(&ctx.SK0_ts, &t.tv_sec, sizeof ctx.SK0_ts);

    memset(&ctx.ephid_ts,0,sizeof ctx.ephid_ts);
    memset(&ctx.ephid,0,sizeof ctx.ephid);

    init_set(&ctx.ephids);
    LOG_INF("Initializing tag");
    // tag needs to be calculated once, after changing SK
    if(0!=get_tag(ctx.SK,ctx.tag)) {
      LOG_ERR("failed to derive tag from SK");
    }
  }

  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  if(ctx.ephid_ts + DP3T_EPOCH_SECONDS <= t.tv_sec) {
    // ephid is too old, get a new one
    LOG_INF("getting fresh ephid");
    if(0!=get_ephid(ctx.tag,nextid(&ctx.ephids),ctx.ephid)) {
      LOG_ERR("failed to get ephid");
      return 1;
    }
    memcpy(token,&ctx.ephid, sizeof ctx.ephid);
    memcpy(&ctx.ephid_ts, &t.tv_sec, sizeof ctx.ephid_ts);
    // set timer to trigger changing ephids and possibly SK
    k_timer_start(&update_timer, K_SECONDS(DP3T_EPOCH_SECONDS), K_SECONDS(DP3T_EPOCH_SECONDS));
  } else {
    memcpy(token,&ctx.ephid, sizeof ctx.ephid);
    // set timer to - so that the current ephid still has some time before expiration - trigger changing ephids and possibly SK
    k_timer_start(&update_timer, K_SECONDS(ctx.ephid_ts - t.tv_sec + DP3T_EPOCH_SECONDS), K_SECONDS(DP3T_EPOCH_SECONDS));
  }

  if(have_fs) {
    savectx();
    if(0!=fs_open(&logfile, "/SD:/dp3t.log")) {
      LOG_ERR("Unable to open logfile");
      have_logfile = 0;
    } else if(0!=fs_seek(&logfile, 0, FS_SEEK_END)) {
      LOG_ERR("Unable to seek to end of logfile");
      have_logfile = 0;
    } else {
      have_logfile = 1;
    }
  }

  logctx();
  return 0;
}

void dp3t_stop(void) {
  k_timer_stop(&update_timer);
  savectx();
  fs_close(&logfile);
  fs_close(&ctxfile);
}


void testhkdf(void) {
  /*
   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
   salt = 0x000102030405060708090a0b0c (13 octets)
   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
   L    = 42

   PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
          90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
   OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
          34007208d5b887185865 (42 octets)
          
   IKM  = 0x000102030405060708090a0b0c0d0e0f
          101112131415161718191a1b1c1d1e1f
          202122232425262728292a2b2c2d2e2f
          303132333435363738393a3b3c3d3e3f
          404142434445464748494a4b4c4d4e4f (80 octets)
   salt = 0x606162636465666768696a6b6c6d6e6f
          707172737475767778797a7b7c7d7e7f
          808182838485868788898a8b8c8d8e8f
          909192939495969798999a9b9c9d9e9f
          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
   info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
          e0e1e2e3e4e5e6e7e8e9eaebecedeeef
          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
   L    = 82

   PRK  = 0x06a6b88c5853361a06104c9ceb35b45c
          ef760014904671014a193f40c15fc244 (32 octets)
   OKM  = 0xb11e398dc80327a1c8e7f78c596a4934
          4f012eda2d4efad8a050cc4c19afa97c
          59045a99cac7827271cb41c65e590e09
          da3275600c2f09b8367793a9aca3db71
          cc30c58179ec3e87c14c01d5c1f3434f
          1d87 (82 octets)
          
   Hash = SHA-256
   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
   salt = (0 octets)
   info = (0 octets)
   L    = 42

   PRK  = 0x19ef24a32c717b167f33a91d6f648bdf
          96596776afdb6377ac434c1c293ccb04 (32 octets)
   OKM  = 0x8da4e775a563c18f715f802a063c5a31
          b8a11f5c5ee1879ec3454e5f3c738d2d
          9d201395faa4b61a96c8 (42 octets)
  */
}
