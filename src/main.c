/* main.c - Application main entry point */

/*
 * Copyright (c) 2020 stf
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <device.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <sys/printk.h>
#include <sys/util.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include <tinycrypt/sha256.h>
#include <tinycrypt/hmac.h>
#include <bluetooth/crypto.h>
#include <tinycrypt/constants.h>

#include <disk/disk_access.h>
#include <logging/log.h>
#include <fs/fs.h>
#include <ff.h>

#include <devicetree.h>
#include <drivers/gpio.h>

LOG_MODULE_REGISTER(main);

#define DP3T_EPOCH 1
// how many times we run the main loop before advancing the ephid
#define RESEND_EPHIDS 20

// led0 on when advertizing
#define LED0_NODE DT_ALIAS(led0)
#define LED0   DT_GPIO_LABEL(LED0_NODE, gpios)
#define LED0_PIN DT_GPIO_PIN(LED0_NODE, gpios)
#if DT_PHA_HAS_CELL(LED0_NODE, gpios, flags)
#define LED0_FLAGS  DT_GPIO_FLAGS(LED0_NODE, gpios)
#else
#define LED0_FLAGS 0
#endif

// led1 on when receiving ephid
#define LED1_NODE DT_ALIAS(led1)
#define LED1   DT_GPIO_LABEL(LED1_NODE, gpios)
#define LED1_PIN DT_GPIO_PIN(LED1_NODE, gpios)
#if DT_PHA_HAS_CELL(LED1_NODE, gpios, flags)
#define LED1_FLAGS  DT_GPIO_FLAGS(LED1_NODE, gpios)
#else
#define LED1_FLAGS 0
#endif

// mutex so we can fsync the logfile in the main thread
// while the scan_cb thread tries to write to it
K_MUTEX_DEFINE(lf_mutex);

// led1 is initialized in main but used in scan_cb
struct device *led1_dev;

static FATFS fat_fs;
/* mounting info */
static struct fs_mount_t mp = {
   .type = FS_FATFS,
   .fs_data = &fat_fs,
};
static const char *disk_mount_pt = "/SD:";

// file handle for the logfile
static struct fs_file_t logfile;
// in case we don't have an sd card we skip using it
static int have_logfile = 0;

// holder for our current ephid
static u8_t mfg_data[] = { 0xc0, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// advertisment beacon
static const struct bt_data ad[] = {
	BT_DATA(BT_DATA_MANUFACTURER_DATA, mfg_data, 18),
};

// callback in case an advertisement is received
static void scan_cb(const bt_addr_le_t *addr, s8_t rssi, u8_t adv_type, struct net_buf_simple *buf) {
  // only handle c019 advertisments
  if(buf->len!=0x14 || (buf->data[2]!=0xc0 && buf->data[3]!=0x19)) return;
  // rx led on
  gpio_pin_set(led1_dev, LED1_PIN, 1);
  // only needed for devel/debug log on uart
  u8_t name[BT_ADDR_LE_STR_LEN];
  bt_addr_le_to_str(addr, name, BT_ADDR_LE_STR_LEN);
  printk("type: %d rssi: %d, addr %s ephid: %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n", adv_type, rssi, name,
         buf->data[4], buf->data[5], buf->data[6], buf->data[7], buf->data[8], buf->data[9], buf->data[10],
         buf->data[11], buf->data[12], buf->data[13], buf->data[14], buf->data[15], buf->data[16], buf->data[17],
         buf->data[18], buf->data[19]);
  // if we have a logfile we dump the rssid+ephid to it.
  if(have_logfile) {
    u8_t entry[16+sizeof rssi];
    memcpy(entry, &rssi, sizeof rssi);
    memcpy(entry+sizeof rssi, buf->data+2, 16);

    // we need to lock the mutex, since the main loop might want to
    // sync the logfile from time to time
    if (k_mutex_lock(&lf_mutex, K_MSEC(100)) == 0) {
      /* mutex successfully locked */
      if(sizeof entry != fs_write(&logfile, entry, sizeof entry)) {
        printk("failed to write log entry\n");
      }
      k_mutex_unlock(&lf_mutex);
    } else {
      printk("Cannot lock lf mutex for logging ephid\n");
    }
  }
  // rx led off
  gpio_pin_set(led1_dev, LED1_PIN, 0);
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

// we don't really need this function, for dev/debug purposes only
// copy from zephr samples
// todo remove from production code
static int lsdir(const char *path)
{
   int res;
   struct fs_dir_t dirp;
   static struct fs_dirent entry;

   /* Verify fs_opendir() */
   res = fs_opendir(&dirp, path);
   if (res) {
      LOG_ERR("Error opening dir %s [%d]", path, res);
      return res;
   }

   LOG_INF("Listing dir %s ...", path);
   for (;;) {
      /* Verify fs_readdir() */
      res = fs_readdir(&dirp, &entry);

      /* entry.name[0] == 0 means end-of-dir */
      if (res || entry.name[0] == 0) {
         break;
      }

      if (entry.type == FS_DIR_ENTRY_DIR) {
        LOG_INF("[DIR ] %s", entry.name);
      } else {
        LOG_INF("[FILE] %s (size = %zu)", log_strdup(entry.name), entry.size);
      }
   }

   /* Verify fs_closedir() */
   fs_closedir(&dirp);

   return res;
}

void main(void) {
  /* raw disk i/o */
  // mostly informative, only disk_access_init is needed
  do {
    static const char *disk_pdrv = "SD";
    u64_t memory_size_mb;
    u32_t block_count;
    u32_t block_size;

    if (disk_access_init(disk_pdrv) != 0) {
      LOG_ERR("Storage init ERROR!");
      break;
    }

    if (disk_access_ioctl(disk_pdrv,
                          DISK_IOCTL_GET_SECTOR_COUNT, &block_count)) {
      LOG_ERR("Unable to get sector count");
      break;
    }
    LOG_INF("Block count %u", block_count);

    if (disk_access_ioctl(disk_pdrv,
                          DISK_IOCTL_GET_SECTOR_SIZE, &block_size)) {
      LOG_ERR("Unable to get sector size");
      break;
    }
    LOG_INF("Sector size %u", block_size);

    memory_size_mb = (u64_t)block_count * block_size;
    LOG_INF("Memory Size(MB) %u", (u32_t)memory_size_mb>>20);
  } while (0);

  mp.mnt_point = disk_mount_pt;

  // try to mount the FAT partition on the SD card
  int res = fs_mount(&mp);

  if (res == FR_OK) {
    LOG_INF("Disk mounted.");
    // only for devel/debug ls the SD Card
    lsdir(disk_mount_pt);
    have_logfile = 1;
  } else {
    LOG_ERR("Error mounting disk.");
  }

  struct bt_le_scan_param scan_param = {
        .type       = BT_HCI_LE_SCAN_PASSIVE,
        .options    = BT_LE_SCAN_OPT_NONE,
        .interval   = 0x0010,
        .window     = 0x0010,
  };
  int err;

  LOG_INF("Starting Scanner/Advertiser Demo");

  u8_t SK_age=0; // counts the age of SK0 in days
  u8_t SK0[32], SK[32];
  // initialize SK
  LOG_INF("Initializing SK");
  sys_csrand_get(SK,32);
  // make a copy of it to keep it for 14 "days"
  memcpy(SK0,SK,32);

  u8_t tag[TC_SHA256_DIGEST_SIZE];
  // tag needs to be calculated once, after changing SK
  LOG_INF("Initializing tag");
  if(0!=get_tag(SK,tag)) {
    LOG_ERR("failed to derive tag from SK");
  }

  // counter, when it reaches 0 we advance ephid
  u32_t ephid_resend = RESEND_EPHIDS;
  u32_t ephid_ctr = 0; // how many ephids we generated from this SK
  u8_t *ephid = mfg_data+2; // the current ephid
  LOG_INF("Initializing ephid");
  if(0!=get_ephid(SK,ephid_ctr++,ephid)) {
    LOG_ERR("failed to get ephid");
  }

  /* Initialize the Bluetooth Subsystem */
  err = bt_enable(NULL);
  if (err) {
    LOG_ERR("Bluetooth init failed (err %d)", err);
    return;
  }

  LOG_INF("Bluetooth initialized");

  err = bt_le_scan_start(&scan_param, scan_cb);
  if (err) {
    LOG_ERR("Starting scanning failed (err %d)", err);
    return;
  }

  // logfile is a global var so it can be used in main and scan thread
  if(have_logfile) {
    if(0!=fs_open(&logfile, "/SD:/dp3t.log")) {
      LOG_ERR("Unable to open logfile");
      have_logfile = 0;
    } else if(0!=fs_seek(&logfile, 0, FS_SEEK_END)) {
      LOG_ERR("Unable to seek to end of logfile");
      have_logfile = 0;
    }
  }


  // tx led
  struct device *led0_dev;
  led0_dev = device_get_binding(LED0);
  if (led0_dev == NULL) {
    LOG_ERR("couldn't bind LED0");
  }
  if(0 > gpio_pin_configure(led0_dev, LED0_PIN, GPIO_OUTPUT_ACTIVE | LED0_FLAGS)) {
    LOG_ERR("couldn't configure LED0");
  }

  // rx led
  led1_dev = device_get_binding(LED1);
  if (led1_dev == NULL) {
    LOG_ERR("couldn't bind LED1");
  }
  if(0 > gpio_pin_configure(led1_dev, LED1_PIN, GPIO_OUTPUT_ACTIVE | LED1_FLAGS)) {
    LOG_ERR("couldn't configure LED1");
  }
  gpio_pin_set(led1_dev, LED1_PIN, 0);

  // main loop
  do {
    k_sleep(K_MSEC(1000));
    // tx led
    gpio_pin_set(led0_dev, LED0_PIN, 1);

    /* Start advertising */
    err = bt_le_adv_start(BT_LE_ADV_NCONN, ad, ARRAY_SIZE(ad),
                          NULL, 0);
    if (err) {
      LOG_ERR("Advertising failed to start (err %d)", err);
      return;
    }

    k_sleep(K_MSEC(400));

    err = bt_le_adv_stop();
    if (err) {
      LOG_ERR("Advertising failed to stop (err %d)", err);
      return;
    }

    gpio_pin_set(led0_dev, LED0_PIN, 0);

    if(--ephid_resend==0) {
      // did we send out (24*60/epoch ephids?
      // then we start the next "day"
      if(++ephid_ctr>=(24*60)/DP3T_EPOCH) {
        LOG_INF("advancing SK");
        ephid_ctr=0;
        // generate next SK
        if(0!=next_sk(SK)) {
          LOG_ERR("failed to derive next SK");
        }
        // handle SK0 aging and forgeting
        if(SK_age<14) { // oldest SK is younger than 14 days
          LOG_INF("aging SK0");
          SK_age++;
        } else {
          // forget old SK0 remember next one
          LOG_INF("ratcheting SK0");
          next_sk(SK0); // forget 15 day old SK, remember next one
        }
        // recalculate tag
        LOG_INF("recalculating tag");
        if(0!=get_tag(SK,tag)) {
          LOG_ERR("failed to derive tag from SK");
        }
      }
      LOG_INF("advancing ephid");
      if(0!=get_ephid(SK,ephid_ctr++,ephid)) {
        LOG_ERR("failed to get ephid");
      }
      ephid_resend = RESEND_EPHIDS;
    }

    if (k_mutex_lock(&lf_mutex, K_MSEC(100)) == 0) {
      /* mutex successfully locked */
      if(0!=fs_sync(&logfile)) {
        LOG_ERR("Failed to sync logfile");
      }
      k_mutex_unlock(&lf_mutex);
    } else {
      printk("Cannot lock lf mutex for syncing\n");
    }

  } while (1);
}
