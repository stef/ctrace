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

#include <disk/disk_access.h>
#include <logging/log.h>
#include <fs/fs.h>
#include <ff.h>

#include <devicetree.h>
#include <drivers/gpio.h>

#include <shell/shell.h>

#include <stdlib.h>
#include <posix/time.h>
#include <time.h>

#include "dp3t.h"

LOG_MODULE_REGISTER(main);

// led0 on when advertizing
#define LED0_NODE DT_ALIAS(led0)
#define LED0   DT_GPIO_LABEL(LED0_NODE, gpios)
#define TXLED_PIN DT_GPIO_PIN(LED0_NODE, gpios)
#if DT_PHA_HAS_CELL(LED0_NODE, gpios, flags)
#define TXLED_FLAGS  DT_GPIO_FLAGS(LED0_NODE, gpios)
#else
#define TXLED_FLAGS 0
#endif

// led1 on when receiving ephid
#define LED1_NODE DT_ALIAS(led1)
#define LED1   DT_GPIO_LABEL(LED1_NODE, gpios)
#define RXLED_PIN DT_GPIO_PIN(LED1_NODE, gpios)
#if DT_PHA_HAS_CELL(LED1_NODE, gpios, flags)
#define RXLED_FLAGS  DT_GPIO_FLAGS(LED1_NODE, gpios)
#else
#define RXLED_FLAGS 0
#endif

// mutex so we can fsync the logfile in the main thread
// while the scan_cb thread tries to write to it
K_MUTEX_DEFINE(lf_mutex);

// led1 is initialized in main but used in scan_cb
struct device *rxled;

static FATFS fat_fs;
/* mounting info */
static struct fs_mount_t mp = {
   .type = FS_FATFS,
   .fs_data = &fat_fs,
};

// file handle for the logfile
struct fs_file_t logfile;
// in case we don't have an sd card we skip using it
int have_fs = 0;
int have_logfile = 0;

// holder for our current ephid
static u8_t mfg_data[] = { 0xc0, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const u8_t *token = mfg_data + 2;

// advertisment beacon
static const struct bt_data ad[] = {
	BT_DATA(BT_DATA_MANUFACTURER_DATA, mfg_data, 18),
};

// callback in case an advertisement is received
static void scan_cb(const bt_addr_le_t *addr, s8_t rssi, u8_t adv_type, struct net_buf_simple *buf) {
  // only handle c019 advertisments
  if(buf->len!=0x14 || (buf->data[2]!=0xc0 && buf->data[3]!=0x19)) return;
  // rx led on
  gpio_pin_set(rxled, RXLED_PIN, 1);
  // only needed for devel/debug log on uart
  u8_t name[BT_ADDR_LE_STR_LEN];
  bt_addr_le_to_str(addr, name, BT_ADDR_LE_STR_LEN);
  printk("type: %d rssi: %d, addr %s ephid: %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n", adv_type, rssi, name,
         buf->data[4], buf->data[5], buf->data[6], buf->data[7], buf->data[8], buf->data[9], buf->data[10],
         buf->data[11], buf->data[12], buf->data[13], buf->data[14], buf->data[15], buf->data[16], buf->data[17],
         buf->data[18], buf->data[19]);
  // if we have a logfile we dump the rssid+ephid to it.
  if(have_fs) {
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
  gpio_pin_set(rxled, RXLED_PIN, 0);
}

static int cmd_ctrace_gettime(const struct shell *shell, size_t argc, char **argv) {
  ARG_UNUSED(argc);
  ARG_UNUSED(argv);

  struct timespec tspec;
  clock_gettime(CLOCK_REALTIME, &tspec);
  struct tm t;
  if(&t!=gmtime_r(&tspec.tv_sec, &t)) {
    shell_error(shell,"cannot convert time from seconds since epoch");
    return 1;
  }
  shell_print(shell, "%d-%d-%dT%d:%d:%d", 1900+t.tm_year, 1+t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
  return 0;
}

static int cmd_ctrace_settime(const struct shell *shell, size_t argc, char **argv) {
  if(argc!=2) {
    shell_error(shell, "Must provide seconds since unix epoch as parameter.");
    return 1;
  }
  struct timespec tspec;
  tspec.tv_sec = atoi(argv[1]);
  tspec.tv_nsec = 0;
  if(0!=clock_settime(CLOCK_REALTIME, &tspec)) {
    shell_error(shell, "Cannot set time");
    return 1;
  }

  return 0;
}

/* Creating subcommands (level 1 command) array for command "demo". */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_ctrace,
        SHELL_CMD(settime, NULL, "set time command.", cmd_ctrace_settime),
        SHELL_CMD(gettime, NULL, "get time command.", cmd_ctrace_gettime),
        SHELL_SUBCMD_SET_END
);
/* Creating root (level 0) command "ctrace" without a handler */
SHELL_CMD_REGISTER(ctrace, &sub_ctrace, "ctrace commands", NULL);

static int fs_init(void) {
  /* raw disk i/o */
  static const char *disk_pdrv = "SD";
  if (disk_access_init(disk_pdrv) != 0) {
    LOG_ERR("Storage init ERROR!");
    return 0;
  }

  mp.mnt_point = "/SD:";
  // try to mount the FAT partition on the SD card
  if (fs_mount(&mp) != FR_OK) {
    LOG_ERR("Error mounting disk.");
    return 0;
  }
  LOG_INF("Disk mounted.");

  return 1;
}

static struct device* led_init(const char *name, gpio_pin_t pin, gpio_flags_t flags) {
  struct device *led_dev = device_get_binding(name);
  if (led_dev == NULL) {
    LOG_ERR("couldn't bind %s", name);
    return NULL;
  }
  if(0 > gpio_pin_configure(led_dev, pin, GPIO_OUTPUT_ACTIVE | flags)) {
    LOG_ERR("couldn't configure %s", name);
    return NULL;
  }
  // switch off led
  gpio_pin_set(led_dev, pin, 0);
  return led_dev;
}

static void init_clock(struct device *txled) {
  struct timespec t;
  // block until time is set
  LOG_INF("Blocking until clock is set via UART");
  do {
    gpio_pin_set(txled, TXLED_PIN, 1);
    gpio_pin_set(rxled, RXLED_PIN, 0);
    k_sleep(K_MSEC(100));
    clock_gettime(CLOCK_REALTIME, &t);
    gpio_pin_set(txled, TXLED_PIN, 0);
    gpio_pin_set(rxled, RXLED_PIN, 1);
    k_sleep(K_MSEC(100));
  } while(t.tv_sec<1591384118);
    gpio_pin_set(rxled, RXLED_PIN, 0);
}

void main(void) {
  have_fs = fs_init();

  // tx led
  struct device *txled = led_init(LED0, TXLED_PIN, TXLED_FLAGS);
  // rx led (is global)
  rxled = led_init(LED1, RXLED_PIN, RXLED_FLAGS);

  init_clock(txled);

  if(0!=dp3t_init()) {
    LOG_ERR("failed to init dp3t");
    return;
  }

  // ble setup
  struct bt_le_scan_param scan_param = {
        .type       = BT_HCI_LE_SCAN_PASSIVE,
        .options    = BT_LE_SCAN_OPT_NONE,
        .interval   = 0x0010,
        .window     = 0x0010,
  };
  int err;

  LOG_INF("Starting Bluetooth subsystem");
  /* Initialize the Bluetooth Subsystem */
  err = bt_enable(NULL);
  if (err) {
    LOG_ERR("Bluetooth init failed (err %d)", err);
    return;
  }

  LOG_INF("Bluetooth initialized");

  err = bt_le_scan_start(&scan_param, scan_cb);
  if (err) {
    LOG_ERR("Starting to scan failed (err %d)", err);
    return;
  }

  // main loop
  do {
    k_sleep(K_MSEC(1000));
    // tx led
    gpio_pin_set(txled, TXLED_PIN, 1);

    /* Start advertising */
    err = bt_le_adv_start(BT_LE_ADV_NCONN, ad, ARRAY_SIZE(ad), NULL, 0);
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

    gpio_pin_set(txled, TXLED_PIN, 0);

    if (k_mutex_lock(&lf_mutex, K_MSEC(10)) == 0) {
      /* mutex successfully locked */
      if(0!=fs_sync(&logfile)) {
        LOG_ERR("Failed to sync logfile");
      }
      k_mutex_unlock(&lf_mutex);
    } else {
      LOG_WRN("Cannot lock lf mutex for syncing");
    }

  } while (1);
}
