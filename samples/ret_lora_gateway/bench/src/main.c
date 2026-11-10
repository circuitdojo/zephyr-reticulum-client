/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Path store benchmark: the gateway's store (ZMS, or LittleFS with
 * -DFILE_SUFFIX=lfs) under a fixed workload. Each phase reports the time
 * per operation and, on native_sim's simulated flash, the bytes read and
 * written per operation and the erases. Start from blank flash (native_sim:
 * a new --flash file).
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/linker/section_tags.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/printk.h>

#if defined(CONFIG_FLASH_SIMULATOR_STATS)
#include <zephyr/stats/stats.h>
#endif

#include "gateway.h"
#include "ret_crypto.h"

#define N   CONFIG_BENCH_PATHS
#define LEN CONFIG_BENCH_ANNOUNCE_LEN

static struct ret_transport_store *store;
static uint8_t announce[RET_MTU];
static uint8_t buf[RET_MTU];

struct counters {
	uint32_t read;
	uint32_t written;
	uint32_t erases;
};

#if defined(CONFIG_FLASH_SIMULATOR_STATS)
static struct stats_hdr *sim_stats;

static int find_group(struct stats_hdr *hdr, void *arg)
{
	ARG_UNUSED(arg);
	if (strcmp(hdr->s_name, "flash_sim_stats") == 0) {
		sim_stats = hdr;
		return 1;
	}
	return 0;
}

static int read_entry(struct stats_hdr *hdr, void *arg, const char *name, uint16_t off)
{
	struct counters *c = arg;
	uint32_t v = *(uint32_t *)((uint8_t *)hdr + off);

	if (strcmp(name, "bytes_read") == 0) {
		c->read = v;
	} else if (strcmp(name, "bytes_written") == 0) {
		c->written = v;
	} else if (strcmp(name, "flash_erase_calls") == 0) {
		c->erases = v;
	}
	return 0;
}
#endif

static bool counters(struct counters *c)
{
	memset(c, 0, sizeof(*c));
#if defined(CONFIG_FLASH_SIMULATOR_STATS)
	if (!sim_stats) {
		(void)stats_group_walk(find_group, NULL);
	}
	if (sim_stats) {
		(void)stats_walk(sim_stats, read_entry, c);
		return true;
	}
#endif
	return false;
}

/* Destination @p i: spread over all bytes, as real hashes are. */
static void dest_of(uint32_t i, uint8_t out[RET_TRUNC_HASH_LEN])
{
	uint32_t x = i * 2654435761u + 0x9e3779b9u;

	for (int k = 0; k < RET_TRUNC_HASH_LEN; k++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		out[k] = (uint8_t)x;
	}
}

static void meta_of(uint32_t i, struct ret_transport_path_meta *m)
{
	memset(m, 0, sizeof(*m));
	dest_of(i, m->dest_hash);
	memcpy(m->next_hop, m->dest_hash, RET_TRUNC_HASH_LEN);
	m->hops = 1 + i % 4;
	m->boot = 1;
	m->n_blobs = 1;
	m->timestamp = i;
}

enum op {
	OP_INSERT,
	OP_HIT_META,
	OP_HIT_ANNOUNCE,
	OP_MISS,
	OP_UPDATE_META,
	OP_REPLACE,
};

static const char *const op_names[] = {
	"insert", "hit (meta)", "hit (+announce)", "miss", "update meta", "replace announce",
};

static int run(enum op op, uint32_t i)
{
	struct ret_transport_path_meta m;
	size_t len;

	meta_of(i, &m);
	switch (op) {
	case OP_INSERT:
		return store->save(store, &m, announce, LEN);
	case OP_HIT_META:
		return store->load(store, m.dest_hash, &m, NULL, 0, NULL);
	case OP_HIT_ANNOUNCE:
		return store->load(store, m.dest_hash, &m, buf, sizeof(buf), &len);
	case OP_MISS: {
		/* Destinations past the inserted ones are absent. */
		int err;

		meta_of(i + N, &m);
		err = store->load(store, m.dest_hash, &m, NULL, 0, NULL);
		return err == -ENOENT ? 0 : -EFAULT;
	}
	case OP_UPDATE_META:
		m.hops++;
		return store->save(store, &m, NULL, 0);
	case OP_REPLACE:
		announce[0]++;
		return store->save(store, &m, announce, LEN);
	}
	return -EINVAL;
}

/* @p cycles from k_cycle_get_32() differences: the nRF91's RTC has no 64-bit count. */
static void report(const char *name, uint32_t ops, uint32_t cycles, const struct counters *a,
		   const struct counters *b, bool have, int failures)
{
	uint64_t us = k_cyc_to_us_floor64(cycles);

	printk("%-18s %5u ops %9llu us/op %8llu ms total", name, ops, us / ops, us / 1000);
	if (have) {
		printk(" %8u B read/op %7u B written/op %5u erases",
		       (b->read - a->read) / ops, (b->written - a->written) / ops,
		       b->erases - a->erases);
	}
	printk(failures ? " (%d FAILED)\n" : "\n", failures);
}

#if defined(CONFIG_RET_GATEWAY_STORE_ZMS)
#if DT_HAS_CHOSEN(zephyr_settings_partition)
#define SETTINGS_PART_ID DT_PARTITION_ID(DT_CHOSEN(zephyr_settings_partition))
#else
#define SETTINGS_PART_ID PARTITION_ID(storage_partition)
#endif

/* Start from blank flash: erase both ZMS partitions. */
static int wipe(void)
{
	const uint8_t ids[] = { PARTITION_ID(gw_paths_partition), SETTINGS_PART_ID };

	for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
		const struct flash_area *fa;
		int err = flash_area_open(ids[i], &fa);

		if (!err) {
			err = flash_area_erase(fa, 0, fa->fa_size);
			flash_area_close(fa);
		}
		if (err) {
			return err;
		}
	}
	return 0;
}
#else
static uint8_t found[CONFIG_RET_GATEWAY_STORE_MAX_PATHS][RET_TRUNC_HASH_LEN];
static size_t n_found;

static int note_path(const struct ret_transport_path_meta *meta, void *user)
{
	ARG_UNUSED(user);
	if (n_found == ARRAY_SIZE(found)) {
		return 1;
	}
	memcpy(found[n_found++], meta->dest_hash, RET_TRUNC_HASH_LEN);
	return 0;
}

/* Start from an empty store: remove an earlier run's paths. */
static int wipe_store(void)
{
	do {
		n_found = 0;
		(void)store->foreach(store, note_path, NULL);
		for (size_t i = 0; i < n_found; i++) {
			(void)store->remove(store, found[i]);
		}
	} while (n_found > 0);
	return 0;
}
#endif

/* The transport loads this many paths into RAM at boot (RET_TRANSPORT_PATHS). */
static int warm_path(const struct ret_transport_path_meta *meta, void *user)
{
	uint32_t *n = user;

	ARG_UNUSED(meta);
	return ++(*n) >= CONFIG_RET_TRANSPORT_PATHS;
}

/*
 * After a warm reboot (where one is possible): the store as the gateway
 * finds it at boot. Kept in RAM that a warm reboot doesn't clear.
 */
#define BOOT_MAGIC 0x5ee0b007
static __noinit uint32_t boot_phase;

static void measure_boot(void)
{
	uint32_t t0 = k_cycle_get_32();
	uint32_t t1;
	uint32_t t2;
	uint32_t warm = 0;
	int err = ret_crypto_init();

	if (!err) {
		err = settings_subsys_init();
	}
	if (!err) {
		err = store_init(&store);
	}
	t1 = k_cycle_get_32();
	if (!err) {
		err = store->foreach(store, warm_path, &warm);
	}
	t2 = k_cycle_get_32();
	if (err) {
		printk("boot: %d\n", err);
		return;
	}
	printk("boot: settings + store_init %u ms, transport's first %u paths %u ms\n",
	       (uint32_t)k_cyc_to_ms_floor32(t1 - t0), warm,
	       (uint32_t)k_cyc_to_ms_floor32(t2 - t1));
}

static int count_path(const struct ret_transport_path_meta *meta, void *user)
{
	ARG_UNUSED(meta);
	(*(uint32_t *)user)++;
	return 0;
}

int main(void)
{
	static const uint8_t id[64] = { 1 };
	struct counters a;
	struct counters b;
	bool have;
	uint32_t t0;
	uint32_t walked = 0;
	int err;

	if (boot_phase == BOOT_MAGIC) {
		boot_phase = 0;
		measure_boot();
		printk("BENCH DONE\n");
		return 0;
	}
	memset(announce, 0xa5, sizeof(announce));
#if defined(CONFIG_RET_GATEWAY_STORE_ZMS)
	err = wipe();
	if (err) {
		printk("wipe: %d\n", err);
		return 0;
	}
#endif
	err = ret_crypto_init();
	if (!err) {
		/* As the gateway: its identity is a setting next to the paths. */
		err = settings_subsys_init();
	}
	if (!err) {
		err = settings_save_one("gw/id", id, sizeof(id));
	}
	if (err) {
		printk("settings: %d\n", err);
		return 0;
	}

	have = counters(&a);
	t0 = k_cycle_get_32();
	err = store_init(&store);
	have = counters(&b);
	if (err) {
		printk("store_init: %d\n", err);
		return 0;
	}
#if !defined(CONFIG_RET_GATEWAY_STORE_ZMS)
	if (store_used_bytes() > 0) {
		/* Not timed: init above is, with the earlier run's paths. */
		(void)wipe_store();
		printk("removed an earlier run's paths\n");
	}
#endif
	printk("BENCH %s, %d paths, %d-byte announces\n",
	       IS_ENABLED(CONFIG_RET_GATEWAY_STORE_ZMS) ? "ZMS" : "LittleFS", N, LEN);
	report("init", 1, k_cycle_get_32() - t0, &a, &b, have, 0);

	for (enum op op = OP_INSERT; op <= OP_REPLACE; op++) {
		int failures = 0;

		counters(&a);
		t0 = k_cycle_get_32();
		for (uint32_t i = 0; i < N; i++) {
			if (run(op, i)) {
				failures++;
			}
		}
		uint32_t dt = k_cycle_get_32() - t0;

		counters(&b);
		report(op_names[op], N, dt, &a, &b, have, failures);
	}

	counters(&a);
	t0 = k_cycle_get_32();
	err = store->foreach(store, count_path, &walked);
	uint32_t dt = k_cycle_get_32() - t0;

	counters(&b);
	/* Every record, warm cache: not a boot (see measure_boot()). */
	report("read all", 1, dt, &a, &b, have, err ? 1 : 0);
	/* Once: ZMS computes free space by reading every entry. */
	ssize_t used = store_used_bytes();

	printk("walked %u paths, store uses %zd bytes of flash (%zd per path)\n", walked, used,
	       used / N);
#if defined(CONFIG_REBOOT) && !defined(CONFIG_BOARD_NATIVE_SIM)
	printk("rebooting to time the boot\n");
	boot_phase = BOOT_MAGIC;
	sys_reboot(SYS_REBOOT_WARM);
#endif
	printk("BENCH DONE\n");
	return 0;
}
