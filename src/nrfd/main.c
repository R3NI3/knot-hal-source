/*
 * Copyright (c) 2016, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <sys/inotify.h>
#include <json-c/json.h>

#include "manager.h"

#define BUF_LEN (sizeof(struct inotify_event))
#define MAX_NODES 5

static GMainLoop *main_loop;

static const char *opt_host = NULL;
static unsigned int opt_port = 9000;
static const char *opt_spi = "/dev/spidev0.0";
static const char *opt_nodes = "/etc/knot/keys.json";

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static struct known_nodes {
	uint64_t mac[MAX_NODES];
} known_nodes;

static GOptionEntry options[] = {
	{ "host", 'h', 0, G_OPTION_ARG_STRING, &opt_host,
					"host", "Host exposing nRF24L01 SPI" },
	{ "port", 'p', 0, G_OPTION_ARG_INT, &opt_port,
					"port", "Remote port" },
	{ "spi", 'i', 0, G_OPTION_ARG_STRING, &opt_spi,
					"spi", "SPI device path" },
	{ "nodes", 'n', 0, G_OPTION_ARG_STRING, &opt_nodes,
					"nodes", "Known nodes file path" },
	{ NULL },
};

static uint64_t string_to_mac(const char *mac_str)
{
	uint64_t hex[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	/*parse the input string into 8 bytes*/
	int rc = sscanf(mac_str, "%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx",
	hex, hex + 1, hex + 2, hex + 3, hex + 4, hex + 5, hex + 6, hex + 7);

	if (rc != 8) {
		printf("invalid mac address format: %s\n", mac_str);
		return 0;
	}
	/*concatenate each byte to form hole mac address*/
	hex[0] <<= 56;
	for (int i = 1; i < 8; i++)
		hex[0] |= (hex[i] << (56 - i*8));

	return hex[0];
}

static char *load_nodes(const char *file)
{
	int length;
	char *buffer;
	FILE *fl;

	fl = fopen(file, "r");
	if (fl == NULL) {
		printf("Failed to open file: %s", file);
		return NULL;
	}

	fseek(fl, 0, SEEK_END);
	length = ftell(fl);
	fseek(fl, 0, SEEK_SET);

	buffer = (char *) malloc((length + 1) * sizeof(char));
	if (buffer == NULL) {
		fclose(fl);
		return NULL;
	}

	if (fread(buffer, length, 1, fl) != 1) {
		free(buffer);
		fclose(fl);
		return NULL;
	}

	buffer[length] = '\0';

	fclose(fl);

	return buffer;
}

static int parse_nodes(const char *nodes_str)
{
	int array_len;
	json_object *jobj, *obj_keys, *obj_nodes, *obj_tmp;

	jobj = json_tokener_parse(nodes_str);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "keys", &obj_keys))
		goto failure;

	array_len = json_object_array_length(obj_keys);
	if (array_len > MAX_NODES) {
		printf("Invalid numbers of nodes in input archive");
		goto failure;
	}
	for (int i = 0; i < array_len; i++) {
		obj_nodes = json_object_array_get_idx(obj_keys, i);
		if (!json_object_object_get_ex(obj_nodes, "mac", &obj_tmp))
			goto failure;

		known_nodes.mac[i] = string_to_mac(
					json_object_get_string(obj_tmp));
		if (known_nodes.mac[i] == 0)
			goto failure;
	}

	/* Free mem used in json parse: */
	json_object_put(jobj);
	return 0;

failure:
	/* Free mem used in json parse: */
	json_object_put(jobj);
	return -EINVAL;
}

static gboolean inotify_cb(GIOChannel *gio, GIOCondition condition,
								gpointer data)
{
	int inotifyFD = g_io_channel_unix_get_fd(gio);
	char buf[BUF_LEN];
	ssize_t numRead;
	const struct inotify_event *event;

	numRead = read(inotifyFD, buf, BUF_LEN);
	if (numRead == -1)
		return FALSE;

	/*Process the event returned from read()*/
	event = (struct inotify_event *) buf;
	if (event->mask & IN_MODIFY)
		g_main_loop_quit(main_loop);

	return TRUE;
}

int main(int argc, char *argv[])
{
	char *nodes_str;
	GOptionContext *context;
	GError *gerr = NULL;
	GIOChannel *inotify_io;
	int err;
	int inotifyFD, wd;
	guint watch_id;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &gerr)) {
		printf("Invalid arguments: %s\n", gerr->message);
		g_error_free(gerr);
		g_option_context_free(context);
		return EXIT_FAILURE;
	}

	g_option_context_free(context);

	if (!opt_nodes) {
		printf("Missing KNOT known nodes file!\n");
		return EXIT_FAILURE;
	}
	/*load nodes' info from json file*/
	nodes_str = load_nodes(opt_nodes);
	if (!nodes_str)
		return EXIT_FAILURE;

	memset(&known_nodes, 0, sizeof(known_nodes));
	/*parse info loaded and writes it to struct known_nodes*/
	err = parse_nodes(nodes_str);
	free(nodes_str);
	if (err < 0)
		return EXIT_FAILURE;

	signal(SIGTERM, sig_term);
	signal(SIGINT, sig_term);
	signal(SIGPIPE, SIG_IGN);

	main_loop = g_main_loop_new(NULL, FALSE);

	printf("KNOT HAL phynrfd\n");
	if (opt_host)
		printf("Development mode: %s:%u\n", opt_host, opt_port);
	else
		printf("Native SPI mode\n");

	err = manager_start(opt_host, opt_port, opt_spi);
	if (err < 0) {
		g_main_loop_unref(main_loop);
		return EXIT_FAILURE;
	}

	/* starting inotify */
	inotifyFD = inotify_init();
	/*
	 * The path to file gatewayConfig.json with radio parameters will be
	 * received through command line in the future, this is just a temporary
	 * path as example.
	 */
	wd = inotify_add_watch(inotifyFD, "gatewayConfig.json", IN_MODIFY);
	if (wd == -1) {
		printf("Error adding watch on: gatewayConfig.json\n");
		close(inotifyFD);
		manager_stop();
		return EXIT_FAILURE;
	}

	/*Setting gio channel to watch inotify fd*/
	inotify_io = g_io_channel_unix_new(inotifyFD);
	watch_id = g_io_add_watch(inotify_io, G_IO_IN, inotify_cb, NULL);
	g_io_channel_set_close_on_unref(inotify_io, TRUE);

	g_main_loop_run(main_loop);

	g_source_remove(watch_id);
	g_io_channel_unref(inotify_io);
	 /*removing from the watch list.*/
	inotify_rm_watch(inotifyFD, wd);
	/*closing the INOTIFY instance*/
	close(inotifyFD);

	manager_stop();

	g_main_loop_unref(main_loop);

	return 0;
}
