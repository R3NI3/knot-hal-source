/*
 * Copyright (c) 2016, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <glib.h>
#include <gio/gio.h>
#include <json-c/json.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "include/nrf24.h"
#include "include/comm.h"
#include "include/time.h"
#include "dbus-obj-manager/nrf-object-manager.h"

#include "nrf24l01_io.h"
#include "include/linux_log.h"
#include "manager.h"

#define KNOTD_UNIX_ADDRESS		"knot"
#define MAC_ADDRESS_SIZE		24
#define BCAST_TIMEOUT			10000

#ifndef MIN
#define MIN(a,b) 			(((a) < (b)) ? (a) : (b))
#endif

static int mgmtfd;
static guint mgmtwatch;
static guint dbus_id;

static struct adapter {
	struct nrf24_mac mac;
	/* file with struct keys */
	gchar *file_name;
	gboolean powered;
	/* Struct with the known peers */
	struct {
		struct nrf24_mac addr;
		gchar *alias;
	} known_peers[MAX_PEERS];
	guint known_peers_size;
} adapter;

struct peer {
	char name[10];
	uint64_t mac;
	int8_t socket_fd;
	int8_t knotd_fd;
	GIOChannel *knotd_io;
	guint knotd_id;
};

static struct peer peers[MAX_PEERS] = {
	{.socket_fd = -1},
	{.socket_fd = -1},
	{.socket_fd = -1},
	{.socket_fd = -1},
	{.socket_fd = -1}
};

struct bcast_presence {
	char name[20];
	unsigned long last_beacon;
};

static GHashTable *peer_bcast_table;
static uint8_t count_clients;

static GDBusObjectManagerServer *manager = NULL;
static GSList *proxy_list = NULL;

static int write_file(const gchar *addr, const gchar *key, const gchar *name)
{
	int array_len;
	int i;
	int err = -EINVAL;
	json_object *jobj, *jobj2;
	json_object *obj_keys, *obj_array, *obj_tmp, *obj_mac;

	/* Load nodes' info from json file */
	jobj = json_object_from_file(adapter.file_name);
	if (!jobj)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "keys", &obj_keys))
		goto failure;

	array_len = json_object_array_length(obj_keys);
	/*
	 * If name and key are NULL it means to remove element
	 * If only name is NULL, update some element
	 * Otherwise add some element to file
	 */
	if (name == NULL && key == NULL) {
		jobj2 = json_object_new_object();
		obj_array = json_object_new_array();
		for (i = 0; i < array_len; i++) {
			obj_tmp = json_object_array_get_idx(obj_keys, i);
			if (!json_object_object_get_ex(obj_tmp, "mac",
								&obj_mac))
				goto failure;

		/* Parse mac address string into struct nrf24_mac known_peers */
			if (g_strcmp0(json_object_get_string(obj_mac), addr)
									!= 0)
				json_object_array_add(obj_array,
						json_object_get(obj_tmp));
		}
		json_object_object_add(jobj2, "keys", obj_array);
		json_object_to_file(adapter.file_name, jobj2);
		json_object_put(jobj2);
	} else if (name == NULL) {
	/* TODO update key of some mac (depends on adding keys to file) */
	} else {
		obj_tmp = json_object_new_object();
		json_object_object_add(obj_tmp, "name",
						json_object_new_string(name));
		json_object_object_add(obj_tmp, "mac",
						json_object_new_string(addr));
		json_object_array_add(obj_keys, obj_tmp);
		json_object_to_file(adapter.file_name, jobj);
	}

	err = 0;
failure:
	json_object_put(jobj);
	return err;
}

static void on_properties_changed(GDBusProxy *proxy,
				GVariant *changed_properties,
				const gchar *const *invalidated_properties,
				gpointer user_data)
{
	write_file(NULL, "tmp", NULL);
	/* TODO: implement action for some properties changed like powered */
}

static gboolean parse_input(Device1 *dev, GVariantDict *properties)
{
	const gchar *in_str;
	gboolean in_bool = FALSE;
	/* PublicKey and Name are optional arguments, others are mandatory */
	if (g_variant_dict_lookup(properties, "PublicKey", "&s", &in_str))
		device1_set_publickey(dev, in_str);

	if (g_variant_dict_lookup(properties, "Name", "&s", &in_str))
		device1_set_name(dev, in_str);

	if (!g_variant_dict_lookup(properties, "Address", "&s", &in_str))
		return FALSE;
	device1_set_address(dev, in_str);

	if (!g_variant_dict_lookup(properties, "Allowed", "b", &in_bool))
		return FALSE;
	device1_set_allowed(dev, in_bool);

	if (!g_variant_dict_lookup(properties, "Connected", "b", &in_bool))
		return FALSE;
	device1_set_connected(dev, in_bool);

	if (g_variant_dict_lookup(properties, "Broadcasting", "b", &in_bool))
		device1_set_broadcasting(dev, in_bool);
	else
		device1_set_broadcasting(dev, FALSE);

	return TRUE;
}

static int32_t add_dev_interface(const gchar *adpt_path, GVariant *properties,
							gpointer user_data)
{
	Device1 *new_dev;
	ObjectSkeleton *obj_skl;
	GVariantDict *prop;
	struct nrf24_mac dev_addr;
	uint32_t i;
	gchar *path;
	gboolean is_exported;

	new_dev = device1_skeleton_new();
	/* Parse the properties passed */
	prop =  g_variant_dict_new(properties);
	if (!parse_input(new_dev, prop)) {
		g_variant_dict_unref(prop);
		g_object_unref(new_dev);
		return -EINVAL;
	}
	g_variant_dict_unref(prop);
	device1_set_adapter(new_dev, adpt_path);

	if (nrf24_str2mac(device1_get_address(new_dev), &dev_addr) < 0) {
		g_object_unref(new_dev);
		return -EINVAL;
	}

	path = g_strdup_printf(
		"%s/dev%02hhx_%02hhx_%02hhx_%02hhx_%02hhx_%02hhx_%02hhx_%02hhx",
		adpt_path,
		dev_addr.address.b[0], dev_addr.address.b[1],
		dev_addr.address.b[2], dev_addr.address.b[3],
		dev_addr.address.b[4], dev_addr.address.b[5],
		dev_addr.address.b[6], dev_addr.address.b[7]);

	obj_skl = object_skeleton_new(path);
	object_skeleton_set_device1(obj_skl, new_dev);
	g_object_unref(new_dev);

	is_exported = g_dbus_object_manager_server_is_exported(manager,
					G_DBUS_OBJECT_SKELETON(obj_skl));
	if (!is_exported)
		g_dbus_object_manager_server_export(manager,
					G_DBUS_OBJECT_SKELETON(obj_skl));

	g_object_unref(obj_skl);
	g_free(path);
	/* Does not set new device as persistent */
	if (!user_data)
		goto done;

	/* Check if device is already on persistent storage */
	for (i = 0; i < MAX_PEERS; i++) {
		if (dev_addr.address.uint64 ==
				adapter.known_peers[i].addr.address.uint64)
			goto done;
	}
	/* Put device on persistent storage */
	for (i = 0; i < MAX_PEERS; i++) {
		if (adapter.known_peers[i].addr.address.uint64 == 0) {
			adapter.known_peers[i].addr.address.uint64 =
						dev_addr.address.uint64;
			g_free(adapter.known_peers[i].alias);
			adapter.known_peers[i].alias =
					g_strdup(device1_get_name(new_dev));
			adapter.known_peers_size++;
			write_file(device1_get_address(new_dev),
						"",
						adapter.known_peers[i].alias);
			break;
		}
	}

done:
	return 0;
}

static void add_known_device(Adapter1 *adpt, GDBusMethodInvocation *invocation,
				GVariant *properties, gpointer user_data)
{
	const gchar *adpt_path;

	g_object_ref(invocation);

	adpt_path = g_dbus_method_invocation_get_object_path(invocation);
	if (add_dev_interface(adpt_path, properties, user_data) < 0) {
		g_dbus_method_invocation_return_dbus_error(invocation,
					"org.cesar.nrf.Error.InvalidArguments",
					"Invalid Address Format");
		return;
	}

	adapter1_complete_add_device(adpt, invocation);
}

static void remove_known_device(Adapter1 *adpt,
					GDBusMethodInvocation *invocation,
					gchar *object, gpointer user_data)
{
	uint32_t i;
	struct nrf24_mac addr;
	gchar mac_str[MAC_ADDRESS_SIZE];
	gchar tmp[21];

	memset(&addr, 0, sizeof(addr));
	g_object_ref(invocation);

	if (sscanf(object,
		"%20s/dev%02hhx_%02hhx_%02hhx_%02hhx_%02hhx_%02hhx_%02hhx_%02hhx",
		tmp, &addr.address.b[0], &addr.address.b[1], &addr.address.b[2],
		&addr.address.b[3], &addr.address.b[4], &addr.address.b[5],
		&addr.address.b[6], &addr.address.b[7]) != 9) {
		g_dbus_method_invocation_return_dbus_error(invocation,
					"org.cesar.nrf.Error.InvalidArguments",
					"Invalid Object Format");
		return;
	}

	for (i = 0; i < MAX_PEERS; i++) {
		if (adapter.known_peers[i].addr.address.uint64 ==
							addr.address.uint64) {
			adapter.known_peers[i].addr.address.uint64 = 0;
			adapter.known_peers_size--;
			nrf24_mac2str(&addr, mac_str);
			write_file(mac_str, NULL, NULL);
			break;
		}
	}

	/*TODO: remove device from the adapter known_devices struct */
	g_dbus_object_manager_server_unexport(manager, object);
	adapter1_complete_remove_device(adpt, invocation);

}

static void on_bus_acquired(GDBusConnection *connection, const gchar *name,
							gpointer user_data)
{
	uint8_t j;
	ObjectSkeleton *obj_skl;
	GVariantBuilder builder;
	char address[MAC_ADDRESS_SIZE];
	Adapter1 *adpt;
	Adapter1 *adpt_proxy;
	gchar *adpt_path;
	GVariant *properties;

	manager = g_dbus_object_manager_server_new("/org/cesar");
	g_dbus_object_manager_server_set_connection(manager, connection);

	adpt_path = g_strdup("/org/cesar/knot/nrf0");
	obj_skl = object_skeleton_new(adpt_path);

	adpt = adapter1_skeleton_new();
	adapter1_set_powered(adpt, TRUE);
	if (nrf24_mac2str(&adapter.mac, address) == 0)
		adapter1_set_address(adpt, address);

	adapter1_set_scan(adpt, FALSE);
	object_skeleton_set_adapter1(obj_skl, adpt);

	g_signal_connect(adpt, "handle-remove-device",
					G_CALLBACK(remove_known_device), NULL);

	g_signal_connect(adpt, "handle-add-device",
					G_CALLBACK(add_known_device),
					connection);

	g_dbus_object_manager_server_export(manager,
					G_DBUS_OBJECT_SKELETON(obj_skl));
	g_object_unref(obj_skl);

	adpt_proxy = adapter1_proxy_new_sync(connection,
						G_DBUS_PROXY_FLAGS_NONE,
						"org.cesar.knot.nrf",
						adpt_path, NULL,
						NULL);

	g_signal_connect(adpt_proxy, "g-properties-changed",
				G_CALLBACK(on_properties_changed), NULL);

	proxy_list = g_slist_prepend(proxy_list, adpt_proxy);

	/* Register on dbus every device already known */
	for (j = 0; j < adapter.known_peers_size; j++) {
		if (nrf24_mac2str(&adapter.known_peers[j].addr, address) < 0) {
			hal_log_error("Invalid stored mac address");
			continue;
		}

		g_variant_builder_init(&builder, G_VARIANT_TYPE_ARRAY);
		g_variant_builder_add(&builder, "{sv}", "Name",
			g_variant_new_string(adapter.known_peers[j].alias));
		g_variant_builder_add(&builder, "{sv}", "Address",
						g_variant_new_string(address));
		g_variant_builder_add(&builder, "{sv}", "Connected",
						g_variant_new_boolean(FALSE));
		g_variant_builder_add(&builder, "{sv}", "Allowed",
						g_variant_new_boolean(TRUE));
		g_variant_builder_add(&builder, "{sv}", "Broadcasting",
						g_variant_new_boolean(FALSE));

		properties = g_variant_builder_end(&builder);
		/* Create dbus objects for devices on persistent storage */
		if (add_dev_interface(adpt_path, properties, NULL) < 0)
			hal_log_error("Invalid values stored on keys.json\n");

		g_variant_unref(properties);
	}
	g_object_unref(adpt);
	g_free(adpt_path);
}

static void on_name_acquired(GDBusConnection *connection, const gchar *name,
							gpointer user_data)
{
	/* Connection successfully estabilished */
	hal_log_info("Connection estabilished");
}

static void on_name_lost(GDBusConnection *connection, const gchar *name,
							gpointer user_data)
{
	if (!connection) {
		/* Connection error */
		hal_log_error("Connection failure");
	} else {
		/* Name not owned */
		hal_log_error("Name can't be obtained");
	}

	g_free(adapter.file_name);
	exit(EXIT_FAILURE);
}

static guint dbus_init(struct nrf24_mac mac)
{
	guint owner_id;

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
					"org.cesar.knot.nrf",
					G_BUS_NAME_OWNER_FLAGS_NONE,
					on_bus_acquired, on_name_acquired,
					on_name_lost, NULL, NULL);
	adapter.mac = mac;
	adapter.powered = TRUE;

	return owner_id;
}

static void dbus_on_close(guint owner_id)
{
	uint8_t i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (adapter.known_peers[i].addr.address.uint64 != 0)
			g_free(adapter.known_peers[i].alias);
	}
	g_free(adapter.file_name);
	g_bus_unown_name(owner_id);
	g_slist_free_full(proxy_list, g_object_unref);
}

/* Check if peer is on list of known peers */
static int8_t check_permission(struct nrf24_mac mac)
{
	uint8_t i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (mac.address.uint64 ==
				adapter.known_peers[i].addr.address.uint64)
			return 0;
	}

	return -EPERM;
}

/* Get peer position in vector of peers*/
static int8_t get_peer(struct nrf24_mac mac)
{
	int8_t i;

	for (i = 0; i < MAX_PEERS; i++)
		if (peers[i].socket_fd != -1 &&
			peers[i].mac == mac.address.uint64)
			return i;

	return -EINVAL;
}

/* Get free position in vector for peers*/
static int8_t get_peer_index(void)
{
	int8_t i;

	for (i = 0; i < MAX_PEERS; i++)
		if (peers[i].socket_fd == -1)
			return i;

	return -EUSERS;
}

static int connect_unix(void)
{
	struct sockaddr_un addr;
	int sock;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -errno;

	/* Represents unix socket from nrfd to knotd */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path + 1, KNOTD_UNIX_ADDRESS,
					strlen(KNOTD_UNIX_ADDRESS));

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1)
		return -errno;

	return sock;
}

static void knotd_io_destroy(gpointer user_data)
{
	struct peer *p = (struct peer *)user_data;
	hal_comm_close(p->socket_fd);
	close(p->knotd_fd);
	p->socket_fd = -1;
	p->knotd_id = 0;
	p->knotd_io = NULL;
	count_clients--;
}

static gboolean knotd_io_watch(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{

	char buffer[128];
	ssize_t readbytes_knotd;
	struct peer *p = (struct peer *)user_data;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	/* Read data from Knotd */
	readbytes_knotd = read(p->knotd_fd, buffer, sizeof(buffer));
	if (readbytes_knotd < 0) {
		hal_log_error("read_knotd() error");
		return FALSE;
	}

	/* Send data to thing */
	/* TODO: put data in list for transmission */
	hal_comm_write(p->socket_fd, buffer, readbytes_knotd);

	return TRUE;
}

static int8_t evt_presence(struct mgmt_nrf24_header *mhdr)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	int8_t position;
	int err;
	char mac_str[MAC_ADDRESS_SIZE];
	struct bcast_presence *peer;
	struct mgmt_evt_nrf24_bcast_presence *evt_pre =
			(struct mgmt_evt_nrf24_bcast_presence *) mhdr->payload;
	GVariantBuilder builder;
	gchar *adpt_path;
	GVariant *properties;

	nrf24_mac2str(&evt_pre->mac, mac_str);
	peer = g_hash_table_lookup(peer_bcast_table, mac_str);
	if (peer != NULL) {
		peer->last_beacon = hal_time_ms();
		goto done;
	}
	peer = g_try_new0(struct bcast_presence, 1);
	if (peer == NULL)
		return -ENOMEM;
	/*
	 * Print every MAC sending presence in order to ease the discover of
	 * things trying to connect to the gw.
	 */
	hal_log_info("Thing sending presence. MAC = %s Name = %s",
							mac_str, evt_pre->name);
	peer->last_beacon = hal_time_ms();
	strncpy(peer->name, (char *) evt_pre->name,
					MIN(sizeof(peer->name) - 1,
						strlen((char *)evt_pre->name)));
	/*
	 * MAC and device name will be printed only once, but the last presence
	 * time is updated. Every time a user refresh the list in the webui
	 * we will discard devices that broadcasted
	 */
	g_hash_table_insert(peer_bcast_table, g_strdup(mac_str), peer);

	/* Set properties and insert new dbus object for this device */
	g_variant_builder_init(&builder,  G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(&builder, "{sv}", "Name",
					g_variant_new_string((char *) evt_pre->name));
	g_variant_builder_add(&builder, "{sv}", "Address",
						g_variant_new_string(mac_str));
	g_variant_builder_add(&builder, "{sv}", "Connected",
						g_variant_new_boolean(FALSE));
	g_variant_builder_add(&builder, "{sv}", "Allowed",
						g_variant_new_boolean(FALSE));
	g_variant_builder_add(&builder, "{sv}", "Broadcasting",
						g_variant_new_boolean(TRUE));

	adpt_path = g_strdup("/org/cesar/knot/nrf0");

	properties = g_variant_builder_end(&builder);
	add_dev_interface(adpt_path, properties, NULL);

	g_variant_unref(properties);
	g_free(adpt_path);
done:
	/* Check if peer is allowed to connect */
	if (check_permission(evt_pre->mac) < 0)
		return -EPERM;

	if (count_clients >= MAX_PEERS)
		return -EUSERS; /*MAX PEERS*/

	/*Check if this peer is already allocated */
	position = get_peer(evt_pre->mac);
	/* If this is a new peer */
	if (position < 0) {
		/* Get free peers position */
		position = get_peer_index();
		if (position < 0)
			return position;

		/*Create Socket */
		err = hal_comm_socket(HAL_COMM_PF_NRF24, HAL_COMM_PROTO_RAW);
		if (err < 0)
			return err;

		peers[position].socket_fd = err;

		peers[position].knotd_fd = connect_unix();
		if (peers[position].knotd_fd < 0) {
			hal_comm_close(peers[position].socket_fd);
			peers[position].socket_fd = -1;
			return peers[position].knotd_fd;
		}

		/* Set mac value for this position */
		peers[position].mac =
				evt_pre->mac.address.uint64;

		/* Copy the slave name */
		strncpy(peers[position].name, (char *) evt_pre->name,
					MIN(sizeof(peers[position].name) - 1,
						strlen((char *)evt_pre->name)));

		/* Watch knotd socket */
		peers[position].knotd_io =
			g_io_channel_unix_new(peers[position].knotd_fd);
		g_io_channel_set_flags(peers[position].knotd_io,
			G_IO_FLAG_NONBLOCK, NULL);
		g_io_channel_set_close_on_unref(peers[position].knotd_io,
			FALSE);

		peers[position].knotd_id =
			g_io_add_watch_full(peers[position].knotd_io,
						G_PRIORITY_DEFAULT,
						cond,
						knotd_io_watch,
						&peers[position],
						knotd_io_destroy);
		g_io_channel_unref(peers[position].knotd_io);

		count_clients++;

		/* Remove device when the connection is established */
		g_hash_table_remove(peer_bcast_table, mac_str);
	}

	/*Send Connect */
	hal_comm_connect(peers[position].socket_fd,
			&evt_pre->mac.address.uint64);
	return 0;
}

static int8_t evt_disconnected(struct mgmt_nrf24_header *mhdr)
{

	int8_t position;

	struct mgmt_evt_nrf24_disconnected *evt_disc =
			(struct mgmt_evt_nrf24_disconnected *) mhdr->payload;

	if (count_clients == 0)
		return -EINVAL;

	position = get_peer(evt_disc->mac);
	if (position < 0)
		return position;

	g_source_remove(peers[position].knotd_id);
	return 0;
}

/* Read RAW from Clients */
static int8_t clients_read()
{
	int8_t i;
	uint8_t buffer[256];
	int ret;

	/*No client */
	if (count_clients == 0)
		return 0;

	for (i = 0; i < MAX_PEERS; i++) {
		if (peers[i].socket_fd == -1)
			continue;

		ret = hal_comm_read(peers[i].socket_fd, &buffer,
			sizeof(buffer));
		if (ret > 0) {
			if (write(peers[i].knotd_fd, buffer, ret) < 0)
				hal_log_error("write_knotd() error");
		}
	}
	return 0;
}

static int8_t mgmt_read(void)
{

	uint8_t buffer[256];
	struct mgmt_nrf24_header *mhdr = (struct mgmt_nrf24_header *) buffer;
	ssize_t rbytes;

	rbytes = hal_comm_read(mgmtfd, buffer, sizeof(buffer));

	/* mgmt on bad state? */
	if (rbytes < 0 && rbytes != -EAGAIN)
		return -1;

	/* Nothing to read? */
	if (rbytes == -EAGAIN)
		return -1;

	/* Return/ignore if it is not an event? */
	if (!(mhdr->opcode & 0x0200))
		return -1;

	switch (mhdr->opcode) {

	case MGMT_EVT_NRF24_BCAST_PRESENCE:
		evt_presence(mhdr);
		break;

	case MGMT_EVT_NRF24_BCAST_SETUP:
		break;

	case MGMT_EVT_NRF24_BCAST_BEACON:
		break;

	case MGMT_EVT_NRF24_DISCONNECTED:
		evt_disconnected(mhdr);
		break;
	}
	return 0;
}

static gboolean read_idle(gpointer user_data)
{
	mgmt_read();
	clients_read();
	return TRUE;
}

static int radio_init(const char *spi, uint8_t channel, uint8_t rfpwr,
						const struct nrf24_mac *mac)
{
	int err;

	err = hal_comm_init("NRF0", mac);
	if (err < 0) {
		hal_log_error("Cannot init NRF0 radio. (%d)", err);
		return err;
	}

	mgmtfd = hal_comm_socket(HAL_COMM_PF_NRF24, HAL_COMM_PROTO_MGMT);
	if (mgmtfd < 0) {
		hal_log_error("Cannot create socket for radio (%d)", mgmtfd);
		goto done;
	}

	mgmtwatch = g_idle_add(read_idle, NULL);
	hal_log_info("Radio initialized");

	return 0;
done:
	hal_comm_deinit();

	return mgmtfd;
}

static void close_clients(void)
{
	int i;

	for (i = 0; i < MAX_PEERS; i++) {
		if (peers[i].socket_fd != -1)
			g_source_remove(peers[i].knotd_id);
	}
}

static void radio_stop(void)
{
	close_clients();
	hal_comm_close(mgmtfd);
	if (mgmtwatch)
		g_source_remove(mgmtwatch);
	hal_comm_deinit();
}

static gboolean nrf_data_watch(GIOChannel *io, GIOCondition cond,
						gpointer user_data)
{
	char buffer[1024];
	GIOStatus status;
	GError *gerr = NULL;
	gsize rbytes;

	/*
	 * Manages TCP data from spiproxyd(nRF proxy). All traffic(raw
	 * data) should be transferred using unix socket to knotd.
	 */

	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	memset(buffer, 0, sizeof(buffer));

	/* Incoming data through TCP socket */
	status = g_io_channel_read_chars(io, buffer, sizeof(buffer),
						 &rbytes, &gerr);
	if (status == G_IO_STATUS_ERROR) {
		hal_log_error("read(): %s", gerr->message);
		g_error_free(gerr);
		return FALSE;
	}

	if (rbytes == 0)
		return FALSE;

	/*
	 * Decode based on nRF PIPE information and forward
	 * the data through a unix socket to knotd.
	 */
	hal_log_info("read(): %zu bytes", rbytes);

	return TRUE;
}

static int tcp_init(const char *host, int port)
{
	GIOChannel *io;
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP;
	struct hostent *hostent;		/* Host information */
	struct in_addr h_addr;			/* Internet address */
	struct sockaddr_in server;		/* nRF proxy: spiproxyd */
	int err, sock;

	hostent = gethostbyname(host);
	if (hostent == NULL) {
		err = errno;
		hal_log_error("gethostbyname(): %s(%d)", strerror(err), err);
		return -err;
	}

	h_addr.s_addr = *((unsigned long *) hostent-> h_addr_list[0]);

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = errno;
		hal_log_error("socket(): %s(%d)", strerror(err), err);
		return -err;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = h_addr.s_addr;
	server.sin_port = htons(port);

	err = connect(sock, (struct sockaddr *) &server, sizeof(server));
	if (err < 0) {
		err = errno;
		hal_log_error("connect(): %s(%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	hal_log_info("nRF Proxy address: %s", inet_ntoa(h_addr));

	io = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(io, TRUE);

	/* Ending 'NULL' for binary data */
	g_io_channel_set_encoding(io, NULL, NULL);
	g_io_channel_set_buffered(io, FALSE);

	/* TCP handler: incoming data from spiproxyd (nRF proxy) */
	g_io_add_watch(io, cond, nrf_data_watch, NULL);

	/* Keep only one reference: watch */
	g_io_channel_unref(io);

	return 0;
}

static char *load_config(const char *file)
{
	char *buffer = NULL;
	int length;
	FILE *fl = fopen(file, "r");

	if (fl == NULL) {
		hal_log_error("No such file available: %s", file);
		return NULL;
	}

	fseek(fl, 0, SEEK_END);
	length = ftell(fl);
	fseek(fl, 0, SEEK_SET);

	buffer = (char *) malloc((length+1)*sizeof(char));
	if (buffer) {
		fread(buffer, length, 1, fl);
		buffer[length] = '\0';
	}
	fclose(fl);

	return buffer;
}

/* Set TX Power from dBm to values defined at nRF24 datasheet */
static uint8_t dbm_int2rfpwr(int dbm)
{
	switch (dbm) {

	case 0:
		return NRF24_PWR_0DBM;

	case -6:
		return NRF24_PWR_6DBM;

	case -12:
		return NRF24_PWR_12DBM;

	case -18:
		return NRF24_PWR_18DBM;
	}

	/* Return default value when dBm value is invalid */
	return NRF24_PWR_0DBM;
}

static int gen_save_mac(const char *config, const char *file,
							struct nrf24_mac *mac)
{
	json_object *jobj, *obj_radio, *obj_tmp;

	int err = -EINVAL;

	jobj = json_tokener_parse(config);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "radio", &obj_radio))
		goto done;

	if (json_object_object_get_ex(obj_radio,  "mac", &obj_tmp)){

			char mac_string[24];
			uint8_t mac_mask = 4;
			mac->address.uint64 = 0;

			hal_getrandom(mac->address.b + mac_mask,
						sizeof(*mac) - mac_mask);

			err = nrf24_mac2str((const struct nrf24_mac *) mac,
								mac_string);
			if (err == -1)
				goto done;

			json_object_object_add(obj_radio, "mac",
					json_object_new_string(mac_string));

			json_object_to_file((char *) file, jobj);
	}

	/* Success */
	err = 0;

done:
	/* Free mem used in json parse: */
	json_object_put(jobj);
	return err;
}

/*
 * TODO: Get "host", "spi" and "port"
 * parameters when/if implemented
 * in the json configuration file
 */
static int parse_config(const char *config, int *channel, int *dbm,
							struct nrf24_mac *mac)
{
	json_object *jobj, *obj_radio, *obj_tmp;

	int err = -EINVAL;

	jobj = json_tokener_parse(config);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "radio", &obj_radio))
		goto done;

	if (json_object_object_get_ex(obj_radio, "channel", &obj_tmp))
		*channel = json_object_get_int(obj_tmp);

	if (json_object_object_get_ex(obj_radio,  "TxPower", &obj_tmp))
		*dbm = json_object_get_int(obj_tmp);

	if (json_object_object_get_ex(obj_radio,  "mac", &obj_tmp))
		if (json_object_get_string(obj_tmp) != NULL){
			err =
			nrf24_str2mac(json_object_get_string(obj_tmp), mac);
			if (err == -1)
				goto done;
		}

	/* Success */
	err = 0;

done:
	/* Free mem used in json parse: */
	json_object_put(jobj);
	return err;
}

static int parse_nodes(const char *nodes_file)
{
	int array_len;
	int i;
	int err = -EINVAL;
	json_object *jobj;
	json_object *obj_keys, *obj_nodes, *obj_tmp;

	/* Load nodes' info from json file */
	jobj = json_object_from_file(nodes_file);
	if (!jobj)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "keys", &obj_keys))
		goto failure;

	array_len = json_object_array_length(obj_keys);
	if (array_len > MAX_PEERS) {
		hal_log_error("Invalid numbers of nodes at %s", nodes_file);
		goto failure;
	}
	for (i = 0; i < array_len; i++) {
		obj_nodes = json_object_array_get_idx(obj_keys, i);
		if (!json_object_object_get_ex(obj_nodes, "mac", &obj_tmp))
			goto failure;

		/* Parse mac address string into struct nrf24_mac known_peers */
		if (nrf24_str2mac(json_object_get_string(obj_tmp),
					&adapter.known_peers[i].addr) < 0)
			goto failure;
		adapter.known_peers_size++;

		if (!json_object_object_get_ex(obj_nodes, "name", &obj_tmp))
			goto failure;

		/* Set the name of the peer registered */
		adapter.known_peers[i].alias =
				g_strdup(json_object_get_string(obj_tmp));
	}

	err = 0;
failure:
	/* Free mem used to parse json */
	json_object_put(jobj);
	return err;
}

static gboolean check_timeout(gpointer key, gpointer value, gpointer user_data)
{
	struct bcast_presence *peer = value;

	/* If it returns true the key/value is removed */
	if (hal_timeout(hal_time_ms(), peer->last_beacon,
							BCAST_TIMEOUT) > 0) {
		hal_log_info("Peer %s timedout.", (char *) key);
		return TRUE;
	}

	return FALSE;
}

static gboolean timeout_iterator(gpointer user_data)
{
	g_hash_table_foreach_remove(peer_bcast_table, check_timeout, NULL);

	return TRUE;
}

int manager_start(const char *file, const char *host, int port,
					const char *spi, int channel, int dbm,
					const char *nodes_file)
{
	int cfg_channel = NRF24_CH_MIN, cfg_dbm = 0;
	char *json_str;
	struct nrf24_mac mac = {.address.uint64 = 0};
	int err = -1;

	/* Command line arguments have higher priority */
	json_str = load_config(file);
	if (json_str == NULL) {
		hal_log_error("load_config()");
		return err;
	}
	err = parse_config(json_str, &cfg_channel, &cfg_dbm, &mac);
	if (err < 0) {
		hal_log_error("parse_config(): %d", err);
		return err;
	}

	memset(&adapter, 0, sizeof(struct adapter));
	/* Parse nodes info from nodes_file and writes it to known_peers */
	err = parse_nodes(nodes_file);
	if (err < 0) {
		hal_log_error("parse_nodes(): %d", err);
		return err;
	}

	if (mac.address.uint64 == 0)
		err = gen_save_mac(json_str, file, &mac);

	free(json_str);
	adapter.file_name = g_strdup(nodes_file);
	adapter.mac = mac;
	adapter.powered = TRUE;

	if (err < 0) {
		hal_log_error("Invalid configuration file(%d): %s", err, file);
		return err;
	}
	/* Start server dbus */
	dbus_id = dbus_init(mac);

	 /* Validate and set the channel */
	if (channel < 0 || channel > 125)
		channel = cfg_channel;

	/*
	 * Use TX Power from configuration file if it has not been passed
	 * through cmd line. -255 means invalid: not informed by user.
	 */
	if (dbm == -255)
		dbm = cfg_dbm;

	peer_bcast_table = g_hash_table_new_full(g_str_hash, g_str_equal,
								g_free, g_free);
	g_timeout_add_seconds(5, timeout_iterator, NULL);

	if (host == NULL) {
		hal_log_info("host is NULL");
		return radio_init(spi, channel, dbm_int2rfpwr(dbm),
						(const struct nrf24_mac*) &mac);
	}
	/*
	 * TCP development mode: Linux connected to RPi(phynrfd radio
	 * proxy). Connect to phynrfd routing all traffic over TCP.
	 */
	return tcp_init(host, port);
}

void manager_stop(void)
{
	dbus_on_close(dbus_id);
	radio_stop();
	g_hash_table_destroy(peer_bcast_table);
}
