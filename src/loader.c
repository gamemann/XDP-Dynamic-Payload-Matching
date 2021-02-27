#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include <net/if.h>
#include <linux/if_link.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"
#include "common.h"

#define PAYLOAD "FF FF 50 60 AE"
#define SECTION "xdp_methodfour"
#define PROGRAM "src/xdp_methodfour.o"

static int cont = 1;
const char *dev = "ens18";
static int progfd;
uint32_t xdp_flags = XDP_FLAGS_SKB_MODE;    // Load with SKB/Generic mode just so we know it'll work (e.g. if we don't support XDP-native). This is all for testing afterall and everything within the XDP program should work with XDP-native as well.

void ShutDown(int tmp)
{
    cont = 0;
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

struct bpf_object *load_bpf_object_file__simple(const char *filename)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    struct bpf_program *bpf_prog;
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);

    if (err)
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Num => %d\n", filename, strerror(-err), err);

        return obj;
    }

    bpf_prog = bpf_object__find_program_by_title(obj, SECTION);

    if (!bpf_prog)
    {
        fprintf(stderr, "Error loading XDP section. File => %s. Error => %s. Error Num => %d. Section => %s.\n", filename, strerror(-err), err, SECTION);

        return obj;
    }

    progfd = bpf_program__fd(bpf_prog);

    return obj;
}

static int xdp_detach(int ifindex, uint32_t xdp_flags)
{
    int err;

    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    if (err < 0)
    {
        fprintf(stderr, "Error detaching XDP program. Error => %s. Error Num => %.d\n", strerror(-err), err);

        return -1;
    }

    return EXIT_SUCCESS;
}

static int xdp_attach(int ifindex, uint32_t xdp_flags, int prog_fd)
{
    int err;
    
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        
        uint32_t oldflags = xdp_flags;

        xdp_flags &= ~XDP_FLAGS_MODES;
        xdp_flags |= (oldflags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

        err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

        if (!err)
        {
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, oldflags);
        }
    }

    if (err < 0)
    {
        fprintf(stderr, "Error attaching XDP program. Error => %s. Error Num => %d. IfIndex => %d.\n", strerror(-err), -err, ifindex);

        switch(-err)
        {
            case EBUSY:

            case EEXIST:
            {
                xdp_detach(ifindex, xdp_flags);
                fprintf(stderr, "Additional: XDP already loaded on device.\n");
                break;
            }

            case EOPNOTSUPP:
                fprintf(stderr, "Additional: XDP-native nor SKB not supported? Not sure how that's possible.\n");

                break;

            default:
                break;
        }

        return -1;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    int ifidx;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *bpf_obj = NULL;
    int payload_map_fd;

    ifidx = if_nametoindex(dev);

    if (ifidx < 1)
    {
        fprintf(stderr, "Error finding device: %s\n", dev);

        exit(EXIT_FAILURE);
    }

    signal(SIGINT, ShutDown);

    xdp_detach(ifidx, xdp_flags);

    struct bpf_map *map;
    struct bpf_map *length_map;

    bpf_obj = load_bpf_object_file__simple(PROGRAM);

    if (!bpf_obj) 
    {
        fprintf(stderr, "Error opening BPF object file.");

        exit(EXIT_FAILURE);
    }

    if (xdp_attach(ifidx, xdp_flags, progfd) != 0)
    {
        fprintf(stderr, "Error attaching XDP program: %s\n", strerror(errno));

        exit(EXIT_FAILURE);
    }

    map = bpf_object__find_map_by_name(bpf_obj, "payload_map");

    payload_map_fd = bpf_map__fd(map);

    if (payload_map_fd < 0) 
    {
        fprintf(stderr, "ERROR: payload map not found: %s\n", strerror(payload_map_fd));

        exit(EXIT_FAILURE);
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) 
    {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));

        exit(EXIT_FAILURE);
    }

    if (strcmp(SECTION, "xdp_methodthree") == 0)
    {
        char str[MAX_PAYLOAD_LENGTH];

        strcpy(str, PAYLOAD);

        char *ptr = strtok(str, " ");

        int i = 0;

        while (ptr != NULL)
        {
            uint8_t key;
            sscanf(ptr, "%2hhx", &key);

            uint8_t val = 1;
            ptr = strtok(NULL, " ");

            i++;
            
            bpf_map_update_elem(payload_map_fd, &key, &val, BPF_ANY);
        }
    }
    else if (strcmp(SECTION, "xdp_methodfour") == 0)
    {
        char str[256];

        strcpy(str, PAYLOAD);

        char *ptr = strtok(str, " ");

        int i = 0;

        uint8_t key[MAX_PAYLOAD_LENGTH] = {0};
        uint8_t val = 1;

        while (ptr != NULL)
        {
            sscanf(ptr, "%2hhx", &key[i]);
            ptr = strtok(NULL, " ");
            i++;
        }

        if (bpf_map_update_elem(payload_map_fd, &key, &val, BPF_ANY) != 0)
        {
            printf("Error updating BPF map.");
        }
        else
        {
            printf("Updated BPF map and set %d %d %d %d %d\n", key[0], key[1], key[2], key[3], key[4]);
        }
    }
    else
    {
        uint32_t key = 0;
        struct payload entry;
        char str[MAX_PAYLOAD_LENGTH];

        strcpy(str, PAYLOAD);

        char *ptr = strtok(str, " ");

        int i = 0;

        while (ptr != NULL)
        {
            sscanf(ptr, "%2hhx", &entry.payload[i]);
            ptr = strtok(NULL, " ");

            entry.length++;
            i++;
        }

        bpf_map_update_elem(payload_map_fd, &key, &entry, BPF_ANY);
    }

    fprintf(stdout, "Starting XDP program and updated maps...\n");

    while (cont)
    {
        sleep(1);
    }

    xdp_detach(ifidx, xdp_flags);

    return EXIT_SUCCESS;
}