#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>      /* open */
#include <unistd.h>     /* exit */
#include <sys/ioctl.h>      /* ioctl */
#include <string.h>
#include <unistd.h>

#if 1
#define DEBUG(x) printf x
#else
#define DEBUG(x)
#endif

#define VENDOR_REQ_TAG      0x56524551
#define VENDOR_READ_IO      _IOW('v', 0x01, unsigned int)
#define VENDOR_WRITE_IO     _IOW('v', 0x02, unsigned int)

#define VENDOR_SN_ID            1
#define VENDOR_WIFI_MAC_ID      2
#define VENDOR_LAN_MAC_ID       3
#define VENDOR_BLUETOOTH_ID     4

#define SUPPORT_DEBUG_LOG
#define MAX_LEN 256

struct rk_vendor_reg {
    uint32_t tag;
    uint16_t id;
    uint16_t len;
    uint8_t data[MAX_LEN];
};

/*
 * if success, return the actually read length
 */
int vendor_storage_write(char id, char *data, int len)
{
    int ret;
    int sys_fd = -1;
    struct rk_vendor_reg req;

    sys_fd = open("/dev/vendor_storage", O_RDWR, 0);
    if (sys_fd < 0) {
        DEBUG(("vendor storage open fail\n"));
        return -5;
    }
    if (len > MAX_LEN)
        len = MAX_LEN;
    req.tag = VENDOR_REQ_TAG;
    req.id = id;
    req.len = len;
    memcpy(req.data, data, len);
    ret = ioctl(sys_fd, VENDOR_WRITE_IO, &req);
    if (ret) {
        DEBUG(("vendor storage write(%d) fail\n", id));
        close(sys_fd);
        return ret;
    }
    close(sys_fd);
    return 0;
}

int vendor_storage_read(char id, char *data, int *len)
{
    int ret;
    int sys_fd = -1;
    struct rk_vendor_reg req;

    sys_fd = open("/dev/vendor_storage", O_RDWR, 0);
    if (sys_fd < 0) {
        DEBUG(("vendor storage open fail\n"));
        return -5;
    }
    req.tag = VENDOR_REQ_TAG;
    req.id = id;
    req.len = MAX_LEN;
    ret = ioctl(sys_fd, VENDOR_READ_IO, &req);
    if (ret) {
        DEBUG(("vendor storage read(%d) fail\n", id));
        close(sys_fd);
        return ret;
    }
    if (*len > req.len )
        *len = req.len;
    memcpy(data, req.data, *len);
    close(sys_fd);
    return 0;
}

/* Bit formats */
enum CMD_OP {
    CMD_NULL = 0,
    CMD_TEST,
    CMD_READ,
    CMD_WRITE
};

enum ITEM_TYPES {
    CMD_NONE = 0,
    CMD_BIN,
    CMD_STR,
    CMD_MAC,
};

void print_usage(char *exe_nane)
{
    fprintf(stderr, "Usage: %s command(v1.0) -i id -t types -v value\n", exe_nane);
}

enum ITEM_TYPES parse_types(char *str)
{
    if (strcmp(str, "string") == 0)
        return CMD_STR;
    else if (strcmp(str, "binary") == 0)
        return CMD_BIN;
    else if (strcmp(str, "mac") == 0)
        return CMD_MAC;
    return CMD_NONE;
}

int tchar_to_byte(const char ch)
{
    int result = 0;

    if(ch >= '0' && ch <= '9') {
        result = (int)(ch - '0');
    } else if(ch >= 'a' && ch <= 'z' ){
        result = (int)(ch - 'a') + 10;
    } else if(ch >= 'A' && ch <= 'Z') {
        result = (int)(ch - 'A') + 10;
    } else{
        result = -1;
    }
    return result;
}

int hex_string_convert(const char *str, char *data, unsigned int len)
{
    int i, strsize, outsize, datasize;

    datasize = len;
    strsize = strlen(str);
    outsize = strsize/2;
    if (outsize >= datasize)
        outsize = datasize;

    for(i = 0; i < outsize; i ++) {
        data[i] = (tchar_to_byte(str[2*i]) << 4) | (tchar_to_byte(str[2*i + 1]));
    }
    return outsize;
}

#define LINE_LENGTH 3
void printhex(const char *data, int len, char *sep)
{
    int i = 0;

    if(!sep)
        sep = " ";
    printf("hex result:\n");
    for (i = 0; i < len; i++) {
        printf("%02x%s", data[i], sep);
    }
    printf("\n");
}

int parse_data(enum ITEM_TYPES item_type, const char *data, int len, const char **str)
{
    int i;
    char *out = 0;
    unsigned int olen;

    if(CMD_MAC == item_type) {
        if (len != 6) {
            DEBUG(("error mac format\n"));
            return -22;
        }
        olen = 18; /* strlen("0A:0B:11:22:33:44") + 1*/
        out = (char *)malloc(olen);
        if (!out){
            DEBUG(("%s:malloc fail\n", __func__));
            return -12;
        }
        sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", data[0], data[1], data[2], data[3], data[4], data[5]);
    } else if (CMD_BIN == item_type) {
        olen = len*2 + 1;
        out = (char *)malloc(olen);
        if (!out) {
            DEBUG(("%s:malloc fail\n", __func__));
            return -12;
        }
    } else if (CMD_STR == item_type) {
        olen = len + 1;
        out = (char *)malloc(olen);
        if (!out){
            DEBUG(("%s:malloc fail\n", __func__));
            return -12;
        }
        memcpy(out, data, len);
        out[len] = '\0';
    }
    *str = out;
    return olen;
parse_exit:
    if (out) {
        free(out);
    }
    return -1;
}

int parse_string(enum ITEM_TYPES item_type, const char *argv_str, char **data)
{
    char *out = 0;
    unsigned int olen;

    /* input string NULL, or length is zero */
    if (!argv_str || argv_str[0] == '\0')
        return -1;
    if(CMD_MAC == item_type) {
        olen = 6;
        out = (char *)malloc(olen);
        if (!out) {
            DEBUG(("%s:malloc fail\n", __func__));
            return -12;
        }
        if(olen != hex_string_convert(argv_str, out, olen)) {
            DEBUG(("convert MAC fail\n"));
            goto parse_exit;
        } else {
            DEBUG(("MAC is %02x:%02x:%02x:%02x:%02x:%02x\n",
                out[0],out[1],out[2],out[3],out[4],out[5]));
            printhex(out, 6, ":");
        }
    } else if (CMD_BIN == item_type) {
        olen = strlen(argv_str)/2;
        out = (char *)malloc(olen);
        if (!out) {
            DEBUG(("%s:malloc fail\n", __func__));
            return -12;
        }
        if(olen != hex_string_convert(argv_str, out, olen)) {
            DEBUG(("convert binary fail\n"));
            goto parse_exit;
        } else {
            printhex(out, 6, " ");
        }
    } else if (CMD_STR == item_type) {
        olen = strlen(argv_str);
        out = (char *)malloc(olen);
        if (!out) {
            DEBUG(("%s:malloc fail\n", __func__));
            return -12;
        }
        memcpy(out, argv_str, olen);
        printhex(out, olen, " ");
    }
    *data = out;
    return olen;
parse_exit:
    if (out) {
        free(out);
    }
    return -1;
}

/*result
 * 0  : OK
 * -22: Invalid argument
 * -5 : I/O erro
 * -12: Out of memory
 */
int main(int argc, char *argv[])
{
    int ret = -1;
    int len, rlen;
    int id = -1; /* vendor id */
    const char *data = 0; /* vendor data */
    const char *rstr = 0, *wstr = 0;
    const char **parsing_argv;
    enum CMD_OP op = CMD_READ;
    enum ITEM_TYPES item_type = CMD_STR;

    if (argc < 2) {
        print_usage(argv[0]);
        return -22;
    }
    if (argv[1][0] == 'w' || argv[1][0] == 'W' ) {
        op = CMD_WRITE;
    } else if (argv[1][0] == 'r' || argv[1][0] == 'R' ){
        op = CMD_READ;
    } else if (argv[1][0] == 't' || argv[1][0] == 'T' ){
        op = CMD_TEST;
    } else if(argv[1][0] == 'h' || argv[1][0] == 'H') {
        print_usage(argv[0]);
        return 0;
    } else {
        print_usage(argv[0]);
        return -22;
    }

    /* parse command line arguments */
    parsing_argv = argv + 2;
    while (*parsing_argv) {
        if (strcmp(*parsing_argv, "-t") == 0) {
            parsing_argv++;
            if (*parsing_argv)
                item_type = parse_types(*parsing_argv);
            continue;
        } else if (strcmp(*parsing_argv, "-T") == 0) {
            parsing_argv++;
            if (*parsing_argv)
                item_type = parse_types(*parsing_argv);
            continue;
        } else if(strcmp(*parsing_argv, "-i") == 0 ) {
            parsing_argv++;
            if (*parsing_argv)
                id = atoi(*parsing_argv);
            continue;
        }
        parsing_argv++;
    };
    if (id == -1) {
        DEBUG(("must specify  id, eg. %s w -i 8\n", __func__));
        return -22;
    }
    parsing_argv = argv + 2;
    /* write id */
    if (op == CMD_WRITE || op == CMD_TEST) {
        while (*parsing_argv) {
            if (strcmp(*parsing_argv, "-v") == 0) {
                parsing_argv++;
                if (*parsing_argv) {
                    wstr = *parsing_argv;
                    len = parse_string(item_type, wstr, &data);
                    if (len < 0) {
                        DEBUG(("parsing input data fail\n"));
                        return -22;
                    }
                }
                break;
            }
            parsing_argv++;
        }
        if (!data) {
            DEBUG(("no set value to write, eg. %s w -i 8 -v rockchip20190327\n"));
            return -22;
        }
        if (vendor_storage_write(id, data, len)) {
            DEBUG(("vendor storage write fail\n"));
            ret = -5; /* io error */
            goto err_exit;
        }
    }
    /* read id */
    if (op == CMD_READ || op == CMD_TEST) {
        if (!data) {
            len = MAX_LEN;
            data = malloc(len);
        }
        if (!data) {
            DEBUG(("malloc buffer fail, exit\n"));
            return -12;
        }
        rlen = len;
        if (vendor_storage_read(id, data, &rlen)) {
            ret = -5; /* io error */
            goto err_exit;
        } else {
            if (parse_data(item_type, data, rlen, &rstr) > 0) {
                printf("%s\n", rstr);
            } else {
                DEBUG(("parse read data fail\n"));
                printhex(data, rlen, " ");
                ret = -5; /* io error */
                goto err_exit;
            }
        }
    }
    ret = 0;
err_exit:
    if (data)
        free (data);
    if (rstr)
        free (rstr);
    return ret;
}

