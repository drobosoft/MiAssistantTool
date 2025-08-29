#define VERSION "1.2"
#define REPOSITORY "https://github.com/drobosoft/MiAssistantTool"

#ifdef _WIN32
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif

#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <curl/curl.h>

#include "tiny-json/tiny-json.h"

#define ADB_CLASS 0xff
#define ADB_SUB_CLASS 0x42
#define ADB_PROTOCOL_CODE 1
#define ADB_CONNECT 0x4E584E43
#define ADB_VERSION 0x01000001
#define ADB_OPEN 0x4E45504F
#define ADB_OKAY 0x59414B4F
#define ADB_WRTE 0x45545257
#define ADB_CLSE 0x45534C43
#define ADB_TRANSFER_DONE 0x00000000
#define ADB_MAX_DATA 1024 * 1024
#define ADB_SIDELOAD_CHUNK_SIZE 1024 * 64

char device[80];
char version[80];
char sn[80];
char codebase[80];
char branch[80];
char language[80];
char region[80];
char romzone[80];

// override values (can be set via command-line args)
char override_device[80] = "";
char override_version[80] = "";
char override_sn[80] = "";
char override_codebase[80] = "";
char override_branch[80] = "";
char override_romzone[80] = "";

int bulk_in;
int bulk_out;
int interface_num;

libusb_context *ctx;
libusb_device_handle *dev_handle;

char response[4096]; 

typedef struct {
    uint32_t cmd;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t len;
    uint32_t checksum;
    uint32_t magic;
} adb_usb_packet;

int usb_read(void *data, int datalen) {
    int read_len;
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_bulk_transfer(dev_handle, bulk_in, data, datalen, &read_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        return -1;
    }
    return read_len;
}

int usb_write(void *data, int datalen) {
    int write_len;
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_bulk_transfer(dev_handle, bulk_out, data, datalen, &write_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        return -1;
    }
    return write_len;
}

int send_command(uint32_t cmd, uint32_t arg0, uint32_t arg1, void *data, int datalen) {
    adb_usb_packet pkt;
    pkt.cmd = cmd;
    pkt.arg0 = arg0;
    pkt.arg1 = arg1;
    pkt.len = datalen;
    pkt.checksum = 0;
    pkt.magic = cmd ^ 0xffffffff;

    if(usb_write(&pkt, sizeof(pkt)) == -1) {
        return 1;
    } 

    if(datalen > 0) {
        if(usb_write(data, datalen) == -1) {
            return 1;
        }
    }
    return 0;
}

int recv_packet(adb_usb_packet *pkt, void* data, int *data_len) {
    if(!usb_read(pkt, sizeof(adb_usb_packet))) {
        return 1;
    }

    if(pkt->len > 0) {
        if(!usb_read(data, pkt->len)) {
            return 1;
        }
    }

    *data_len = pkt->len;
    return 0;
}



char* adb_cmd(char* command) {
    int cmd_len = strlen(command);
    char cmd[cmd_len + 1];
    memcpy(cmd, command, cmd_len);
    cmd[cmd_len] = 0;

    if (send_command(ADB_OPEN, 1, 0, cmd, cmd_len)) {
        printf("device not accept connect request\n");
        return NULL;
    }

    adb_usb_packet pkt;
    char data[512];
    int data_len;
    recv_packet(&pkt, data, &data_len);

    if (recv_packet(&pkt, response, &data_len)) {
        printf("Failed to get info from device\n");
        return NULL;
    }

    response[data_len] = 0;

    if (response[data_len - 1] == '\n')
        response[data_len - 1] = 0;

    recv_packet(&pkt, data, &data_len);

    return response;
}

void calculate_md5(char *filePath, char *md5) {
    FILE *file;

    while (1) {
        printf("Enter .zip file path: ");
        if (fgets(filePath, 256, stdin)) {
            filePath[strcspn(filePath, "\n")] = '\0';
            if (strstr(filePath, ".zip") && (file = fopen(filePath, "rb"))) {
                fclose(file);
                break;
            }
        }
        printf("Invalid file, try again.\n");
    }

    file = fopen(filePath, "rb");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    unsigned char data[1024], md5hash[EVP_MAX_MD_SIZE];
    size_t bytesRead;
    unsigned int md5len;

    while ((bytesRead = fread(data, 1, sizeof(data), file)) > 0)
        EVP_DigestUpdate(mdctx, data, bytesRead);

    EVP_DigestFinal_ex(mdctx, md5hash, &md5len);
    fclose(file);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < md5len; i++)
        sprintf(&md5[i * 2], "%02x", md5hash[i]);

    md5[md5len * 2] = '\0';
}

const char *validate_check(const char *md5, int flash) {
    const unsigned char key[16] = { 0x6D, 0x69, 0x75, 0x69, 0x6F, 0x74, 0x61, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x65, 0x64, 0x31, 0x31 };
    const unsigned char iv[16] = { 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38 };

    char json_request[1024];
    sprintf(json_request, "{\"d\":\"%s\",\"v\":\"%s\",\"c\":\"%s\",\"b\":\"%s\",\"sn\":\"%s\",\"l\":\"en-US\",\"f\":\"1\",\"options\":{\"zone\":%s},\"pkg\":\"%s\"}", device, version, codebase, branch, sn, romzone, md5);

    // Print original JSON to be sent (before padding)
    printf("[DEBUG] JSON request (original): %s\n", json_request);

    int len = strlen(json_request);
    int mod_len = 16 - (len % 16);
    if (mod_len > 0) memset(json_request + len, mod_len, mod_len), len += mod_len;

    unsigned char enc_out[1024]; 
    int enc_out_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int update_len = 0;
    if (EVP_EncryptUpdate(ctx, enc_out, &update_len, (unsigned char*)json_request, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    enc_out_len += update_len;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, enc_out + enc_out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    enc_out_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    char encoded_buf[EVP_ENCODE_LENGTH(enc_out_len)];
    EVP_EncodeBlock((unsigned char*)encoded_buf, enc_out, enc_out_len);

    // Print base64 encoded payload
    printf("[DEBUG] Encoded (base64) payload: %s\n", encoded_buf);

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    char *json_post_data = curl_easy_escape(curl, encoded_buf, strlen(encoded_buf));
    if (!json_post_data) { 
        curl_easy_cleanup(curl); 
        return NULL; 
    }

    size_t post_buf_len = strlen(json_post_data) + strlen("q=&t=&s=1") + 1;
    unsigned char *post_buf_send = (unsigned char *)malloc(post_buf_len);
    if (!post_buf_send) {
        curl_free(json_post_data);
        curl_easy_cleanup(curl);
        return NULL;
    }

    snprintf((char*)post_buf_send, post_buf_len, "q=%s&t=&s=1", json_post_data);
    // Print POST body (URL-escaped)
    printf("[DEBUG] POST body: %s\n", post_buf_send);
    curl_free(json_post_data);

    FILE *response_file = fopen("response.tmp", "wb");
    if (!response_file) {
        perror("Error opening file for writing");
        free(post_buf_send);
        curl_easy_cleanup(curl);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://update.miui.com/updates/miotaV3.php");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "MiTunes_UserAgent_v3.0");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf_send);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_file);

    if (curl_easy_perform(curl) != CURLE_OK) {
        perror("Error during curl_easy_perform");
        fclose(response_file);
        free(post_buf_send);
        curl_easy_cleanup(curl);
        return NULL;
    }
    fclose(response_file);
    curl_easy_cleanup(curl);

    // Read server response
    FILE *response_file_read = fopen("response.tmp", "rb");
    if (!response_file_read) {
        perror("Failed to open file for reading");
        free(post_buf_send);
        return NULL;
    }

    fseek(response_file_read, 0, SEEK_END);
    long response_size = ftell(response_file_read);
    fseek(response_file_read, 0, SEEK_SET);

    char *response_buffer = malloc(response_size + 1);
    if (!response_buffer) {
        perror("Memory allocation failed");
        fclose(response_file_read);
        free(post_buf_send);
        return NULL;
    }

    fread(response_buffer, 1, response_size, response_file_read);
    response_buffer[response_size] = '\0';
    fclose(response_file_read);

    // Print raw server response
    printf("[DEBUG] Raw server response (base64 or raw): %s\n", response_buffer);

    // Decode base64 response into a separate buffer
    unsigned char *decoded_buf = malloc(response_size + 4); // ensure some extra space
    if (!decoded_buf) {
        perror("Memory allocation failed");
        free(response_buffer);
        free(post_buf_send);
        return NULL;
    }
    int decoded_len = EVP_DecodeBlock(decoded_buf, (unsigned char*)response_buffer, response_size);
    if (decoded_len < 0) decoded_len = 0;
    // Ensure null-termination for printing
    if (decoded_len >= 0) {
        if ((size_t)decoded_len >= (response_size + 4)) decoded_buf[response_size + 3] = '\0';
        else decoded_buf[decoded_len] = '\0';
    }

    printf("[DEBUG] Base64-decoded server response (len=%d): %s\n", decoded_len, decoded_len > 0 ? (char*)decoded_buf : "(empty)");

    // Decrypt decoded response
    unsigned char *decrypted_buf = malloc(decoded_len + 32);
    if (!decrypted_buf) {
        perror("Memory allocation failed");
        free(decoded_buf);
        free(response_buffer);
        free(post_buf_send);
        return NULL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(decrypted_buf);
        free(decoded_buf);
        free(response_buffer);
        free(post_buf_send);
        return NULL;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int plain_len = 0, temp_len = 0;
    if (decoded_len > 0) EVP_DecryptUpdate(ctx, decrypted_buf, &plain_len, decoded_buf, decoded_len);
    EVP_DecryptFinal_ex(ctx, decrypted_buf + plain_len, &temp_len);
    plain_len += temp_len;
    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate decrypted data for printing
    if (plain_len >= 0) decrypted_buf[plain_len] = '\0';
    printf("[DEBUG] Decrypted response (len=%d): %s\n", plain_len, plain_len > 0 ? (char*)decrypted_buf : "(empty)");

    // Prepare JSON substring from decrypted data
    char *start = strchr((char*)decrypted_buf, '{');
    char *end = strrchr((char*)decrypted_buf, '}');
    if (!start || !end) {
        // cleanup
        free(decrypted_buf);
        free(decoded_buf);
        free(response_buffer);
        free(post_buf_send);
        return NULL;
    }

    size_t json_len = end - start + 1;
    char *json_buf = malloc(json_len + 1);
    if (!json_buf) {
        free(decrypted_buf);
        free(decoded_buf);
        free(response_buffer);
        free(post_buf_send);
        return NULL;
    }
    memcpy(json_buf, start, json_len);
    json_buf[json_len] = '\0';

    // printf("Response after decryption: %s\n", json_buf);
    json_t pool[10000];
    json_t const *parsed_json = json_create((char *)json_buf, pool, 10000);
    if (!parsed_json) {
        free(json_buf);
        free(decrypted_buf);
        free(decoded_buf);
        free(response_buffer);
        free(post_buf_send);
        return NULL;
    }

    // free temporary buffers we no longer need
    free(json_buf);
    free(decrypted_buf);
    free(decoded_buf);
    free(response_buffer);
    free(post_buf_send);
    remove("response.tmp");

    if (flash == 1) {
        json_t const *pkg_rom = json_getProperty(parsed_json, "PkgRom");
        if (pkg_rom) {
            int Erase = atoi(json_getValue(json_getProperty(pkg_rom, "Erase")));
            if (Erase == 1) {
                printf("NOTICE: Data will be erased during flashing.\nPress Enter to continue...");
                getchar(); 
           }
            json_t const *validate = json_getProperty(pkg_rom, "Validate");
            return json_getValue(validate);
        } else {
            json_t const *code = json_getProperty(parsed_json, "Code");
            json_t const *message = json_getProperty(code, "message");
            printf("\n%s\n", json_getValue(message));
            return NULL;
        }
    } else {
        if (json_getType(parsed_json) == JSON_OBJ) {
            json_t const *child = json_getChild(parsed_json);
            if (strcmp(json_getName(json_getSibling(child)), "Signup") == 0 || strcmp(json_getName(json_getSibling(child)), "VersionBoot") == 0) {
                fprintf(stderr, "Error: Invalid data\n");
                return NULL;
            }
            while (child) {
                child = json_getSibling(child); 
                if (strcmp(json_getName(child), "Icon") == 0) {
                    break;
                }
                json_t const *cA = json_getProperty(parsed_json, json_getName(child));
                if (cA) {
                    json_t const *md5p = json_getProperty(cA, "md5");
                    if (md5p) {
                        printf("\n%s: %s\nmd5: %s\n", json_getName(child), json_getValue(json_getProperty(cA, "name")), json_getValue(md5p));
                    } 
                }     
            }
        }
        return NULL;
    }
}

int start_sideload(const char *sideload_file, const char *validate) {

    printf("[DEBUG] start_sideload: file='%s' validate='%s'\n", sideload_file ? sideload_file : "(null)", validate ? validate : "(null)");
    printf("\n\n");
    FILE *fp = fopen(sideload_file, "r");
    if (!fp) {
        perror("Failed to open file");
        printf("[DEBUG] fopen failed for '%s'\n", sideload_file);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);  
    printf("[DEBUG] file_size=%ld\n", file_size);
    char sideload_host_command[128 + (validate ? strlen(validate) : 0)];
    memset(sideload_host_command, 0, sizeof(sideload_host_command));
    sprintf(sideload_host_command, "sideload-host:%ld:%d:%s:0", file_size, ADB_SIDELOAD_CHUNK_SIZE, validate ? validate : "");
    printf("[DEBUG] sideload_host_command='%s'\n", sideload_host_command);

    if (send_command(ADB_OPEN, 1, 0, sideload_host_command, strlen(sideload_host_command) + 1)) {
        printf("[DEBUG] send_command ADB_OPEN failed\n");
    } else {
        printf("[DEBUG] send_command ADB_OPEN sent\n");
    }

    uint8_t *work_buffer = malloc(ADB_SIDELOAD_CHUNK_SIZE);
    if (!work_buffer) {
        perror("Failed to allocate memory");
        printf("[DEBUG] malloc work_buffer failed\n");
        fclose(fp);
        return 1;
    } else {
        printf("[DEBUG] allocated work_buffer %d bytes\n", ADB_SIDELOAD_CHUNK_SIZE);
    }

    char dummy_data[64];
    int dummy_data_size;
    adb_usb_packet pkt;
    long total_sent = 0;

    while (1) {
        pkt.cmd = 0;
        int recv_res = recv_packet(&pkt, dummy_data, &dummy_data_size);
        printf("[DEBUG] recv_packet returned %d, pkt.cmd=0x%08x arg0=%u arg1=%u len=%u dummy_data_size=%d\n", recv_res, (unsigned int)pkt.cmd, (unsigned int)pkt.arg0, (unsigned int)pkt.arg1, (unsigned int)pkt.len, dummy_data_size);

        if (recv_res) {
            printf("[DEBUG] recv_packet error, breaking loop\n");
            break;
        }

        if (dummy_data_size >= (int)sizeof(dummy_data)) {
            printf("[DEBUG] dummy_data_size too large: %d, truncating\n", dummy_data_size);
            dummy_data[sizeof(dummy_data)-1]=0;
        } else {
            dummy_data[dummy_data_size] = 0;
        }

        if(dummy_data_size > 8) {
            printf("\n\n[DEBUG] Long message from device: %s\n\n", dummy_data);
            break;
        }

        if (pkt.cmd == ADB_OKAY) {
            printf("[DEBUG] Received ADB_OKAY, replying with ADB_OKAY\n");
            send_command(ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0);
        }

        if (pkt.cmd == ADB_TRANSFER_DONE && total_sent > 0) {
            printf("[DEBUG] Received ADB_TRANSFER_DONE, total_sent=%ld\n", total_sent);
        }

        if (pkt.cmd != ADB_WRTE) {
            printf("[DEBUG] Packet cmd 0x%08x is not ADB_WRTE, continue\n", (unsigned int)pkt.cmd);
            continue;
        }

        long block = strtol(dummy_data, NULL, 10);
        printf("[DEBUG] block parsed=%ld\n", block);
        long offset = block * ADB_SIDELOAD_CHUNK_SIZE;
        printf("[DEBUG] calculated offset=%ld\n", offset);
        if (offset > file_size) {
            printf("[DEBUG] offset (%ld) > file_size (%ld), breaking\n", offset, file_size);
            break;
        }
        int to_write = ADB_SIDELOAD_CHUNK_SIZE;
        if(offset + ADB_SIDELOAD_CHUNK_SIZE > file_size)
            to_write = file_size - offset;
        printf("[DEBUG] to_write=%d\n", to_write);
        fseek(fp, offset, SEEK_SET);
        size_t read_bytes = fread(work_buffer, 1, to_write, fp);
        printf("[DEBUG] fread read %zu bytes\n", read_bytes);
        if (read_bytes == 0 && to_write > 0) {
            printf("[DEBUG] fread returned 0, possible read error or EOF\n");
            break;
        }
        int sc = send_command(ADB_WRTE, pkt.arg1, pkt.arg0, work_buffer, read_bytes);
        printf("[DEBUG] send_command ADB_WRTE returned %d\n", sc);
        int sc2 = send_command(ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0);
        printf("[DEBUG] send_command ADB_OKAY returned %d\n", sc2);
        total_sent += read_bytes;
        int percent = file_size > 0 ? (int)((total_sent * 100) / file_size) : 100;
        if (percent > 100) percent = 100;
        printf("\rFlashing in progress ... %d/100%% (total_sent=%ld/%ld)", percent, total_sent, file_size);
        fflush(stdout);

    }

    printf("\n[DEBUG] Exiting sideload loop, total_sent=%ld\n", total_sent);
    free(work_buffer);
    fclose(fp);
    return 0;
}


int check_device(libusb_device *dev) {

    struct libusb_device_descriptor desc;
    int r = libusb_get_device_descriptor(dev, &desc);
    struct libusb_config_descriptor *configs;
    r = libusb_get_active_config_descriptor(dev, &configs);

    bulk_in = -1;
    bulk_out = -1;
    interface_num = -1;
    for (int i = 0; i < configs->bNumInterfaces; i++) {
        struct libusb_interface intf = configs->interface[i];
        if (intf.num_altsetting == 0) {
            continue;
        }
        interface_num = i;
        struct libusb_interface_descriptor intf_desc = intf.altsetting[0];

        if (!(intf_desc.bInterfaceClass == ADB_CLASS && intf_desc.bInterfaceSubClass == ADB_SUB_CLASS && intf_desc.bInterfaceProtocol == ADB_PROTOCOL_CODE)) {
            continue;
        }
        if (intf.num_altsetting != 1) {
            continue;
        }

        for(int endpoint_num = 0; endpoint_num < intf_desc.bNumEndpoints; endpoint_num++) {
            struct libusb_endpoint_descriptor ep = intf_desc.endpoint[endpoint_num];
            const uint8_t endpoint_addr = ep.bEndpointAddress;
            const uint8_t endpoint_attr = ep.bmAttributes;
            const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;
            if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
                continue;
            }
            if ((endpoint_addr & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT && bulk_out == -1) {
                bulk_out = endpoint_addr;
            } else if ((endpoint_addr & LIBUSB_ENDPOINT_DIR_MASK) != LIBUSB_ENDPOINT_OUT && bulk_in == -1) {
                bulk_in = endpoint_addr;
            }

            if(bulk_out != -1 && bulk_in != -1) {
                return 0;
            }
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {

    if (argc == 1) {
        printf("\nVERSION: %s\n", VERSION);
        printf("Repository: %s\n\n", REPOSITORY);
        const char *choices[] = {"Read Info", "ROMs that can be flashed", "Flash Official Recovery ROM", "Format Data", "Reboot"};
        printf("\nUsage: %s \033[0;32m<choice>\033[0m\n\n  \033[0;32mchoice\033[0m > description\n\n", argv[0]);
        for (int i = 0; i < 5; i++)
            printf("  \033[0;32m%d\033[0m > %s\n\n", i + 1, choices[i]);
        return 0;
    }

    int choice = atoi(argv[1]);
    if (choice < 1 || choice > 5) {
        printf("Invalid choice\n");
        return 1;
    }

    // Parse optional overrides from remaining argv entries
    for (int ai = 2; ai < argc; ai++) {
        if (strncmp(argv[ai], "--device=", 9) == 0) strncpy(override_device, argv[ai] + 9, sizeof(override_device) - 1);
        else if (strncmp(argv[ai], "--version=", 10) == 0) strncpy(override_version, argv[ai] + 10, sizeof(override_version) - 1);
        else if (strncmp(argv[ai], "--sn=", 5) == 0) strncpy(override_sn, argv[ai] + 5, sizeof(override_sn) - 1);
        else if (strncmp(argv[ai], "--codebase=", 11) == 0) strncpy(override_codebase, argv[ai] + 11, sizeof(override_codebase) - 1);
        else if (strncmp(argv[ai], "--branch=", 9) == 0) strncpy(override_branch, argv[ai] + 9, sizeof(override_branch) - 1);
        else if (strncmp(argv[ai], "--romzone=", 10) == 0) strncpy(override_romzone, argv[ai] + 10, sizeof(override_romzone) - 1);
    }

    #ifdef _WIN32
        int method = 2;
    #else
        int method = (getenv("PREFIX") && access("/data/data/com.termux", F_OK) != -1) ? (geteuid() == 0 ? 2 : 1) : 2;
    #endif

    libusb_init(&ctx);

    if (method == 1) {
        const char *fd = getenv("TERMUX_USB_FD");
        if (fd == NULL) {
            printf("\n\nWithout root (termux-usb must be used)\n\n");
            return 1;
        }
        libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
        libusb_wrap_sys_device(ctx, (intptr_t)atoi(fd), &dev_handle);
        if (check_device(libusb_get_device(dev_handle))) {
            printf("\n\ndevice is not connected, or not in mi assistant mode\n\n");
            return 1;
        }
    } else {
        libusb_device **devs = NULL;
        ssize_t cnt = libusb_get_device_list(ctx, &devs);
        int i = 0;
        libusb_device *dev = NULL;
        while ((dev = devs[i++]) != NULL && check_device(dev) != 0);
        if (!dev) {
            printf("\n\ndevice is not connected, or not in mi assistant mode\n\n");
            return 1;
        } else {
            libusb_open(dev, &dev_handle) || libusb_claim_interface(dev_handle, interface_num);
        }        
    }

    int result = send_command(ADB_CONNECT, ADB_VERSION, ADB_MAX_DATA, "host::\x0", 7);
    char buf[512];
    adb_usb_packet pkt;
    if (result || recv_packet(&pkt, buf, &(int){sizeof(buf)}) || memcmp(buf, "sideload::", 10)) {
        printf("\nFailed to connect with device\n");
        return 1;
    }

    strncpy(device, adb_cmd("getdevice:"), sizeof(device) - 1);
    strncpy(version, adb_cmd("getversion:"), sizeof(version) - 1);
    strncpy(sn, adb_cmd("getsn:"), sizeof(sn) - 1);
    strncpy(codebase, adb_cmd("getcodebase:"), sizeof(codebase) - 1);
    strncpy(branch, adb_cmd("getbranch:"), sizeof(branch) - 1);
    strncpy(language, adb_cmd("getlanguage:"), sizeof(language) - 1);
    strncpy(region, adb_cmd("getregion:"), sizeof(region) - 1);
    strncpy(romzone, adb_cmd("getromzone:"), sizeof(romzone) - 1);

    // Apply overrides if any
    if (strlen(override_device) > 0) strncpy(device, override_device, sizeof(device) - 1);
    if (strlen(override_version) > 0) strncpy(version, override_version, sizeof(version) - 1);
    if (strlen(override_sn) > 0) strncpy(sn, override_sn, sizeof(sn) - 1);
    if (strlen(override_codebase) > 0) strncpy(codebase, override_codebase, sizeof(codebase) - 1);
    if (strlen(override_branch) > 0) strncpy(branch, override_branch, sizeof(branch) - 1);
    if (strlen(override_romzone) > 0) strncpy(romzone, override_romzone, sizeof(romzone) - 1);

    switch (choice) {
        case 1: {
            printf("\n\nDevice: %s\n", device);
            printf("Version: %s\n", version);
            printf("Serial Number: %s\n", sn);
            printf("Codebase: %s\n", codebase);
            printf("Branch: %s\n", branch);
            printf("Language: %s\n", language);
            printf("Region: %s\n", region);
            printf("ROM Zone: %s\n\n", romzone);
            break;
        }
        case 2: {
            validate_check("", 0);
            break;
        }
        case 3: {
            char filePath[256], md5[65];
            calculate_md5(filePath, md5);
            const char *validate = validate_check(md5, 1);
            if (validate) {
                start_sideload(filePath, validate);
            } 
            break;
        }
        case 4: {
            char *format = adb_cmd("format-data:");
            printf("\n%s\n", format);
            char *reboot = adb_cmd("reboot:");
            printf("\n%s\n", reboot);
            break;
        }
        case 5: {
            char *reboot = adb_cmd("reboot:");
            printf("\n%s\n", reboot);
            break;
        }
        default:
            printf("Invalid option selected.\n");
            break;
    }

}
