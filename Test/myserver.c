#include <microhttpd.h>
#include <stdio.h>
#include <string.h>

#define PORT 8888

enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     const char *version, const char *upload_data,
                                     size_t *upload_data_size, void **con_cls) {
    const char *response_text = "Hello from C!";
    struct MHD_Response *response;
    enum MHD_Result ret;

    response = MHD_create_response_from_buffer(strlen(response_text),
                                               (void *)response_text, MHD_RESPMEM_PERSISTENT);

    // Add CORS headers to the response
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

int main() {
    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL, 
                              &answer_to_connection, NULL, MHD_OPTION_END);
    if (NULL == daemon) return 1;

    printf("Server running on port %d. Press Enter to terminate.\n", PORT);
    getchar(); // Press Enter to terminate

    MHD_stop_daemon(daemon);
    printf("Server has been stopped.\n");
    return 0;
}

