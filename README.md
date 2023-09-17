# creqhttp library

My first implementation http get post input request.

# How you should use this library
```
void func_handle (creqhttp_epoll_event *v) {

        http_req *htr = NULL;


        if (!v->http) {
                htr = creqhttp_parse_request (v->data.data, v->data.len);
                if (!htr) {
                        fprintf (stderr, "cannot get\n");
                        return;
                }
                v->http = htr;
                FILE *fp = fopen ("data.out", "w");
                size_t writed = fwrite (v->http->post_data, 1, v->http->left_size, fp);
                v->http->left_size = 0;
                fclose (fp);
                v->first = 0;
        } else {
                FILE *fp = fopen ("data.out", "a");
                v->http->left_size = 0;
                v->http->content_length -= v->data.len;
                size_t writed = fwrite (v->data.data, 1, v->data.len, fp);

                if (v->http->content_length <= 0) {
                        free_http (v->http);
                        v->http = NULL;
                }
                fclose (fp);
        }
}

int main (int argc, char **argv) {
        int ret; 

        creqhttp_params args = {
                .is_ssl = 0,
                .port = 8080,
                .cb_handle = func_handle
        };
        creqhttp *cq = creqhttp_init (&args);
        ret = creqhttp_init_connection (cq);
        if (ret == -1) {
                fprintf (stderr, "ret == %d\n", ret);
                exit (EXIT_FAILURE); 
        }
        creqhttp_accept_connections (cq);
}
```
