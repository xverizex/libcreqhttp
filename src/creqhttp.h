#ifndef CREQ_HTTP_H
#define CREQ_HTTP_H

enum {
	REQ_UNSUPPORTED,
	REQ_GET,
	REQ_POST,
	N_REQ
};

struct _creqhttp;
struct _http_req;
struct _creqhttp_data;
struct _creqhttp_epoll_event;
typedef struct _creqhttp creqhttp;
typedef struct _http_req http_req;
typedef struct _creqhttp_data creqhttp_data;
typedef struct _creqhttp_epoll_event creqhttp_epoll_event;

typedef struct _creqhttp_params {
	uint32_t is_ssl;
	uint64_t max_alloc_memory;
	void (*cb_handle) (creqhttp_epoll_event *_data);
	uint16_t port;
} creqhttp_params;


int creqhttp_init_connection (creqhttp *cq);
creqhttp *creqhttp_init (creqhttp_params *args);
int creqhttp_accept_connections (creqhttp *cq);
http_req *creqhttp_parse_request (uint8_t *_data, uint64_t len);
#endif
