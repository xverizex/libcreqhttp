#ifndef CREQ_HTTP_H
#define CREQ_HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>

enum {
	REQ_UNSUPPORTED,
	REQ_GET,
	REQ_POST,
	N_REQ
};

#define HTTP_LINE         512
#define HTTP_VERSION       10
#define MAX_EVENTS         30

#define MAX_OPEN_SIZE   16384
#define MAX_SSL_SIZE     4096

struct _creqhttp;
struct _http_req;
struct _creqhttp_data;
struct _creqhttp_epoll_event;
typedef struct _creqhttp creqhttp;
typedef struct _http_req http_req;
typedef struct _creqhttp_data creqhttp_data;
typedef struct _creqhttp_epoll_event creqhttp_epoll_event;

typedef struct _creqhttp_connection {
	int fd;
	creqhttp *cq;
} creqhttp_connection;

typedef struct _creqhttp_data {
	uint64_t len;
	uint8_t *data;
	uint8_t *ans_data;
	uint64_t ans_len;
	uint32_t is_answer;
	http_req *http;
	FILE *fp;
	int first;
} creqhttp_data;

struct _creqhttp_connection_params;
typedef struct _creqhttp_connection_params creqhttp_connection_params;

typedef struct _creqhttp {
	uint64_t max_alloc_memory;
	void (*cb_handle) (creqhttp_epoll_event *_data);
	creqhttp_epoll_event *(*cb_init_connection) (creqhttp_connection_params *args);
	struct epoll_event ev;
	struct epoll_event events[MAX_EVENTS];
	int epollfd;
	int sockfd;
	int max_buffer_size;
	pthread_t thread_event;
	uint16_t port;
	SSL_CTX *ctx;
	SSL *ssl;
	char *cert_file;
	char *private_key_file;
	uint32_t is_ssl;
} creqhttp;

typedef struct _creqhttp_epoll_event {
	creqhttp *cq;
	http_req *http;
	int fd;
	creqhttp_data data;
	int first;
	SSL_CTX *ctx;
	SSL *ssl;
	uint32_t is_ssl;
} creqhttp_epoll_event;

typedef struct _creqhttp_connection_params {
	int fd;
	creqhttp *cq;
	char *cert_file;
	char *private_key_file;
	SSL_CTX *ctx;
	int is_ssl;
} creqhttp_connection_params;


typedef struct _http_header_req {
	uint32_t type;
	uint8_t line[HTTP_LINE];
	uint8_t version_http[HTTP_VERSION];
} http_header_req;

typedef struct _http_header_field {
	char *field;
	char *value;
} http_header_field;

typedef struct _http_req {
	http_header_req req;
	http_header_field *fields;
	uint32_t fields_size;
	uint8_t *post_data;
	int64_t content_length;
	uint64_t left_size;
} http_req;

typedef struct _creqhttp_params {
	uint32_t is_ssl;
	uint64_t max_alloc_memory;
	void (*cb_handle) (creqhttp_epoll_event *_data);
	uint16_t port;
	char *cert_file;
	char *private_key_file;
	SSL_CTX *ctx;
	SSL *ssl;
} creqhttp_params;


int creqhttp_init_connection (creqhttp *cq);
creqhttp *creqhttp_init (creqhttp_params *args);
int creqhttp_accept_connections (creqhttp *cq);
void free_http (http_req *);
http_req *creqhttp_parse_request (uint8_t *_data, uint64_t len);
#endif
