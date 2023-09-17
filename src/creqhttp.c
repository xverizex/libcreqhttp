#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <pthread.h>
#include "creqhttp.h"

#define HTTP_LINE         512
#define HTTP_VERSION       10
#define MAX_EVENTS         30

#define MAX_OPEN_SIZE   16384
#define MAX_SSL_SIZE     4096

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

struct _creqhttp_epoll_event;
typedef struct _creqhttp_epoll_event creqhttp_epoll_event;

struct _creqhttp_connection_params;
typedef struct _creqhttp_connection_params creqhttp_connection_params;

struct _creqhttp_epoll_event;
typedef struct _creqhttp_epoll_event creqhttp_epoll_event;

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
} creqhttp;

struct _http_req;
typedef struct _http_req http_req;

typedef struct _creqhttp_epoll_event {
	creqhttp *cq;
	http_req *http;
	int fd;
	creqhttp_data data;
	int first;
} creqhttp_epoll_event;

typedef struct _creqhttp_connection_params {
	int fd;
	creqhttp *cq;
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

static creqhttp_epoll_event *cb_init_connection_open_fd (creqhttp_connection_params *cq) {
	creqhttp_epoll_event *data = malloc (sizeof (creqhttp_epoll_event));
	data->cq = cq->cq;
	data->fd = cq->fd;
	data->http = NULL;
	data->first = 1;

	return data;
}

static creqhttp_epoll_event *cb_init_connection_ssl_fd (creqhttp_connection_params *cq) {
}

static char *find_field (http_req *r, char *field) {
	char *ret = NULL;
	for (int i = 0; i < r->fields_size; i++) {
		if (!strncmp (r->fields[i].field, field, strlen (field) + 1)) {
			ret = r->fields[i].value;
			break;
		}
	}

	return ret;
}

static int is_num (char *s) {
	int len = strlen (s);
	for (int i = 0; i < len; i++) {
		if (s[i] >= '0' && s[i] <= '9')
			continue;
		return 0;
	}

	return 1;
}

static void free_http (http_req *req) {
	if (req) {
		for (int i = 0; i < req->fields_size; i++) {
			if (req->fields) {
				if (req->fields[i].field)
					free (req->fields[i].field);
	
				if (req->fields[i].value)
					free (req->fields[i].value);
			}
		}

		if (req->post_data) {
			free (req->post_data);
			req->post_data = NULL;
		}

		free (req);
	}
}

http_req *creqhttp_parse_request (uint8_t *_data, uint64_t len) {
	http_req *req = NULL;
	uint8_t *line_req = NULL;
	uint8_t *http_version = NULL;
	req = malloc (sizeof (http_req));
	req->post_data = NULL;
	req->content_length = 0L;
	req->fields = NULL;

	uint8_t *r = malloc (len + 1);
	if (!r)
		goto err;

	memcpy (r, _data, len);
	r[len] = 0;

	uint8_t *end_of_header = strstr (r, "\r\n\r\n");
	if (end_of_header) {
		end_of_header[0] = end_of_header[1] = end_of_header[2] = end_of_header[3] = 0;
	} else {
		goto err;
	}

	for (uint64_t i = 0; i < len; i++) {
		if (r[i] == 0)
			break;

		if (r[i] == '\r' || r[i] == '\n')
			r[i] = 0;
	}

	/* search two space in first line in request */
	uint8_t *s = r;
	for (int i = 0; i < 3; i++) {
		s = strchr (s, ' ');
		if (s == NULL && i <= 1) {
			goto err;
		}
		if (!s)
			break;
		*s = 0;
		s++;
	}
	if (s)
		goto err;

	/* get type of request */
	struct requests {
		char *name;
		uint32_t type;
	} requests[] = {
		{"GET", REQ_GET},
		{"POST", REQ_POST}
	};

	uint32_t count_requests = sizeof (requests) / sizeof (struct requests);
	uint32_t found_type = REQ_UNSUPPORTED;
	for (uint32_t i = 0; i < count_requests; i++) {
		if (!memcmp (requests[i].name, r, strlen (r))) {
			found_type = requests[i].type;
			break;
		}
	}

	if (!found_type)
		goto err;

	/* get line request */
	s = strchr (r, 0);
	if (s)
		while (*s == 0) s++;
	
	uint32_t len_s = strlen (s);
	line_req = s;
	if (!line_req)
		goto err;

	/* get http version */
	s = strchr (s, 0);
	while (*s == 0) s++;

	http_version = s;

	/* fill header request */
	uint32_t len_line = strlen (line_req);
	uint32_t len_http_version = strlen (http_version);

	if (len_line >= HTTP_LINE)
		goto err;
	if (len_http_version >= HTTP_VERSION)
		goto err;

	if (!req)
		goto err;


	req->req.type = found_type;
	memcpy (req->req.line, line_req, len_line + 1);
	memcpy (req->req.version_http, http_version, len_http_version + 1);

	uint32_t count_in_block = 20;
	uint32_t cur_block = 1;

	uint32_t max_alloc_fields = cur_block * count_in_block;
	req->fields_size = 0;
	req->fields = malloc (sizeof (http_header_field) * max_alloc_fields);
	

	memset (&req->fields[0], 0, max_alloc_fields * sizeof (http_header_field));

	/* split header section */
	s = strchr (s, 0);
	while (*s == 0) s++;

	while (s <= end_of_header) {
		uint32_t len = 0;
		char *s_end = NULL;
		while (*s == ' ' && *s != 0) s++;
		if (*s == 0) {
			s++;
			continue;
		}
		s_end = s;
		while (*s_end != ':' && *s_end != 0) s_end++;
		if (*s_end == 0) {
			goto err;
		}
		*s_end = 0;
		char *truncate_field = (s_end - 1);
		while (*truncate_field == ' ') truncate_field--;
		if (*truncate_field == ' ')
			*truncate_field = 0;
		/* check field */
		if (strstr (s, " ")) {
			goto err;
		}
		

		char *val_start = (s_end + 1);
		while (*val_start == ' ') val_start++;

		uint32_t index = req->fields_size++;
		req->fields[index].field = NULL;
		req->fields[index].value = NULL;
		if (req->fields_size >= max_alloc_fields) {
			cur_block++;
			max_alloc_fields = cur_block * count_in_block;
			void *mem = NULL;
			mem = realloc (req->fields, sizeof (http_header_field) * max_alloc_fields);
			if (!mem) {
				goto err;
			}
			req->fields = mem;
			memset (&req->fields[index], 0, (max_alloc_fields - index) * sizeof (http_header_field));
		}
		
		req->fields[index].field = strdup (s);
		req->fields[index].value = strdup (val_start);

		s = strchr (val_start, 0);
		s++;
	}

#if 1
	for (int i = 0; i < req->fields_size; i++) {
		printf ("(%s == %s)\n",
				req->fields[i].field,
				req->fields[i].value
		       );
	}
#endif

	if (req->req.type == REQ_POST) {
		s = end_of_header + 4;

		uint64_t filled_size = s - r;
		uint64_t left_size = len - filled_size;

		char *num = find_field (req, "Content-Length");
		if (!num) {
			goto err;
		}

		if (!is_num (num)) {
			goto err;
		}

		uint64_t size = atol (num);

		req->left_size = left_size;
		req->content_length = size - left_size;
		req->post_data = malloc (left_size + 1);
		memcpy (req->post_data, s, left_size);
		req->post_data[left_size] = 0;
	}

	if (r)
		free (r);

	return req;

err:
	if (r)
		free (r);

	free_http (req);

	req = NULL;

	return req;
}


#if 0
static void func_handle (creqhttp_epoll_event *v) {

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
#endif

static void *thread_handle (void *_data) {
	creqhttp *cq = (creqhttp *) _data;

	while (1) {

		int nfds = epoll_wait (cq->epollfd,
				cq->events,
				MAX_EVENTS,
				-1
				);
		if (nfds == -1) {
			/*
			 * TODO: implement correct exit
			 */
			exit (EXIT_FAILURE);
		}

		uint8_t *data = malloc (cq->max_buffer_size + 1);
		data[cq->max_buffer_size] = 0;

		for (int n = 0; n < nfds; n++) {

			creqhttp_epoll_event *v = (creqhttp_epoll_event *) cq->events[n].data.ptr;
			creqhttp *cq = v->cq;

			int ret = read (v->fd, data, cq->max_buffer_size);
			if (ret < 0) {
				close (v->fd);
				continue;
			}

			v->data.data = data;
			v->data.len = ret;
			v->data.is_answer = 0;
			v->data.ans_data = NULL;
			v->data.ans_len = 0L;

			cq->cb_handle (v);

			if (v->data.is_answer)
				write (v->fd, v->data.ans_data, v->data.ans_len);
		}
	}
}

creqhttp *creqhttp_init (creqhttp_params *args) {
	creqhttp *cq = malloc (sizeof (creqhttp));

	cq->max_alloc_memory = args->max_alloc_memory;
	cq->port = args->port;
	cq->cb_handle = args->cb_handle;
	cq->epollfd = epoll_create1 (0);
	if (cq->epollfd == -1) {
		goto err;
	}

	pthread_create (&cq->thread_event, NULL, thread_handle, cq);

	cq->max_buffer_size = args->is_ssl ? MAX_SSL_SIZE: MAX_OPEN_SIZE;	
	cq->cb_init_connection = args->is_ssl ? 
		cb_init_connection_ssl_fd: 
		cb_init_connection_open_fd;

	return cq;
err:
	free (cq);
	return NULL;
}

int creqhttp_init_connection (creqhttp *cq) {
	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_port = htons (cq->port);
	memset (&s.sin_addr, 0, sizeof (s.sin_addr));

	int ret;
	ret = cq->sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (ret == -1) {
		return ret;
	}
	int opt = 1;
	ret = setsockopt (cq->sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof (opt));
	if (ret == -1) {
		close (cq->sockfd);
		return ret;
	}

	ret = bind (cq->sockfd, (const struct sockaddr *) &s, sizeof (s));
	if (ret == -1) {
		close (cq->sockfd);
		return ret;
	}

	ret = listen (cq->sockfd, 0);

	return ret;
}

typedef struct _creqhttp_connection {
	int fd;
	creqhttp *cq;

} creqhttp_connection;


int creqhttp_accept_connections (creqhttp *cq) {
#define SIZE_DATA      16384
	uint8_t data[SIZE_DATA];
	creqhttp_data cq_data;

	while (1) {
		int ret;
		int clientfd;
		struct sockaddr_in s;
		socklen_t size_s = sizeof (s);
		ret = clientfd = accept (cq->sockfd, (struct sockaddr *) &s, &size_s);
		if (ret == -1) {
			return ret;
		}

		creqhttp_connection_params params_init = {
			.fd = clientfd,
			.cq = cq
		};

		/*
		 * callback perform simple fd or ssl connection setup.
		 */
		creqhttp_epoll_event *event_info = cq->cb_init_connection (&params_init);
		/*
		 * TODO: implement thread work
		 */

		cq->ev.events = EPOLLIN;
		cq->ev.data.ptr = event_info;

		if (epoll_ctl (cq->epollfd, EPOLL_CTL_ADD, clientfd, &cq->ev) == -1) {
			free (event_info);
			continue;
		}
	}
}

#if 0
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
#endif
