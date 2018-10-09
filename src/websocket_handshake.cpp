#include <stdio.h>
#include <string.h>

#include "websocket_handshake.h"

/* HTTP/1.1 101 Switching Protocols */
/* Upgrade: websocket */
/* Connection: Upgrade */
/* Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo= */
/* Sec-WebSocket-Protocol: chat */

const char* RESPONSE = "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\r\n";
// Sec-WebSocket-Protocol: chat\r\n\

int header_value(const char* requestHead,
                 const char* headerName,
                 char* value) {
    /* strpbrk—find characters in string */
    /* char *strpbrk(const char *s1, const char *s2); */

    short prefixLength = strlen(headerName)+4;
    char search[prefixLength];
    sprintf(search, "\r\n%s: ", headerName);

    /* strcasestr segfault ?? */
    char *idx = strstr(requestHead, search);
    if (idx == NULL) {
        return -1;
    }
    idx += prefixLength;

    char* val = value;
    int len = 0;
    while (!(*idx == '\r' && *(idx+1) == '\n')) {
        *(val++) = *(idx++);
        len++;
    }
    *val = '\0';

    return len;
}


int handshake_response(char* buffer, const char* acceptValue) {
    return sprintf(buffer, RESPONSE, acceptValue);
}
