#ifndef WEBSOCKET_HANDSHAKE_H_
#define WEBSOCKET_HANDSHAKE_H_

int header_value(const char* requestHead,
                 const char* headerName,
                 char* value);

int handshake_response(char* buffer,
                       const char* acceptValue);

#endif
