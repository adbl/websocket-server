#include <string.h>

#include "Hash.h"
#include <Base64.h>
#include "websocket_handshake.h"
#include <unistd.h>

uint8_t hexCharValue(char chr);

TCPServer server = TCPServer(80);
TCPClient client;

uint8_t SHORT_PAYLOAD_LENGTH = 125;
uint16_t EXTENDED_PAYLOAD_LENGTH_16 = 0xffff;
/* RFC says MSB must be 0 (why?)  */
uint64_t EXTENDED_PAYLOAD_LENGTH_64 = 0x7fffffffffffffff;

/* ~150-210 KB/s, ~35-40 frames/s */
const uint32_t sendBufferLen = 4096; /* 8192 */
uint32_t sendBuffer[sendBufferLen/4];

void setup() {
  Serial.begin(9600);
  waitFor(Serial.isConnected, 5000);

  server.begin();
  Serial.println("server:");
  Serial.println(WiFi.localIP());
  /* Serial.println(WiFi.subnetMask()); */
  /* Serial.println(WiFi.gatewayIP()); */
  /* Serial.println(WiFi.SSID()); */
  Serial.print("\nwaiting");
  Serial.flush();

  for (uint32_t i=0; i != sendBufferLen/4; i++) {
      sendBuffer[i] = i;
  }
}

enum parse_status{
    REQUEST_LINE,
    REQUEST_HEADER_NAME,
    REQUEST_HEADER_VALUE,
    REQUEST_BODY
};

const char* WS_KEY_HEADER = "sec-websocket-key";
const char* WS_KEY_SUFFIX = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

uint16_t readHttpRequestHead(TCPClient client,
                             char* buffer,
                             uint16_t maxLength) {
    enum parse_status status = REQUEST_LINE;

    uint16_t idx = 0;
    while (status < REQUEST_BODY && client.available()) {
        char byte = client.read();

        buffer[idx++] = status == REQUEST_HEADER_NAME
            ? tolower(byte)
            : byte;

        /* Serial.printf("%c|%i|%c\n", byte, byte, buffer[idx-1]); */

        if (status == REQUEST_HEADER_NAME &&
            buffer[idx-1] == ' ' && buffer[idx-2] == ':') {
            status = REQUEST_HEADER_VALUE;
        }
        else if (byte == '\n' && buffer[idx-2] == '\r') {
            switch (status) {
            case REQUEST_LINE:
            case REQUEST_HEADER_VALUE:
                status = REQUEST_HEADER_NAME;
                break;
            case REQUEST_HEADER_NAME:
                if (buffer[idx-3] == '\n' && buffer[idx-4] == '\r') {
                    status = REQUEST_BODY;
                }
                break;
            }
        }

        /* TODO */
        /* if (idx == maxLength) {} */
    }
    /* ......... */

    buffer[idx] = '\0';
    return idx;
}

const uint16_t MAX_BUFFER = 1024;

void handshake() {
    char head[MAX_BUFFER];

    Serial.println("\nreading");
    Serial.flush();
    const uint16_t readBytes =
        readHttpRequestHead(client, head, MAX_BUFFER);
    Serial.printf("request, %u bytes:\n%s", readBytes, head);

    char key[MAX_BUFFER];
    int keyLen = header_value(head, WS_KEY_HEADER, key); /* != 0 */
    /* srpcpy */
    strcpy(key+keyLen, WS_KEY_SUFFIX);

    /* Serial.println("key with suffix"); */
    /* Serial.println(key); */
    String hashStr = sha1(key);
    /* Serial.println("hashStr"); */
    /* Serial.println(hashStr); */
    const uint8_t hashLen = hashStr.length();
    /* Serial.println("hashLen"); */
    /* Serial.println(hashLen); */
    const uint8_t bytesLen = hashLen / 2;
    char hashBytes[bytesLen];

    for (int i=0; i < hashLen; i++) {
        char chr = hashStr.charAt(i);
        uint8_t value = hexCharValue(chr);

        uint8_t byteIdx = i / 2;

        if (i % 2 == 0) {
            hashBytes[byteIdx] = value << 4;
        }
        else {
            hashBytes[byteIdx] |= value;
        }
        /* Serial.printlnf("%u: %c -> %x, %x", i, chr, value, hashBytes[byteIdx]); */
    }

    /* Serial.println(); */
    /* for (int i=0; i<bytesLen; i++) { */
    /*     Serial.printf("%x", hashBytes[i]); */
    /* } */
    /* Serial.println(); */

    const int base64Length = base64_enc_len(bytesLen);
    /* Serial.println("base64Length"); */
    /* Serial.println(base64Length); */

    char hashBase64[base64Length];
    base64_encode(hashBase64, hashBytes, bytesLen);
    /* Serial.println("hashBase64"); */
    /* Serial.println(hashBase64); */

    char response[MAX_BUFFER];
    /* handshakeLen =  */
    handshake_response(response, hashBase64);

    uint16_t wroteBytes = client.write(response);
    Serial.printf("wrote response, %u bytes:\n%s", wroteBytes, response);
}


/* const uint8_t FRAME_FIN                 = 0x00000001; */
/* const uint8_t FRAME_OPCODE_CONTINUATION = 0x00000000; */
/* const uint8_t FRAME_OPCODE_TEXT         = 0x00000010; */
/* const uint8_t FRAME_OPCODE_BINARY       = 0x00000020; */
/* const uint8_t FRAME_OPCODE_CLOSE        = 0x00000080; */
/* const uint8_t FRAME_OPCODE_PING         = 0x00000090; */
/* const uint8_t FRAME_OPCODE_PONG         = 0x000000a0; */
const uint8_t FRAME_FIN                 = 0x80;
const uint8_t FRAME_OPCODE_CONTINUATION = 0x00;
const uint8_t FRAME_OPCODE_TEXT         = 0x01;
const uint8_t FRAME_OPCODE_BINARY       = 0x02;
const uint8_t FRAME_OPCODE_CLOSE        = 0x08;
const uint8_t FRAME_OPCODE_PING         = 0x09;
const uint8_t FRAME_OPCODE_PONG         = 0x0a;
/* const uint32_t FRAME_PAYLOAD_MASK        = 0x00000100; */

void send(TCPClient client, const uint8_t* buf, const uint64_t length) {
    client.write(FRAME_FIN | FRAME_OPCODE_BINARY);

    if (length <= SHORT_PAYLOAD_LENGTH) {
        client.write(length);
    }
    else if (length <= EXTENDED_PAYLOAD_LENGTH_16) {
        client.write(126);
        /* hmmmmmmmmmmmmmmmmm... */
        uint16_t extendedLength = length;
        uint16_t eee;
        swab(&extendedLength, &eee, 2);
        client.write((const uint8_t *) &eee, 2);
    }
    else if (length <= EXTENDED_PAYLOAD_LENGTH_64) {
        /* not working probably */
        client.write(127);
        client.write((const uint8_t *) &length, 8);
    }

    client.write(buf, length);
}

/* WebSocketInterceptor */


bool hasHandshake = false;

void loop() {
    /* client.status(); */

  if (client.connected()) {
      if (!hasHandshake) {
          handshake();
          hasHandshake = true;

          Serial.printf("wait\n");
          Serial.flush();
          delay(2000);
      }
      else {
          uint32_t time = (uint32_t) micros();
          Serial.printf("time: %u\n", time);
          Serial.flush();

          sendBuffer[0] = time;

          send(client, (uint8_t *) &sendBuffer, sendBufferLen);
      }
  }
  else {
      hasHandshake = false;
      client = server.available();
      if (client.connected()) {
          Serial.print("\nclient: ");
          Serial.println(client.remoteIP());
          Serial.flush();
      }
      else {
          Serial.print(".");
          delay(1000);
      }
  }
}

uint8_t hexCharValue(char chr) {
    switch (chr) {
    case '0':
        return 0x00;
    case '1':
        return 0x01;
    case '2':
        return 0x02;
    case '3':
        return 0x03;
    case '4':
        return 0x04;
    case '5':
        return 0x05;
    case '6':
        return 0x06;
    case '7':
        return 0x07;
    case '8':
        return 0x08;
    case '9':
        return 0x09;
    case 'a':
        return 0x0a;
    case 'b':
        return 0x0b;
    case 'c':
        return 0x0c;
    case 'd':
        return 0x0d;
    case 'e':
        return 0x0e;
    case 'f':
        return 0x0f;
    }
}
