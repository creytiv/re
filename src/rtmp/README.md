RTMP module
-----------

This module implements Real Time Messaging Protocol (RTMP) [1].




Functional overview:
-------------------

```
RTMP Specification v1.0 .......... YES
RTMP with TCP transport .......... YES

RTMPS (RTMP over TLS) ............ NO
RTMPE (RTMP over Adobe Encryption) NO
RTMPT (RTMP over HTTP) ........... NO
RTMFP (RTMP over UDP) ............ NO

Transport:
Client ........................... YES
Server ........................... YES
IPv4 ............................. YES
IPv6 ............................. YES
DNS Resolving A/AAAA ............. YES

RTMP Components:
RTMP Handshake ................... YES
RTMP Header encoding and decoding. YES
RTMP Chunking .................... YES
RTMP Dechunking .................. YES
AMF0 (Action Message Format) ..... YES
AMF3 (Action Message Format) ..... NO
Send and receive audio/video ..... YES
Regular and extended timestamp ... YES
Multiple streams ................. YES
```




TODO:
----

- [x] improve AMF encoding API
- [x] implement AMF transaction matching
- [x] add support for Data Message
- [x] add support for AMF Strict Array (type 10)
- [ ] add support for TLS encryption
- [x] add support for extended timestamp




Protocol stack:
--------------

    .-------.  .-------.  .-------.
    |  AMF  |  | Audio |  | Video |
    '-------'  '-------'  '-------'
        |          |          |
        +----------+----------'
                   |
               .-------.
               |  RTMP |
               '-------'
                   |
                   |
               .-------.
               |  TCP  |
               '-------'




Message Sequence:
----------------


```
Client                                      Server

|----------------- TCP Connect -------------->|
|                                             |
|                                             |
|                                             |
|<-------------- 3-way Handshake ------------>|
|                                             |
|                                             |
|                                             |
|----------- Command Message(connect) ------->| chunkid=3, streamid=0, tid=1
|                                             |
|<------- Window Acknowledgement Size --------| chunkid=2, streamid=0
|                                             |
|<----------- Set Peer Bandwidth -------------| chunkid=2, streamid=0
|                                             |
|-------- Window Acknowledgement Size ------->|
|                                             |
|<------ User Control Message(StreamBegin) ---| chunkid=2, streamid=0
|                                             |
|<------------ Command Message ---------------| chunkid=3, streamid=0, tid=1
|        (_result- connect response)          |
```


Interop:
-------

- Wowza Streaming Engine 4.7.1
- Youtube service
- FFmpeg's RTMP module




References:
----------

[1] http://wwwimages.adobe.com/www.adobe.com/content/dam/acom/en/devnet/rtmp/pdf/rtmp_specification_1.0.pdf

[2] https://wwwimages2.adobe.com/content/dam/acom/en/devnet/flv/video_file_format_spec_v10_1.pdf

[3] https://en.wikipedia.org/wiki/Action_Message_Format

[4] https://wwwimages2.adobe.com/content/dam/acom/en/devnet/pdf/amf0-file-format-specification.pdf
