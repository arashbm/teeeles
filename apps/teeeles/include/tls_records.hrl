-record(tls_record, {record_value}).

-record(tls_handshake, {type,  message}).

-define(TLSVersionValue, <<3, 3>>).

-define(HandshakeTypeHelloRequest,      0).
-define(HandshakeTypeClientHello,       1).
-define(HandshakeTypeServerHello,       2).
-define(HandshakeTypeCertificate,       11).
-define(HandshakeTypeServerKeyExchange, 12).
-define(HandshakeTypeServerHelloDone,   14).
-define(HandshakeTypeClientKeyExchange, 16).

-define(RecordTypeChangeCipherSpec, 20).
-define(RecordTypeAlert,            21).
-define(RecordTypeHandshake,        22).
-define(RecordTypeApplicationData,  23).

-define(TLS_RSA_WITH_AES_128_CBC_SHA, <<0, 47>>).
