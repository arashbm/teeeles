%%%-------------------------------------------------------------------
%%% @author arashbm
%%% @copyright (C) 2016, arashbm
%%% @doc
%%%
%%% @end
%%% Created : 2016-11-21 14:53:13.211252
%%%-------------------------------------------------------------------
-module(teeeles_client).

-behaviour(gen_statem).

%% API
-export([start_link/1]).

%% gen_statem callbacks
-export([
         init/1,
         hello/3,
         terminate/3,
         code_change/4,
         callback_mode/0
        ]).

-include("tls_records.hrl").
-include_lib("public_key/include/public_key.hrl").

-record(state, {
          manager,
          client_random :: binary(),
          server_random :: binary(),
          suit :: binary(),
          compression :: byte(),
          cert_chain :: [#'OTPCertificate'{}]
         }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_statem process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Manager) ->
  gen_statem:start_link(?MODULE, [Manager], []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_statem is started using gen_statem:start/[3,4] or
%% gen_statem:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {CallbackMode, StateName, State} |
%%                     {CallbackMode, StateName, State, Actions} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init([Manager]) ->
  RandomBytes = crypto:strong_rand_bytes(28),
  Random = <<(os:system_time(seconds)):32,
             RandomBytes/binary>>,
  SessionID = <<>>,    % no session ID
  Suits = <<?TLS_RSA_WITH_AES_128_CBC_SHA/binary>>,   % only this for now
  CompressionMethods = <<0>>, % nope nope nope
  Extentions = <<>>,

  ClientHelloMessage = <<
                         ?TLSVersionValue/binary,
                         Random/binary,  % Random Structure

                         (byte_size(SessionID)):8,
                         SessionID/binary,

                         (byte_size(Suits)):16,
                         Suits/binary,   % CipherSuits

                         (byte_size(CompressionMethods)):8,
                         CompressionMethods/binary,

                         (byte_size(Extentions)):16,
                         Extentions/binary
                       >>,


  ClientHello = #tls_record{record_value =
                            #tls_handshake{
                               type = ?HandshakeTypeClientHello,
                               message = ClientHelloMessage
                              }},

  teeeles_connection_manager:send(Manager, ClientHello),

  {ok, hello, #state{manager=Manager}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name.  If callback_mode is statefunctions, one of these
%% functions is called when gen_statem receives and event from
%% call/2, cast/2, or as a normal process message.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Actions} |
%%                   {stop, Reason, NewState} |
%%    				 stop |
%%                   {stop, Reason :: term()} |
%%                   {stop, Reason :: term(), NewData :: data()} |
%%                   {stop_and_reply, Reason, Replies} |
%%                   {stop_and_reply, Reason, Replies, NewState} |
%%                   {keep_state, NewData :: data()} |
%%                   {keep_state, NewState, Actions} |
%%                   keep_state_and_data |
%%                   {keep_state_and_data, Actions}
%% @end
%%--------------------------------------------------------------------
hello(cast, #tls_record{record_value = #tls_handshake{
                                          type = ?HandshakeTypeServerHello,
                                          message = ServerHello
                                         }}, State) ->
  Version = ?TLSVersionValue,
  <<Version:2/binary,
    ServerRandom:32/binary,
    SessionIDLength, Rest/binary>> = ServerHello,
  lager:info("ServerHello"),
  <<_Session:SessionIDLength/binary, Suit:2/binary, Compression, _Exts/binary>> = Rest,
  {keep_state, State#state{server_random=ServerRandom,
                           suit=Suit,
                           compression=Compression}};
hello(cast, #tls_record{record_value = #tls_handshake{
                                          type = ?HandshakeTypeCertificate,
                                          message = CertMsg
                                         }}, State) ->
  <<_CertLen:24, CertBin/binary>> = CertMsg,
  CertChain = decode_certs(CertBin),
  {keep_state, State#state{cert_chain=CertChain}};
hello(cast, #tls_record{record_value = #tls_handshake{
                                          type = ?HandshakeTypeServerKeyExchange,
                                          message = ServerKeyExchange
                                         }}, State) ->
  lager:info("ServerKeyExchange: ~p", [ServerKeyExchange]),
  {keep_state, State};
hello(cast, #tls_record{record_value = #tls_handshake{
                                          type = ?HandshakeTypeServerHelloDone
                                         }}, State = #state{}) ->
  lager:info("ServerHelloDone."),
  case verify_connection_state(State) of
    {error, Error} ->
      {stop, Error, State};
    ok ->
      {next_state, key_exchange, State}
  end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_statem when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_statem terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
  {ok, StateName, State}.

callback_mode() ->
  state_functions.

%%%===================================================================
%%% Internal functions
%%%===================================================================

decode_certs(Bin) ->
  decode_certs(Bin, []).

decode_certs(<<>>, Decoded) ->
  Decoded;
decode_certs(<<CertLen:24,CertAndRest/binary>>, Decoded) ->
  <<Cert:CertLen/binary, Rest/binary>> = CertAndRest,
  DecodedCert = public_key:pkix_decode_cert(Cert, otp),
  lager:info("Certificate: ~p", [lager:pr(DecodedCert, ?MODULE)]),
  decode_certs(Rest, Decoded ++ [DecodedCert]).

verify_connection_state(#state{compression=C}) when C =/= 0 ->
  {error, compression_not_supported};
verify_connection_state(#state{suit=S}) when S =/= ?TLS_RSA_WITH_AES_128_CBC_SHA ->
  {error, bad_server_cipher_suit};
verify_connection_state(#state{cert_chain=Chain}) ->
  teeeles_certificate:verify_chain(Chain).
