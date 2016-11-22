%%%-------------------------------------------------------------------
%%% @author arashbm
%%% @copyright (C) 2016, arashbm
%%% @doc
%%%
%%% @end
%%% Created : 2016-11-21 17:59:11.889252
%%%-------------------------------------------------------------------
-module(teeeles_connection_manager).

-behaviour(gen_server).

%% API
-export([start_link/2, send/2]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {socket, client, rest = <<>>}).

-include("tls_records.hrl").

%%%===================================================================
%%% API
%%%===================================================================

send(Manager, Record = #tls_record{}) ->
  gen_server:cast(Manager, {send_record, Record}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Host, Port) ->
  gen_server:start_link(?MODULE, [Host, Port], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Host, Port]) ->
  {ok, Socket} = gen_tcp:connect(Host, Port,
                                 [{active, once}, binary],
                                 10000),
  {ok, Client} = teeeles_client:start_link(self()),
  {ok, #state{socket=Socket, client=Client}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
  Reply = ok,
  {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({send_record, Record = #tls_record{}},
            State = #state{socket=Socket}) ->
  lager:info("Sending record: ~p", [Record]),
  ok = gen_tcp:send(Socket, record_to_binary(Record)),
  {noreply, State};
handle_cast(_Msg, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({tcp, Socket, Payload}, State = #state{socket=Socket,
                                                   client=Client,
                                                   rest=Rest}) ->
  inet:setopts(Socket, [{active, once}]),
  NewRest = parse_payload(<<Rest/binary, Payload/binary>>, Client),
  {noreply, State#state{rest = NewRest}};
handle_info(_Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

record_to_binary(#tls_record{record_value=RecordValue}) ->
  {RecordType, RecordValueBinary} = case RecordValue of
                                      #tls_handshake{} ->
                                        {?RecordTypeHandshake,
                                         handshake_to_binary(RecordValue)}
                                    end,
  <<RecordType,
    ?TLSVersionValue/binary,
    (byte_size(RecordValueBinary)):16,
    RecordValueBinary/binary>>.

handshake_to_binary(#tls_handshake{type = HandshakeType, message = Message}) ->
  <<HandshakeType, (byte_size(Message)):24, Message/binary>>.

binary_to_record(Bin) when byte_size(Bin) < 5 ->
  more;
binary_to_record(<<RecordType, _:2/binary, Size:16, ValueAndRest/binary>>) ->
  case byte_size(ValueAndRest) >= Size of
    true ->
      <<ValueBin:Size/binary, Rest/binary>> = ValueAndRest,
      Value = case RecordType of
                ?RecordTypeHandshake -> binary_to_hanshake(ValueBin)
              end,
      {#tls_record{record_value = Value}, Rest};
    _ ->
      more
  end.

binary_to_hanshake(<<?HandshakeTypeServerHelloDone, 0:24>>) ->
  #tls_handshake{type = ?HandshakeTypeServerHelloDone, message = <<>>};
binary_to_hanshake(HandshakeBin) ->
  <<Type, _Size:24, Message/binary>> = HandshakeBin,
  #tls_handshake{type=Type, message=Message}.

parse_payload(Payload, Client) ->
  case binary_to_record(Payload) of
    more ->
      Payload;
    {TLSRecord, Rest} ->
      gen_statem:cast(Client, TLSRecord),
      parse_payload(Rest, Client)
  end.
