%%%-------------------------------------------------------------------
%%% Copyright: (c) 2007-2010 Gemini Mobile Technologies, Inc.  All rights reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%% File    : mod_gdss_s3_proto.erl
%%% Purpose : S3 implementation for inets/httpd and storage bricks.
%%%-------------------------------------------------------------------

%% @doc An inets/httpd module to handle the Amazon S3 REST protocol.
%%
%% This module implements the Amazon Simple Storage Service REST (HTTP) API.
%%
%% This implementation uses the brick_simple API, which limits its scalability.
%% At some point I need to rewrite this to do the more complicated dance that
%% the PSS protocol does.
%%
%% At the moment, this module takes care of the following:
%% <ul>
%% <li> S3 GET requests [SERVICE, BUCKET, OBJECT]. </li>
%% <li> S3 PUT requests [BUCKET, OBJECT]. </li>
%% <li> S3 DELETE BUCKET request. </li>
%% <li> S3 Authorization API.  This is actually an authentication API, since all it does is identify the user to the system. </li>
%% <li> S3 Extension: ADDUSER request.  Amazon add users outside of the scope of S3</li>
%% </ul>

-module(mod_gdss_s3_proto).

-compile([binary_comprehension]).

%% External API
-export([check_auth/1, make_auth/3, make_auth/8, make_head_object/5, make_get_object/5, make_get_bucket/4, make_get_service/3, make_put_object/6, make_put_bucket/4, make_delete_bucket/4, make_add_user/2, binary_to_hexlist/1, binary_to_integer/1, integer_to_binary/2, integer_to_binary/1, hexlist_to_binary/1]).

%% EWSAPI API
-export([do/1, load/2]).

-ifdef(new_inets).
-include_lib("inets/src/http_server/httpd.hrl").
-ifndef(NICE).
-define(NICE(Reason),lists:flatten(atom_to_list(?MODULE)++": "++Reason)).
-endif.
-else.
-include_lib("inets/src/httpd.hrl").
-endif.

-define(VMODULE,"S3").
-define(DEFAULT_S3_CHECK_AUTH, true).
-define(DEFAULT_S3_ENFORCE_AUTH, true).
-define(S3_TIMEOUT, 10000).
-define(S3_MAX_KEYS, 55555).
-define(S3_TABLE, 'tab1').
-define(S3_MASTER, "MASTER").
-define(S3_USER_TABLE, 's3_user_table').
-define(S3_BUCKET_TABLE, 's3_bucket_table').
-define(HASH_PREFIX_SEPARATOR, $/).

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc EWSAPI request callback.
do(ModData) ->
    try
        case proplists:get_value(status, ModData#mod.data) of
            {_StatusCode, _PhraseArgs, _Reason} ->
                {proceed, ModData#mod.data};
            undefined ->
                case proplists:get_value(response, ModData#mod.data) of
                    undefined ->
                        case get_s3_check_auth(ModData) of
                            true ->
                                case get_s3_enforce_auth(ModData) of
                                    true ->
                                        check_auth(ModData);
                                    false ->
                                        try
                                            check_auth(ModData)
                                        catch
                                            T:R ->
                                                io:format("~s:do: warning: authorization failed (~p:~p), but we aren't enforcing it!~n", [?MODULE, T, R])
                                        end
                                end;
                            false ->
                                %%io:format("~S:do: warning: not checking authorization!~n", [?MODULE])
                                ok
                        end,

                        Uri = ModData#mod.request_uri,

                        {Path, QS} = case string:tokens(Uri, "?") of
                                       [P, Q] ->
                                           {P, Q};
                                       [P] ->
                                           {P, []}
                                   end,

                        {Bucket, Key} = split_uri(Path, $/, 2),

                        case ModData#mod.method of
                            "GET" ->
                                do_get(ModData, Path, QS, Bucket, Key);
                            "PUT" ->
                                do_put(ModData, Path, QS, Bucket, Key);
                            "POST" ->
                                do_put(ModData, Path, QS, Bucket, Key);
                            "HEAD" ->
                                do_head(ModData, Path, QS, Bucket, Key);
                            "DELETE" ->
                                do_delete(ModData, Path, QS, Bucket, Key);
                            "ADDUSER" ->
                                do_add_user(ModData);
                            _ ->
                                {proceed, ModData#mod.data}
                        end;
                    _Response ->
                        {proceed, ModData#mod.data}
                end
           end
    catch
         Type:Reason ->
             Stack = erlang:get_stacktrace(),
             Msg = io_lib:format("~s encountered an error: ~p:~p at ~p", [?MODULE, Type, Reason, Stack]),
             write_error(500, "ApplicationError", Msg, ModData)
    end.

%% @spec (string(), list()) ->  eof |
%%                     ok |
%%                     {ok, list()} |
%%                     {ok, list(), tuple()} |
%%                     {ok, list(), list()} |
%%                     {error, term()}
%% @doc EWSAPI config callback.
load("S3CheckAuth " ++ AuthArg, [])->
    case catch list_to_atom(httpd_conf:clean(AuthArg)) of
        true ->
            {ok, [], {s3_check_auth, true}};
        false ->
            {ok, [], {s3_check_auth, false}};
        _ ->
            {error, ?NICE(httpd_conf:clean(AuthArg) ++ " is an invalid S3CheckAuth directive")}

    end;

load("S3EnforceAuth " ++ AuthArg, [])->
    case catch list_to_atom(httpd_conf:clean(AuthArg)) of
        true ->
            {ok, [], {s3_enforce_auth, true}};
        false ->
            {ok, [], {s3_enforce_auth, false}};
        _ ->
            {error, ?NICE(httpd_conf:clean(AuthArg) ++ " is an invalid S3EnforceAuth directive")}

    end.

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle all GET requests.
do_get(ModData, _Path, QS, Bucket, Key) ->
    if
        length(Bucket) > 0 andalso length(Key) > 0 ->
            get_object(Bucket, Key, QS, ModData);
        length(Bucket) > 0 ->
            get_bucket(Bucket, QS, ModData);
        true ->
            get_service(QS, ModData)
    end.

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle all HEAD requests.
do_head(ModData, _Path, _QS, Bucket, Key) ->
    case brick_simple:get(?S3_TABLE, make_brick_key(Bucket, Key), [witness, get_all_attribs], ?S3_TIMEOUT) of
        {ok, Ts, Flags} ->
            Vs = proplists:get_value(val_len, Flags, 0),
            FlagData = proplists:get_value(flagdata, Flags, []),

            CType = binary_to_list(proplists:get_value('content-type', FlagData, <<"binary/octet-stream">>)),
            ETag = binary_to_hexlist(proplists:get_value(etag, FlagData, <<"">>)),
            XAmz = [{atom_to_list(K), binary_to_list(V)} || {K, V} <- FlagData,
                                                            string:str(atom_to_list(K), "x-amz-") =:= 1],

            Headers = [{"timestamp", integer_to_list(Ts)},
                       {"content-length", integer_to_list(Vs)},
                       {"content-type", CType},
                       {"last-modified", make_date(Ts)},
                       {"ETag", ETag}] ++ XAmz,

            httpd_response:send_header(ModData, 200, Headers),

            %% httpd_response:send_final_chunk(ModData, true),

            {proceed, [{response, {already_sent, 200, 0}} | ModData#mod.data]};
        key_not_exist ->
            write_not_found(ModData)
    end.

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle all PUT requests.
do_put(ModData, _Path, QS, Bucket, Key) ->
    case Key of
	[_|_] ->
            put_object(Bucket, Key, ModData#mod.entity_body, QS, ModData);
        [] ->
            put_bucket(Bucket, QS, ModData)
    end.

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle all DELETE requests.
do_delete(ModData, _Path, _QS, Bucket, Key) ->
    case Key of
	[_|_] ->
            delete_object(Bucket, Key, ModData);
        [] ->
            delete_bucket(Bucket, ModData)
    end.

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle the ADDUSER request.
do_add_user(ModData) ->
    Name = key1search(ModData#mod.parsed_header, "x-amz-name"),
    add_user(Name, ModData).

%% @spec (mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Write a 404 'Not Found' error to the HTTP response, and return to EWSAPI.
write_not_found(ModData) ->
    write_error(404, "NoSuchKey", "The resource you requested does not exist", ModData).

%% @spec (integer(), string(), string(), mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Write a generic error to the HTTP response, and return to EWSAPI.
write_error(StatusCode, Code, Message, ModData) ->
    ReqID = <<"">>,
    Msg = [
<<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n">>,
<<"<Error>\r\n">>,
<<"  <Code>">>, Code, <<"</Code>\r\n">>,
<<"  <Message>">>, Message, <<"</Message>\r\n">>,
<<"  <Resource>">>, ModData#mod.request_uri, <<"</Resource>\r\n">>,
<<"  <RequestId>">>, ReqID, <<"</RequestId>\r\n">>,
<<"</Error>\r\n">>],

    httpd_response:send_header(ModData, StatusCode, [{"content-type", "text/xml"}, {"content-length", integer_to_list(iolist_size(Msg))}]),
    httpd_response:send_chunk(ModData, Msg, true),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, StatusCode, 0}} | ModData#mod.data]}.

%% @spec (string(), string(), term(), mod()) -> {proceed, OldData} | {proceed, NewData} | {break, NewData} | done
%% @doc Get the object with the passed key from the passed bucket.
get_object(Bucket, Key, _QS, ModData) ->
    case brick_simple:get(?S3_TABLE, make_brick_key(Bucket, Key), ?S3_TIMEOUT) of
        {ok, Ts, Val} ->
            Vs = size(Val),

            httpd_response:send_header(ModData, 200, [{"timestamp", integer_to_list(Ts)}, {"content-length", integer_to_list(Vs)}, {"content-type", "binary/octet-stream"}]),
            httpd_response:send_chunk(ModData, Val, true),
            %% httpd_response:send_final_chunk(ModData, true),

            {proceed, [{response, {already_sent, 200, Vs}} | ModData#mod.data]};
        key_not_exist ->
            write_not_found(ModData)
    end.

make_date(Ts) ->
    Now = brick_server:make_now(Ts),
    {_Mega, _Sec, _Micro} = Now,
    {Date, Time} = calendar:now_to_local_time(Now),
    {Year, Month, Day} = Date,
    {Hour, Minute, Second} = Time,

    io_lib:format("~4.10b-~2.10.0b-~2.10.0bT~2.10.0b:~.10b:~2.10.0bZ", [Year, Month, Day, Hour, Minute, Second]).

has_delimiter(Key, Delimiter) ->
    if
        Delimiter /= [] ->
            SKey = binary_to_list(Key),
            string:str(SKey, Delimiter) /= 0;
        true ->
            false
    end.

%% @spec (string(), term(), mod()) -> {proceed, OldData} | {proceed, NewData} | {break, NewData} | done
%% @doc List the contents of the passed bucket.
get_bucket(Bucket, QS, ModData) ->
    XmlHead = [
<<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n">>,
<<"<ListBucketResult xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\">\r\n">>,
<<"  <Name>">>, Bucket, <<"</Name>\r\n">>,
<<"  <IsTruncated>false</IsTruncated>\r\n">>],

    XmlTail = [
<<"</ListBucketResult>\r\n">>],

    KeyID = get_auth_key(ModData),
    Name = get_user_name(KeyID),

    XmlOwner = [
<<"    <Owner>\r\n">>,
<<"      <ID>">>, KeyID, <<"</ID>\r\n">>,
<<"      <DisplayName>">>, Name, <<"</DisplayName>\r\n">>,
<<"    </Owner>\r\n">>],

    Base = make_base_key(Bucket),
    Props = mod_admin:make_proplist(QS, "&", "="),

    Prefix =
        case proplists:get_value(prefix, Props) of
            undefined ->
                Base;
            true ->
                Base;
            P ->
                make_brick_key(Bucket, P)
        end,

    PPrefix = proplists:get_value(prefix, Props),

    MaxKeys =
        case proplists:get_value('max-keys', Props) of
            undefined ->
                ?S3_MAX_KEYS;
            _N ->
                %%list_to_integer(N)
                ?S3_MAX_KEYS
        end,

    Delimiter = proplists:get_value(delimiter, Props, []),

    Size = size(Prefix),

    {ok, {Data, _More}} = brick_simple:get_many(?S3_TABLE, Prefix, MaxKeys, [witness, get_all_attribs, {binary_prefix, Prefix}]),

    XmlContents = [ [ <<"  <Contents>\r\n">>, <<"    <Key>">>, Key, <<"</Key>\r\n">>, <<"    <LastModified>">>, make_date(Ts), <<"</LastModified>\r\n">>, <<"    <Size>">>, integer_to_list(proplists:get_value(val_len, Flags, 0)), <<"</Size>\r\n">>, XmlOwner, <<"  </Contents>\r\n">> ]
                    || {BucketKey, Ts, Flags} <- Data,
                       <<_KeyBase:Size/binary, Key/binary>> <= BucketKey,
                       size(Key) > 0,
                       (Prefix =:= Base andalso PPrefix =/= true) orelse has_delimiter(Key, Delimiter) =:= false ],

    Xml = [XmlHead, XmlContents, XmlTail],

    httpd_response:send_header(ModData, 200, [{"content-type", "text/xml"}, {"content-length", integer_to_list(iolist_size(Xml))}]),
    httpd_response:send_chunk(ModData, Xml, true),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 200, iolist_size(Xml)}} | ModData#mod.data]}.

%% @spec (atom()) -> {ok, integer(), binary()}
%% @doc Load the passed table from the brick.  Return the timestamp along with the data.
load_table_from_brick(Table) ->
    case brick_simple:get(?S3_TABLE, make_table_key(Table), ?S3_TIMEOUT) of
        {ok, Ts, Val} ->
            {Ts, binary_to_term(Val)};
        key_not_exist ->
            _ = brick_simple:set(?S3_TABLE, make_table_key(Table), term_to_binary([]), ?S3_TIMEOUT),
            load_table_from_brick(Table)
    end.

%% @spec (mod()) -> string()
%% @doc Parse the AWS header to get the passed key ID.
get_auth_key(ModData) ->
    ModAuth = key1search(ModData#mod.parsed_header, "authorization"),
    ["AWS", KeySig] = string:tokens(ModAuth, " "),
    case string:tokens(KeySig, ":") of
        [Key, _Sig] ->
            Key;
        [_Sig] ->
            ""
    end.

%% @spec (term(), mod()) -> {proceed, OldData} | {proceed, NewData} | {break, NewData} | done
%% @doc Handle the GET SERVICE request; list the buckets for this user.
get_service(_QS, ModData) ->
    XmlHead = [
<<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n">>,
<<"<ListAllMyBucketsResult xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\">\r\n">>,
<<"  <Owner>\r\n">>],

    XmlMid = [
<<"  </Owner>\r\n">>,
<<"  <Buckets>\r\n">>],

    XmlTail = [
<<"  </Buckets>\r\n">>,
<<"</ListAllMyBucketsResult>\r\n">>],

    Key = get_auth_key(ModData),
    Name = get_user_name(Key),
    XmlOwner = [
<<"    <ID>">>, Key, <<"</ID>\r\n">>,
<<"    <DisplayName>">>, Name, <<"</DisplayName>\r\n">>],

    {_Ts, Data} = load_table_from_brick(?S3_BUCKET_TABLE),
    XmlBuckets = [ [<<"    <Bucket><Name>">>, Bucket, <<"</Name><CreationDate>">>, Date, <<"</CreationDate></Bucket>\r\n">>] ||
                     {Bucket, {ID, Date}} <- Data,
                     ID =:= Key],

    Xml = [XmlHead, XmlOwner, XmlMid, XmlBuckets, XmlTail],

    httpd_response:send_header(ModData, 200, [{"content-type", "text/xml"}, {"content-length", integer_to_list(iolist_size(Xml))}]),

    httpd_response:send_chunk(ModData, Xml, true),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 200, 0}} | ModData#mod.data]}.

%% @spec (string(), string(), binary(), term(), mod()) -> {proceed, OldData} | {proceed, NewData} | {break, NewData} | done
%% @doc Handle the PUT OBJECT request; set the passed key/bucket to the passed value.
put_object(Bucket, Key, Val, _QS, ModData) ->
    ET = [{etag, crypto:md5(Val)}],
    CT =
        case key1search(ModData#mod.parsed_header, "content-type") of
            undefined ->
                [];
            H1 ->
                [{'content-type', list_to_binary(H1)}]
        end,

    XAmz = [{list_to_atom(K), list_to_binary(V)} || {K, V} <- ModData#mod.parsed_header,
                                                    string:str(K, "x-amz-") =:= 1],

    Flags = [{flagdata, ET ++ CT ++ XAmz}],
    ok = brick_simple:set(?S3_TABLE, make_brick_key(Bucket, Key), Val, 0, Flags, ?S3_TIMEOUT),
    httpd_response:send_header(ModData, 200, []),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 200, 0}} | ModData#mod.data]}.

%% @spec (string(), term(), mod()) -> {proceed, OldData} | {proceed, NewData} | {break, NewData} | done
%% @doc Handle the PUT BUCKET request; create a bucket with the passed name for this user.
put_bucket(Bucket, _QS, ModData) ->
    Key = get_auth_key(ModData),

    true = add_atomic(?S3_BUCKET_TABLE, Bucket, {Key, httpd_util:rfc1123_date()}),
    ok = brick_simple:set(?S3_TABLE, make_base_key(Bucket), <<"">>, ?S3_TIMEOUT),

    httpd_response:send_header(ModData, 200, []),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 200, 0}} | ModData#mod.data]}.

%% @spec (string(), string(), mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle the DELETE OBJECT request; delete the passed bucket/key from the brick.
delete_object(Bucket, Key, ModData) ->
    ok = brick_simple:delete(?S3_TABLE, make_brick_key(Bucket, Key), ?S3_TIMEOUT),
    httpd_response:send_header(ModData, 204, []),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 204, 0}} | ModData#mod.data]}.

%% @spec (string(), mod()) -> {proceed, binary()} | {break, binary()} | done
%% @doc Handle the DELETE BUCKET request; delete the passed bucket from the brick, and any associated keys.
delete_bucket(Bucket, ModData) ->
    %% first delete the bucket from the master buckets object
    ok = delete_atomic(?S3_BUCKET_TABLE, Bucket),

    %% next delete all keys from this bucket, including <<"bucket_">>
    Base = make_base_key(Bucket),
    Size = size(Base),
    {ok, {Data, _More}} = brick_simple:get_many(?S3_TABLE, Base, ?S3_MAX_KEYS, [witness, {binary_prefix, Base}]),
    _ = [ok = brick_simple:delete(?S3_TABLE, Key, ?S3_TIMEOUT)
         || {BucketKey, _Ts, _Val, _Opts, _Flags} <- Data,
            <<_KeyBase:Size/binary, Key/binary>> <= BucketKey],

    httpd_response:send_header(ModData, 204, []),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 204, 0}} | ModData#mod.data]}.

%% @spec (integer(), integer(), integer()) -> integer()
%% @doc Integer version of the standard pow() function.
pow(Base, Power, Acc) ->
    case Power of
        0 ->
            Acc;
        _ ->
            pow(Base, Power - 1, Acc * Base)
    end.

%% @spec (integer(), integer()) -> integer()
%% @doc Integer version of the standard pow() function; call the recursive accumulator to calculate.
pow(Base, Power) ->
    pow(Base, Power, 1).

%% @spec () -> term()
%% @doc Seed the random number generator with the output of erlang:now().
srand() ->
    {A, B, C} = erlang:now(),
    random:seed(A, B, C).

%% @spec (string(), mod()) -> {proceed, binary()}
%% @doc Handle the extension ADDUSER request; create a new key and key ID, save them, then return to the user.
add_user(Name, ModData) ->
    %% KeySize > 64 seems problematic
    KeySize = 64,
    _ = srand(),
    Rand = random:uniform(pow(2, KeySize)),
    BKey = <<Rand:KeySize>>,
    XKey = binary_to_hexlist(BKey),
    {ok, KeyID} = append_atomic(?S3_USER_TABLE, {Name, XKey}),

    httpd_response:send_header(ModData, 200, [{"x-amz-key-id", integer_to_list(KeyID)}, {"x-amz-key", XKey}]),
    %% httpd_response:send_final_chunk(ModData, true),

    {proceed, [{response, {already_sent, 200, 0}} | ModData#mod.data]}.

%% @spec (atom()) -> {ok, integer()}
%% @doc Load the passed table, and return the timestamp.
load_table(Table) ->
    case ets:info(Table) of
        undefined ->
            _ = ets:new(Table, [named_table, ordered_set, public]),
            ok;
        _Ret ->
            ok
    end,
    {Ts, Data} = load_table_from_brick(Table),
    Dump = ets:tab2list(Table),
    if
        Dump /= Data ->
            true = ets:delete_all_objects(Table),
            true = ets:insert(Table, Data),
            {ok, Ts};
        true ->
            {ok, Ts}
    end.

%% @spec (atom(), integer()) -> ok | {ts_error, integer()}
%% @doc Save the passed table iff the timestamp has not changed.
save_table(Table, Ts) ->
    Data = term_to_binary(ets:tab2list(Table)),
    brick_simple:set(?S3_TABLE, make_table_key(Table), Data, 0, [{testset, Ts}], ?S3_TIMEOUT).

%% @spec (atom(), string(), term()) -> true | false
%% @doc Add the key/val to the table, then try to save it.  If the add fails, return false; if the save fails, recurse and try again.
add_atomic(Table, Key, Val) ->
    {ok, Ts} = load_table(Table),
    case ets:insert_new(Table, {Key, Val}) of
        true ->
            case save_table(Table, Ts) of
                ok ->
                    true;
                _Ret ->
                    add_atomic(Table, Key, Val)
            end;
        false ->
            false
    end.

%% @spec (atom(), term()) -> {ok, string()}
%% @doc Append the passed value to the passed table; return the new key associated with the value.
append_atomic(Table, Val) ->
    {ok, _Ts} = load_table(Table),

    Key =
        case ets:last(Table) of
            '$end_of_table' ->
                1;
            LastKey ->
                LastKey + 1
        end,

    case add_atomic(Table, Key, Val) of
        true ->
            {ok, Key};
        false ->
            append_atomic(Table, Val)
    end.

%% @spec (atom(), string()) -> ok
%% @doc Delete the passed key from the passed table; recurse if necessary and return ok when done.
delete_atomic(Table, Key) ->
    {ok, Ts} = load_table(Table),
    true = ets:delete(Table, Key),
    case save_table(Table, Ts) of
        ok ->
            ok;
        _ ->
            delete_atomic(Table, Key)
    end.

%% @spec (string(), string()) -> binary()
%% @doc Take the passed bucket and key and mangle them into a binary suitable to be used as a key for the brick.
make_brick_key(Bucket, Key) ->
    iolist_to_binary([Bucket, ?HASH_PREFIX_SEPARATOR, Key]).

%% @spec (atom()) -> binary()
%% @doc Mangle the passed table into a key for the brick.
make_table_key(Table) ->
    make_brick_key(?S3_MASTER, atom_to_list(Table)).

%% @spec (string()) -> binary()
%% @doc Mangle the passed bucket name into a prefix key for the brick.
make_base_key(Bucket) ->
    make_brick_key(Bucket, "").

%% @spec (string(), string(), mod()) -> iolist()
%% @doc Make an S3 authorization string.
make_auth(KeyID, Key, ModData) ->
    AmzHeaders = orddict:to_list(orddict:from_list([NV || {Name,_Value} = NV <- ModData#mod.parsed_header, string:substr(Name, 1, 6) =:= "x-amz-"])),
    Uri = ModData#mod.request_uri,
    Resource =
        case string:tokens(Uri, "?") of
            [Path, _Qs] ->
                Path;
            [Path] ->
                Path
        end,

    make_auth(KeyID, Key,
              ModData#mod.method,
              key1search(ModData#mod.parsed_header, "content-md5", ""),
              key1search(ModData#mod.parsed_header, "content-type", ""),
              key1search(ModData#mod.parsed_header, "date"),
              AmzHeaders,
              Resource).

%% @spec (string(), string(), string(), string(), string(), string(), string(), string()) -> iolist()
%% @doc Make an S3 authorization string.
make_auth(KeyID, KeyData, Verb, ContentMD5, ContentType, Date, AmzHeaders, Resource) ->
    StringToSign =
        [Verb, "\n",
         ContentMD5, "\n",
         ContentType, "\n",
         Date, "\n",
         AmzHeaders,
         Resource],

    Signature = base64:encode_to_string(crypto:sha_mac(KeyData, StringToSign)),

    ["AWS", " ", KeyID, ":", Signature].

%% @spec (mod()) -> ok
%% @doc Check the auth header of the request against one generated; return ok if successful.
check_auth(ModData) ->
    case ModData#mod.method of
        "ADDUSER" ->
            ok;
        _ ->
            KeyID = get_auth_key(ModData),
            ModAuth = list_to_binary(key1search(ModData#mod.parsed_header, "authorization")),
            {ok, _Ts} = load_table(?S3_USER_TABLE),
            [{_, {_Name, HexKey}}] = ets:lookup(?S3_USER_TABLE, list_to_integer(KeyID)),
            MakeAuth = iolist_to_binary(make_auth(KeyID, HexKey, ModData)),
            if
                MakeAuth =:= ModAuth ->
                    ok
            end
    end.

%% @spec (string()) -> string()
%% @doc Get the user name corresponding to the passed key ID.
get_user_name(KeyID) ->
    {ok, _Ts} = load_table(?S3_USER_TABLE),
    [{_, {Name, _HexKey}}] = ets:lookup(?S3_USER_TABLE, list_to_integer(KeyID)),
    Name.

%% @spec (string(), string(), string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_head_object(Bucket, Key, Host, KeyID, KeyData) ->
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/", Bucket, "/", Key],

    _Data =
        ["HEAD ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "GET", "", "", Date, AmzHeaders, Resource), "\r\n\r\n"].

%% @spec (string(), string(), string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_get_object(Bucket, Key, Host, KeyID, KeyData) ->
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/", Bucket, "/", Key],

    _Data =
        ["GET ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "GET", "", "", Date, AmzHeaders, Resource), "\r\n\r\n"].

%% @spec (string(), string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_get_bucket(Bucket, Host, KeyID, KeyData) ->
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/", Bucket, "/"],

    _Data =
        ["GET ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "GET", "", "", Date, AmzHeaders, Resource), "\r\n\r\n"].

%% @spec (string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_get_service(Host, KeyID, KeyData) ->
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/"],

    _Data =
        ["GET ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "GET", "", "", Date, AmzHeaders, Resource), "\r\n\r\n"].

%% @spec (string(), string(), string(), string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_put_object(Bucket, Key, Val, Host, KeyID, KeyData) ->
    Content = Val,
    ContentLength = integer_to_list(size(Content)),
    ContentMD5 =  binary_to_hexlist(crypto:md5(Content)),
    ContentType = "binary/octet-stream",
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/", Bucket, "/", Key],

    _Data =
        ["PUT ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Content-Type: ", ContentType, "\r\n",
         "Content-Length: ", ContentLength, "\r\n",
         "Content-MD5: ", ContentMD5, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "PUT", ContentMD5, ContentType, Date, AmzHeaders, Resource), "\r\n\r\n",
         Content, "\r\n"].

%% @spec (string(), string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_put_bucket(Bucket, Host, KeyID, KeyData) ->
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/", Bucket, "/"],

    _Data =
        ["PUT ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "PUT", "", "", Date, AmzHeaders, Resource), "\r\n\r\n"].

%% @spec (string(), string(), string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_delete_bucket(Bucket, Host, KeyID, KeyData) ->
    Date = httpd_util:rfc1123_date(),
    AmzHeaders = "",
    Resource = ["/", Bucket, "/"],

    _Data =
        ["DELETE ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "Date: ", Date, "\r\n",
         "Authorization: ", make_auth(KeyID, KeyData, "DELETE", "", "", Date, AmzHeaders, Resource), "\r\n\r\n"].

%% @spec (string(), string()) -> iolist()
%% @doc Create a request that can be piped over the network.
make_add_user(Name, Host) ->
    Date = httpd_util:rfc1123_date(),
    Resource = ["/"],

    _Data =
        ["ADDUSER ", Resource, " HTTP/1.1\r\n",
         "Host: ", Host, "\r\n",
         "X-Amz-Name: ", Name, "\r\n",
         "Date: ", Date, "\r\n\r\n"].

%% @spec (mod()) -> atom()
%% @doc Check the module data to see if we are configured to check authorization.
get_s3_check_auth(ModData) ->
    httpd_util:lookup(ModData#mod.config_db, s3_check_auth, ?DEFAULT_S3_CHECK_AUTH).

%% @spec (mod()) -> atom()
%% @doc Check the module data to see if we are configured to enforce authorization.
get_s3_enforce_auth(ModData) ->
    httpd_util:lookup(ModData#mod.config_db, s3_enforce_auth, ?DEFAULT_S3_ENFORCE_AUTH).

%% @spec (binary()) -> string()
%% @doc Convert the passed binary into a string where the numbers are represented in hexadecimal (lowercase and 0 prefilled).
binary_to_hexlist(Bin) ->
    XBin =
        [ begin
              Hex = erlang:integer_to_list(X, 16),
              if
                  X < 16 ->
                      lists:flatten(["0" | Hex]);
                  true ->
                      Hex
              end
          end || X <- binary_to_list(Bin)],

    string:to_lower(lists:flatten(XBin)).

%% @spec (binary()) -> integer()
%% @doc Convert the passed binary into an integer.
binary_to_integer(Bin) ->
    binary_to_integer(Bin, size(Bin) * 8).

%% @spec (binary(), integer()) -> integer()
%% @doc Convert N bits of the passed binary into an integer.
binary_to_integer(Bin, N) ->
    <<Int:N, _/binary>> = Bin,
    Int.

%% @spec (integer()) -> binary()
%% @doc Convert the passed integer to a binary.
integer_to_binary(Int) ->
    L = math:log(Int + 1) / math:log(2),
    T = trunc(L),
    Diff = L - T,

    N = case Diff of
            0.0 ->
                T;
            _ ->
                T + 1
        end,

    Div = N div 8,
    Rem = N rem 8,
    case Rem of
        0 ->
            integer_to_binary(Int, N);
        _ ->
            integer_to_binary(Int, Div * 8 + 8)
    end.

%% @spec (integer(), integer()) -> binary()
%% @doc Convert the passed integer to an N-bit binary.
integer_to_binary(Int, N) ->
    <<Int:N>>.

%% @spec (string()) -> binary()
%% @doc Convert the passed hexadecimal string to a binary.
hexlist_to_binary(Hex) ->
    Int = erlang:list_to_integer(Hex, 16),
    integer_to_binary(Int).

key1search(TupleList, Key) ->
    key1search(TupleList, Key, undefined).

key1search(TupleList, Key, Undefined) ->
    case lists:keyfind(Key, 1, TupleList) of
        {Key, Value} ->
            Value;
        false ->
            Undefined
    end.

split_uri([], _Sep, _X, _N, Acc) ->
    {lists:reverse(Acc), []};
split_uri(Path, _Sep, X, X, Acc) ->
    {lists:reverse(Acc), Path};
split_uri([Sep | Rest], Sep, X, N, Acc) ->
    split_uri(Rest, Sep, X, N + 1, Acc);
split_uri([C | Rest], Sep, X, N, Acc) ->
    split_uri(Rest, Sep, X, N, [C | Acc]).

split_uri(Path, Sep, X) ->
    split_uri(Path, Sep, X, 0, []).

