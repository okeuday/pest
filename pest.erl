#!/usr/bin/env escript
%%!
%-*-Mode:erlang;coding:utf-8;tab-width:4;c-basic-offset:4;indent-tabs-mode:()-*-
% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
%%%------------------------------------------------------------------------
%%% @doc
%%% ==Primitive Erlang Security Tool (PEST)==
%%% @end
%%%
%%% BSD LICENSE
%%% 
%%% Copyright (c) 2016, Michael Truog <mjtruog at gmail dot com>
%%% All rights reserved.
%%% 
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%% 
%%%     * Redistributions of source code must retain the above copyright
%%%       notice, this list of conditions and the following disclaimer.
%%%     * Redistributions in binary form must reproduce the above copyright
%%%       notice, this list of conditions and the following disclaimer in
%%%       the documentation and/or other materials provided with the
%%%       distribution.
%%%     * All advertising materials mentioning features or use of this
%%%       software must display the following acknowledgment:
%%%         This product includes software developed by Michael Truog
%%%     * The name of the author may not be used to endorse or promote
%%%       products derived from this software without specific prior
%%%       written permission
%%% 
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
%%% CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
%%% INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
%%% DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
%%% CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
%%% SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
%%% INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
%%% WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
%%% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
%%% OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
%%% DAMAGE.
%%%
%%% @version 0.2.0 {@date} {@time}
%%%------------------------------------------------------------------------

-module(pest).
-vsn("0.2.0").

-mode(compile).

-export([checks/0,
         analyze/1,
         analyze/2,
         main/1]).

-type severity() :: 0..100. % 0 == low, 100 == high
-type problem() :: {Module :: module(),
                    Function :: function_name(),
                    Arity :: arity()} |
                   module().
-type message() :: nonempty_string().
-type checks() :: nonempty_list({severity(),
                                 nonempty_list(problem()),
                                 message()}).
-type file_path() :: string().
-type line() :: erl_anno:line().
-type options() :: list(consistency_checks |
                        {checks, checks()} |
                        {severity_min, severity()}).
-type warning() :: {severity(),
                    message(),
                    #{problem() := nonempty_list(line())}}.
-type warnings() :: nonempty_list(warning()).
-export_type([checks/0,
              file_path/0,
              options/0,
              warning/0,
              warnings/0]).

-record(state,
        {
            severity_min = 50 :: severity(),
            consistency_checks = false :: boolean(),
            input_beam_only = false :: boolean(),
            input_source_only = false :: boolean(),
            recursive = false :: boolean(),
            file_paths = [] :: list(file_path())
        }).
-record(warnings,
        {
            checks_lookup :: #{problem() := {severity(), message()}} | #{},
            instances = #{} :: #{problem() := nonempty_list(line())} | #{}
        }).

% erl_parse tree nodes represented as records
-type function_name() :: atom().
-record('remote',
        {
            anno :: erl_anno:anno(),
            module :: erl_parse:abstract_expr(),
            function_name :: erl_parse:abstract_expr()
        }).
-record('call',
        {
            anno :: erl_anno:anno(),
            function :: erl_parse:abstract_expr() | #'remote'{},
            args :: list(erl_parse:abstract_expr())
        }).

%%-------------------------------------------------------------------------
%% @doc
%% ===Security checks.===
%% @end
%%-------------------------------------------------------------------------

-spec checks() ->
    checks().

%%-------------------------------------------------------------------------
%% Clearly describe all the security problems that might be present in
%% Erlang source code with an associated severity and short message
%%
%% Severity Guide (default severity_min == 50):
%% 100..86 undefined behavior that can be exploited
%%  85..75 OS execution that can be exploited
%%  25..15 Erlang VM dependencies can be exploited
%%  14..0  Erlang VM may be killed due to memory consumption

checks() ->
    [{90,
      [{erlang, load_nif, 2}],
      "NIFs may cause undefined behavior"},
     {90,
      [{erl_ddll, load, 2},
       {erl_ddll, load_driver, 2},
       {erl_ddll, reload, 2},
       {erl_ddll, reload_driver, 2},
       {erl_ddll, try_load, 3}],
      "Port Drivers may cause undefined behavior"},
     {80,
      [{os, cmd, 1}],
      "OS shell usage may require input validation"},
     {80,
      [{erlang, open_port, 2}],
      "OS process creation may require input validation"},
     {15,
      [{crypto, block_encrypt, 3},
       {crypto, block_decrypt, 3},
       {crypto, block_encrypt, 4},
       {crypto, block_decrypt, 4},
       {crypto, compute_key, 4},
       {crypto, generate_key, 2},
       {crypto, generate_key, 3},
       {crypto, next_iv, 2},
       {crypto, next_iv, 3},
       {crypto, private_decrypt, 4},
       {crypto, private_encrypt, 4},
       {crypto, public_decrypt, 4},
       {crypto, public_encrypt, 4},
       {crypto, sign, 4},
       {crypto, stream_init, 2},
       {crypto, stream_init, 3},
       {crypto, stream_encrypt, 2},
       {crypto, stream_decrypt, 2},
       {crypto, ec_curve, 1},
       {crypto, verify, 5}] ++
       % application modules: public_key (with "-m public_key")
['OTP-PUB-KEY','PKCS-FRAME',pubkey_cert,pubkey_cert_records,pubkey_crl,
 pubkey_pbe,pubkey_pem,pubkey_ssh,public_key] ++
       % application modules: ssl (with "-m ssl")
[dtls,dtls_connection,dtls_connection_sup,dtls_handshake,dtls_record,dtls_v1,
 inet6_tls_dist,inet_tls_dist,ssl,ssl_alert,ssl_app,ssl_certificate,
 ssl_cipher,ssl_config,ssl_connection,ssl_crl,ssl_crl_cache,ssl_crl_cache_api,
 ssl_crl_hash_dir,ssl_dist_sup,ssl_handshake,ssl_listen_tracker_sup,
 ssl_manager,ssl_pkix_db,ssl_record,ssl_session,ssl_session_cache,
 ssl_session_cache_api,ssl_socket,ssl_srp_primes,ssl_sup,ssl_tls_dist_proxy,
 ssl_v2,ssl_v3,tls,tls_connection,tls_connection_sup,tls_handshake,tls_record,
 tls_v1] ++
       % application modules: ssh (with "-m ssh")
[ssh,ssh_acceptor,ssh_acceptor_sup,ssh_app,ssh_auth,ssh_bits,ssh_channel,
 ssh_channel_sup,ssh_cli,ssh_client_key_api,ssh_connection,
 ssh_connection_handler,ssh_connection_sup,ssh_daemon_channel,ssh_dbg,
 ssh_file,ssh_info,ssh_io,ssh_message,ssh_no_io,ssh_server_key_api,ssh_sftp,
 ssh_sftpd,ssh_sftpd_file,ssh_sftpd_file_api,ssh_shell,ssh_subsystem_sup,
 ssh_sup,ssh_system_sup,ssh_transport,ssh_xfer,sshc_sup,sshd_sup] ++
       % application modules: snmp (with "-m snmp")
[snmp,snmp_app,snmp_app_sup,snmp_community_mib,snmp_conf,snmp_config,
 snmp_framework_mib,snmp_generic,snmp_generic_mnesia,snmp_index,snmp_log,
 snmp_mini_mib,snmp_misc,snmp_note_store,snmp_notification_mib,snmp_pdus,
 snmp_shadow_table,snmp_standard_mib,snmp_target_mib,snmp_user_based_sm_mib,
 snmp_usm,snmp_verbosity,snmp_view_based_acm_mib,snmpa,snmpa_acm,snmpa_agent,
 snmpa_agent_sup,snmpa_app,snmpa_authentication_service,snmpa_conf,
 snmpa_discovery_handler,snmpa_discovery_handler_default,snmpa_error,
 snmpa_error_io,snmpa_error_logger,snmpa_error_report,snmpa_local_db,
 snmpa_mib,snmpa_mib_data,snmpa_mib_data_tttn,snmpa_mib_lib,snmpa_mib_storage,
 snmpa_mib_storage_dets,snmpa_mib_storage_ets,snmpa_mib_storage_mnesia,
 snmpa_misc_sup,snmpa_mpd,snmpa_net_if,snmpa_net_if_filter,
 snmpa_network_interface,snmpa_network_interface_filter,
 snmpa_notification_delivery_info_receiver,snmpa_notification_filter,
 snmpa_set,snmpa_set_lib,snmpa_set_mechanism,snmpa_supervisor,snmpa_svbl,
 snmpa_symbolic_store,snmpa_target_cache,snmpa_trap,snmpa_usm,snmpa_vacm,
 snmpc,snmpc_lib,snmpc_mib_gram,snmpc_mib_to_hrl,snmpc_misc,snmpc_tok,snmpm,
 snmpm_conf,snmpm_config,snmpm_misc_sup,snmpm_mpd,snmpm_net_if,
 snmpm_net_if_filter,snmpm_net_if_mt,snmpm_network_interface,
 snmpm_network_interface_filter,snmpm_server,snmpm_server_sup,
 snmpm_supervisor,snmpm_user,snmpm_user_default,snmpm_user_old,snmpm_usm] ++
       % encrypt_debug_info option usage
      [{compile, file, 2},
       {compile, forms, 2},
       {compile, noenv_file, 2},
       {compile, noenv_forms, 2}],
      "Keep OpenSSL updated for crypto module use"},
     {10,
      [{erlang, list_to_atom, 1},
       {erlang, binary_to_atom, 2},
       {erlang, binary_to_term, 1},
       {file, consult, 1},
       {file, eval, 1},
       {file, eval, 2},
       {file, path_consult, 2},
       {file, path_eval, 2},
       {file, path_script, 2},
       {file, path_script, 3},
       {file, script, 1},
       {file, script, 2}] ++
       % application modules: xmerl (with "-m xmerl")
[xmerl,xmerl_b64Bin,xmerl_b64Bin_scan,xmerl_eventp,xmerl_html,xmerl_lib,
 xmerl_otpsgml,xmerl_regexp,xmerl_sax_old_dom,xmerl_sax_parser,
 xmerl_sax_parser_latin1,xmerl_sax_parser_list,xmerl_sax_parser_utf16be,
 xmerl_sax_parser_utf16le,xmerl_sax_parser_utf8,xmerl_sax_simple_dom,
 xmerl_scan,xmerl_sgml,xmerl_simple,xmerl_text,xmerl_ucs,xmerl_uri,
 xmerl_validate,xmerl_xlate,xmerl_xml,xmerl_xpath,xmerl_xpath_lib,
 xmerl_xpath_parse,xmerl_xpath_pred,xmerl_xpath_scan,xmerl_xs,xmerl_xsd,
 xmerl_xsd_type],
      "Dynamic creation of atoms can exhaust atom memory"}].

%%-------------------------------------------------------------------------

%%-------------------------------------------------------------------------
%% @doc
%% ===Analyze a file.===
%% @end
%%-------------------------------------------------------------------------

-spec analyze(FilePath :: file_path()) ->
    ok |
    {warning, warnings()} |
    {error, any()}.

analyze(FilePath) ->
    analyze(FilePath, []).

%%-------------------------------------------------------------------------
%% @doc
%% ===Analyze a file with options.===
%% @end
%%-------------------------------------------------------------------------

-spec analyze(FilePath :: file_path(),
              Options :: options()) ->
    ok |
    {warning, warnings()} |
    {error, any()}.

analyze(FilePath, Options) ->
    Checks = proplists:get_value(checks, Options, checks()),
    case proplists:get_value(consistency_checks, Options, false) of
        true ->
            ok = consistency_checks(Checks);
        false ->
            ok
    end,
    SeverityMin = proplists:get_value(severity_min, Options, 50),
    case abstract_forms(FilePath) of
        {ok, _} when not (is_integer(SeverityMin) andalso
                          (SeverityMin >= 0) andalso (SeverityMin =< 100)) ->
            {error, severity_min};
        {ok, Forms} ->
            ChecksLookup = checks_lookup(Checks, SeverityMin),
            Warnings0 = #warnings{checks_lookup = ChecksLookup},
            WarningsN = erl_syntax_lib:fold(fun(TreeNode, Warnings1) ->
                case TreeNode of
                    #'call'{function = #'remote'{anno = Anno,
                                                 module = {atom, _, M},
                                                 function_name = {atom, _, F}},
                            args = Args} ->
                        Line = erl_anno:line(Anno),
                        analyze_checks(Warnings1, Line, {M, F, length(Args)});
                    _ ->
                        Warnings1
                end
            end, Warnings0, erl_syntax:form_list(Forms)),
            case warnings_format(WarningsN) of
                [] ->
                    ok;
                [_ | _] = Output ->
                    {warning, Output}
            end;
        {error, _} = Error ->
            Error
    end.

%%-------------------------------------------------------------------------
%% @doc
%% ===Escript Main Function.===
%% @end
%%-------------------------------------------------------------------------

-spec main(Arguments :: list(string())) ->
    no_return().

main(Arguments) ->
    State = main_arguments(Arguments),
    #state{severity_min = SeverityMin,
           consistency_checks = ConsistencyChecks,
           file_paths = FilePaths} = State,
    if
        ConsistencyChecks =:= true ->
            ok = consistency_checks(checks());
        ConsistencyChecks =:= false ->
            ok
    end,
    Options = [{severity_min, SeverityMin}],
    WarningsN = lists:foldl(fun(FilePath, Warnings0) ->
        case analyze(FilePath, Options) of
            ok ->
                Warnings0;
            {warning, FileWarnings} ->
                main_warnings_merge(FileWarnings, Warnings0, FilePath);
            {error, Reason} ->
                erlang:error({FilePath, Reason})
        end
    end, #{}, FilePaths),
    main_warnings_display(WarningsN),
    if
        WarningsN =:= #{} ->
            exit_code(0);
        true ->
            exit_code(1)
    end.

%%%------------------------------------------------------------------------
%%% Private functions
%%%------------------------------------------------------------------------

main_arguments(Arguments) ->
    main_arguments(Arguments, [], [], #state{}).

main_arguments(["-b" | Arguments], FilePaths, Directories,
               #state{input_source_only = false} = State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{input_beam_only = true,
                               recursive = true});
main_arguments(["-c" | Arguments], FilePaths, Directories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{consistency_checks = true});
main_arguments(["-e" | Arguments], FilePaths, Directories,
               #state{input_beam_only = false} = State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{input_source_only = true,
                               recursive = true});
main_arguments(["-h" | _], _, _, _) ->
    io:format(help(), [filename:basename(escript:script_name())]),
    exit_code(0);
main_arguments(["-m", ApplicationName | _], _, _, _) ->
    Application = erlang:list_to_atom(ApplicationName),
    case application:load(Application) of
        ok ->
            {ok, Modules} = application:get_key(Application, modules),
            io:format("~p~n", [lists:sort(Modules)]),
            exit_code(0);
        {error, Reason} ->
            erlang:error({invalid_application, Reason})
    end;
main_arguments(["-r" | Arguments], FilePaths, Directories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{recursive = true});
main_arguments(["-s", SeverityMin | Arguments],
               FilePaths, Directories, State) ->
    SeverityMinValue = try erlang:list_to_integer(SeverityMin)
    catch
        error:badarg ->
            erlang:error(invalid_severity_min)
    end,
    if
        SeverityMinValue < 0; SeverityMinValue > 100 ->
            erlang:error(invalid_severity_min);
        true ->
            ok
    end,
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{severity_min = SeverityMinValue});
main_arguments(["-U", Component | _], _, _, _) ->
    case Component of
        "crypto" ->
            case update_crypto_data() of
                ok ->
                    ok;
                {error, Reason} ->
                    erlang:error({update_failed, Reason})
            end;
        _ ->
            erlang:error({invalid_component, Component})
    end,
    exit_code(0);
main_arguments(["-v" | Arguments], FilePaths, Directories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{severity_min = 0});
main_arguments(["-V" | Arguments], _, _, _) ->
    Component = case Arguments of
        [] ->
            "pest";
        ["-" ++ _ | _] ->
            "pest";
        [ComponentName | _] ->
            ComponentName
    end,
    case Component of
        "pest" ->
            version_info_pest();
        "crypto" ->
            version_info_crypto();
        _ ->
            erlang:error({invalid_component, Component})
    end,
    exit_code(0);
main_arguments(["-" ++ InvalidParameter | _], _, _, _) ->
    erlang:error({invalid_parameter, InvalidParameter});
main_arguments([Path | Arguments], FilePaths, Directories, State) ->
    case filelib:is_dir(Path) of
        true ->
            main_arguments(Arguments, FilePaths, [Path | Directories], State);
        false ->
            main_arguments(Arguments, [Path | FilePaths], Directories, State)
    end;
main_arguments([], FilePaths, Directories,
               #state{input_beam_only = BeamOnly,
                      input_source_only = SourceOnly,
                      recursive = Recursive} = State) ->
    FilePathsFoundN = if
        Recursive =:= false, Directories /= [] ->
            erlang:error(not_recursive);
        Recursive =:= true ->
            RegExp = if
                BeamOnly =:= true ->
                    ".*\\.beam$";
                SourceOnly =:= true ->
                    ".*\\.erl$";
                true ->
                    ".*"
            end,
            lists:foldl(fun(Directory, FilePathsFound0) ->
                FilePathsFound0 ++
                lists:reverse(filelib:fold_files(Directory, RegExp, true,
                                                 fun(FilePathFound,
                                                     FilePathsFound1) ->
                    [FilePathFound | FilePathsFound1]
                end, FilePathsFound0))
            end, [], lists:reverse(Directories));
        true ->
            []
    end,
    State#state{file_paths = lists:reverse(FilePaths) ++ FilePathsFoundN}.

main_warnings_merge([], Warnings, _) ->
    Warnings;
main_warnings_merge([{Severity, Message, Problems} | FileWarnings],
                    Warnings, FilePath) ->
    Key = {Severity, Message},
    NewWarnings = maps:put(Key,
                           maps:put(FilePath, Problems,
                                    maps:get(Key, Warnings, #{})),
                           Warnings),
    main_warnings_merge(FileWarnings, NewWarnings, FilePath).

main_warnings_display(Warnings) ->
    OutputN = lists:reverse(maps:fold(fun(Key, FileProblems, Output0) ->
        FileOutput1 = maps:fold(fun(FilePath, Problems, FileOutput0) ->
            ProblemsOutput1 = maps:fold(fun(Problem, Lines, ProblemsOutput0) ->
                ProblemName = case Problem of
                    {M, F, A} ->
                        lists:flatten(io_lib:format("~w:~w/~w", [M, F, A]));
                    M ->
                        lists:flatten(io_lib:format("~w:_/_", [M]))
                end,
                lists:ukeymerge(1, ProblemsOutput0, [{ProblemName, Lines}])
            end, [], Problems),
            lists:ukeymerge(1, FileOutput0, [{FilePath, ProblemsOutput1}])
        end, [], FileProblems),
        lists:ukeymerge(1, Output0, [{Key, FileOutput1}])
    end, [], Warnings)),
    lists:foreach(fun({{Severity, Message}, FileOutputN}) ->
        io:format("~3.. w: ~s~n", [Severity, Message]),
        lists:foreach(fun({FilePath, ProblemsOutputN}) ->
            FileName = filename:basename(FilePath),
            lists:foreach(fun({ProblemName, Lines}) ->
                FileLines = case Lines of
                    [Line] ->
                        Line;
                    [_ | _] ->
                        Lines
                end,
                io:format("~-5s~s:~w (~s)~n",
                          ["", FileName, FileLines, ProblemName])
            end, ProblemsOutputN)
        end, FileOutputN)
    end, OutputN).

checks_lookup(Checks, SeverityMin) ->
    checks_lookup(Checks, #{}, SeverityMin).

checks_lookup([], Lookup, _) ->
    Lookup;
checks_lookup([{Severity, Problems, Message} | Checks], Lookup0, SeverityMin)
    when Severity >= SeverityMin ->
    LookupN = lists:foldl(fun(Problem, Lookup1) ->
        Lookup1#{Problem => {Severity, Message}}
    end, Lookup0, Problems),
    checks_lookup(Checks, LookupN, SeverityMin);
checks_lookup([_ | Checks], Lookup, SeverityMin) ->
    checks_lookup(Checks, Lookup, SeverityMin).

analyze_checks(#warnings{checks_lookup = ChecksLookup,
                         instances = Instances} = Warnings, Line, Call) ->
    {Module, _, _} = Call,
    ProblemFunction = maps:is_key(Call, ChecksLookup),
    ProblemModule = maps:is_key(Module, ChecksLookup),
    Store = fun(Problem) ->
        Lines = maps:get(Problem, Instances, []),
        NewInstances = maps:put(Problem, [Line | Lines], Instances),
        Warnings#warnings{instances = NewInstances}
    end,
    if
        ProblemFunction =:= true ->
            Store(Call);
        ProblemModule =:= true ->
            Store(Module);
        true ->
            Warnings
    end.

-spec warnings_format(Warnings :: #warnings{}) ->
    list(warning()).

warnings_format(#warnings{checks_lookup = ChecksLookup,
                          instances = Instances}) ->
    OutputN = maps:fold(fun(Problem, Lines, Output0) ->
        Key = maps:get(Problem, ChecksLookup),
        maps:put(Key,
                 maps:put(Problem,
                          lists:reverse(Lines),
                          maps:get(Key, Output0, #{})),
                 Output0)
    end, #{}, Instances),
    lists:reverse(maps:fold(fun({Severity, Message}, Problems, L) ->
        lists:umerge(L, [{Severity, Message, Problems}])
    end, [], OutputN)).

-spec consistency_checks(Checks :: any()) ->
    ok.

consistency_checks([_ | _] = Checks) ->
    % internal consistency checks to make sure all the checks are valid
    Set0 = sets:new(),
    _ = lists:foldl(fun({Rank, Problems, Message}, Set1) ->
        if
            is_integer(Rank), Rank >= 0, Rank =< 100 ->
                ok;
            true ->
                erlang:error({invalid_severity, Rank})
        end,
        Set2 = if
            is_list(Problems) ->
                lists:foldl(fun(Problem, Set3) ->
                    ProblemOk = case Problem of
                        {M, F, A} ->
                            function_exists(M, F, A);
                        M ->
                            function_exists(M, module_info, 0)
                    end,
                    if
                        ProblemOk =:= true ->
                            ok;
                        ProblemOk =:= false ->
                            erlang:error({invalid_problem, Problem})
                    end,
                    case sets:is_element(Problem, Set3) of
                        true ->
                            erlang:error({duplicate_problem, Problem});
                        false ->
                            sets:add_element(Problem, Set3)
                    end
                end, Set1, Problems);
            true ->
                erlang:error({invalid_problems, Problems})
        end,
        if
            is_list(Message), is_integer(hd(Message)) ->
                ok;
            true ->
                erlang:error({invalid_message, Message})
        end,
        Set2
    end, Set0, Checks),
    ok;
consistency_checks(Checks) ->
    erlang:error({invalid_checks, Checks}).

-spec abstract_forms(FilePath :: file_path()) ->
    {ok, Forms :: list(erl_parse:abstract_form())} |
    {error, any()}.

abstract_forms(FilePath) ->
    case filename:extension(FilePath) of
        ".beam" ->
            case beam_lib:chunks(FilePath, [abstract_code]) of
                {ok, {_, [{abstract_code, {_, Forms}}]}} ->
                    {ok, Forms};
                {ok, {_, [{abstract_code, no_abstract_code}]}} ->
                    {error, no_abstract_code};
                {error, beam_lib, ChunkReason} ->
                    {error, erlang:delete_element(2, ChunkReason)}
            end;
        _ ->
            % can parse escript files
            case epp:parse_file(FilePath, []) of
                {ok, _} = Success ->
                    Success;
                {error, _} = Error ->
                    Error
            end
    end.

function_exists(M, F, A) ->
    Loaded = code:is_loaded(M) =/= false,
    if
        Loaded =:= true ->
            ok;
        Loaded =:= false ->
            code:ensure_loaded(M)
    end,
    Exists = erlang:function_exported(M, F, A),
    if
        Loaded =:= true ->
            ok;
        Loaded =:= false ->
            code:purge(M)
    end,
    Exists.

exit_code(ExitCode) when is_integer(ExitCode) ->
    erlang:halt(ExitCode, [{flush, true}]).

pest_data_file() ->
    filename:join([filename:dirname(escript:script_name()), "pest.dat"]).

pest_data_find(Key) ->
    FilePath = pest_data_file(),
    case file:consult(FilePath) of
        {ok, [Data]} ->
            case lists:keyfind(Key, 1, Data) of
                {Key, Value} ->
                    {ok, Value};
                false ->
                    error
            end;
        {error, enoent} ->
            error
    end.

pest_data_store(Key, Value) ->
    FilePath = pest_data_file(),
    DataNew = case file:consult(FilePath) of
        {ok, [DataOld]} ->
            lists:keystore(Key, 1, DataOld, {Key, Value});
        {error, enoent} ->
            [{Key, Value}]
    end,
    file:write_file(FilePath, io_lib:format("~p.", [DataNew]), [raw]).

update_crypto_data() ->
    % webscraper for OpenSSL Vulnerabilities
    URL = "https://www.openssl.org/news/vulnerabilities.html",
    Timeout = 20000, % milliseconds
    error_logger:tty(false),
    ok = ssl:start(),
    ok = inets:start(),
    Result = case httpc:request(get, {URL, []},
                                [{autoredirect, false},
                                 {timeout, Timeout}],
                                [{body_format, string}]) of
        {ok, {{_, 200, "OK"}, _Headers, Body}} ->
            {ok, Vulnerabilities} = update_crypto_openssl_data_parse(Body, []),
            pest_data_store(crypto, [{openssl, Vulnerabilities}]);
        {ok, RequestFailed} ->
            {error, RequestFailed};
        {error, _} = Error ->
            Error
    end,
    ok = inets:stop(),
    ok = ssl:stop(),
    error_logger:tty(true),
    Result.

update_crypto_openssl_data_parse("CVE-" ++ _ = L0, D) ->
    {CVE, LN} = lists:split(13, L0),
    update_crypto_openssl_data_parse_cve(LN, moderate, CVE, D);
update_crypto_openssl_data_parse([], D) ->
    {ok, D};
update_crypto_openssl_data_parse([_ | L], D) ->
    update_crypto_openssl_data_parse(L, D).

update_crypto_openssl_data_parse_cve("[Critical severity]" ++ L, _, CVE, D) ->
    update_crypto_openssl_data_parse_cve(L, critical, CVE, D);
update_crypto_openssl_data_parse_cve("[High severity]" ++ L, _, CVE, D) ->
    update_crypto_openssl_data_parse_cve(L, high, CVE, D);
update_crypto_openssl_data_parse_cve("[Moderate severity]" ++ L, _, CVE, D) ->
    update_crypto_openssl_data_parse_cve(L, moderate, CVE, D);
update_crypto_openssl_data_parse_cve("[Low severity]" ++ L, _, CVE, D) ->
    update_crypto_openssl_data_parse_cve(L, low, CVE, D);
update_crypto_openssl_data_parse_cve("Fixed in OpenSSL " ++ L0,
                                     Level, CVE, D) ->
    Version = fun(V) ->
        (V >= $0 andalso V =< $9) orelse (V == $.) orelse
        (V >= $a andalso V =< $z)
    end,
    {_, L1} = lists:splitwith(fun(C0) -> not Version(C0) end, L0),
    {Fix, LN} = lists:splitwith(fun(C1) -> Version(C1) end, L1),
    update_crypto_openssl_data_parse_cve_fix(LN, Fix, Level, CVE, D);
update_crypto_openssl_data_parse_cve(">CVE-" ++ _ = L, _, _, D) ->
    update_crypto_openssl_data_parse(L, D);
update_crypto_openssl_data_parse_cve([], _, _, D) ->
    {ok, D};
update_crypto_openssl_data_parse_cve([_ | L], Level, CVE, D) ->
    update_crypto_openssl_data_parse_cve(L, Level, CVE, D).

update_crypto_openssl_data_parse_cve_fix("(Affected " ++ L0,
                                         Fix, Level, CVE, D) ->
    {Affected, LN} = lists:splitwith(fun(C0) -> C0 /= $) end, L0),
    AffectedList = string:tokens(Affected, ", "),
    Entry = {CVE, Level, Fix, AffectedList},
    update_crypto_openssl_data_parse_cve(LN, Level, CVE, [Entry | D]);
update_crypto_openssl_data_parse_cve_fix(">CVE-" ++ _ = L, _, _, _, D) ->
    update_crypto_openssl_data_parse(L, D);
update_crypto_openssl_data_parse_cve_fix([], _, _, _, D) ->
    {ok, D};
update_crypto_openssl_data_parse_cve_fix([_ | L], Fix, Level, CVE, D) ->
    update_crypto_openssl_data_parse_cve_fix(L, Fix, Level, CVE, D).

version_info_openssl(VersionRuntime) ->
    [<<"OpenSSL">>, VersionMajor, VersionMinor, VersionPatch |
     _] = binary:split(VersionRuntime, [<<" ">>, <<".">>], [global]),
    Version = erlang:binary_to_list(<<VersionMajor/binary, $.,
                                      VersionMinor/binary, $.,
                                      VersionPatch/binary>>),
    [PatchNumber | Patch] = erlang:binary_to_list(VersionPatch),
    Fork = {erlang:binary_to_list(VersionMajor),
            erlang:binary_to_list(VersionMinor),
            [PatchNumber]},
    {ok, [{openssl, Vulnerabilities}]} = pest_data_find(crypto),
    SecurityProblemsList = [
    % based on https://en.wikipedia.org/wiki/OpenSSL#Major_version_releases
    if Fork =< {"1", "0", "0"} ->
        "OLD OpenSSL!"; true -> "" end,
    % based on https://en.wikipedia.org/wiki/OpenSSL#Notable_vulnerabilities
    % without https://www.openssl.org/news/vulnerabilities.html
    if Fork == {"0", "9", "7"}, Patch =< "a" ->
        "CAN-2003-0147"; true -> "" end, % Timing attacks on RSA Keys
    if Fork == {"0", "9", "7"}, Patch =< "b" ->
        "CAN-2003-054[345]"; true -> "" end, % Denial of Service ASN.1 parsing
    if Fork == {"0", "9", "8"}, Patch < "g-9" ->
        "CVE-2008-0166"; true -> "" end % Predictable private keys (Debian)
    ] ++
    lists:map(fun({CVE, _Level, _Fix, Affected}) ->
        case lists:member(Version, Affected) of
            true ->
                CVE;
            false ->
                ""
        end
    end, Vulnerabilities),
    LibrarySource = if
        Patch == "" ->
            "package manager fork?";
        true ->
            "openssl mainline!"
    end,
    SecurityProblems = lists:filter(fun(S) ->
        S /= ""
    end, SecurityProblemsList),
    {length(SecurityProblems), length(SecurityProblemsList),
     LibrarySource, SecurityProblems}.

version_info_crypto() ->
    {ok, _} = application:ensure_all_started(crypto),
    lists:foreach(fun(CryptoComponent) ->
        case CryptoComponent of
            {<<"OpenSSL">>, VersionHeader, VersionRuntime} ->
                {SecurityProblemsFound,
                 SecurityProblemsKnown,
                 LibrarySource,
                 SecurityProblems} = version_info_openssl(VersionRuntime),
                io:format("OpenSSL version information:~n"
                          "    crypto compile-time "
                              "openssl/opensslv.h version ~w~n"
                          "    crypto run-time version ~s~n"
                          "    ~w/~w problems found (~s)~n"
                          "    ~p~n",
                          [VersionHeader, VersionRuntime,
                           SecurityProblemsFound,
                           SecurityProblemsKnown,
                           LibrarySource,
                           SecurityProblems]);
            Other ->
                io:format("~p (crypto dependency unknown)~n", [Other])
        end
    end, crypto:info_lib()).

version_info_pest() ->
    Version = case ?MODULE:module_info(attributes) of
        [] ->
            "UNKNOWN!";
        Attributes ->
            VersionListN = lists:foldr(fun(Attribute, VersionList0) ->
                case Attribute of
                    {vsn, VSN} ->
                        VSN ++ VersionList0;
                    _ ->
                        VersionList0
                end
            end, [], Attributes),
            io_lib:format("~p", [VersionListN])
    end,
    {ok, Data} = file:read_file(?FILE),
    FileHash = erlang:phash2(Data),
    io:format("~s version ~s (~w)~n",
              [filename:basename(escript:script_name()),
               Version, FileHash]).

help() ->
"Usage ~s [OPTION] [FILES] [DIRECTORIES]

  -b              Only process beam files recursively
  -c              Perform internal consistency checks
  -e              Only process source files recursively
  -h              List available command line flags
  -m APPLICATION  Display a list of modules in an Erlang/OTP application
  -r              Recursively search directories
  -s SEVERITY     Set the minimum severity to use when reporting problems
                  (default is 50)
  -U COMPONENT    Update local data related to a component
                  (valid components are: crypto)
  -v              Verbose output (set the minimum severity to 0)
  -V [COMPONENT]  Print version information
                  (valid components are: pest, crypto)
".

