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
%%% @version 0.1.0 {@date} {@time}
%%%------------------------------------------------------------------------

-module(pest).
-vsn("0.1.0").

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
       {erl_ddll, reload_driver, 2}],
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
       {crypto, verify, 5},
       public_key,
       ssl,
       ssh,
       ssh_channel,
       ssh_connection,
       ssh_client_key_api,
       ssh_server_key_api,
       ssh_sftp,
       ssh_sftpd],
      "Keep OpenSSL updated for crypto module use"},
     {10,
      [{erlang, list_to_atom, 1},
       {erlang, binary_to_atom, 2},
       {erlang, binary_to_term, 1}],
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
                                                 module = Module,
                                                 function_name = Function},
                            args = Args} ->
                        Call = {erl_parse:normalise(Module),
                                erl_parse:normalise(Function),
                                length(Args)},
                        Line = erl_anno:line(Anno),
                        analyze_checks(Warnings1, Line, Call);
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
                   State#state{input_beam_only = true});
main_arguments(["-c" | Arguments], FilePaths, Directories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{consistency_checks = true});
main_arguments(["-e" | Arguments], FilePaths, Directories,
               #state{input_beam_only = false} = State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{input_source_only = true});
main_arguments(["-h" | _], _, _, _) ->
    io:format(help(), [filename:basename(escript:script_name())]),
    exit_code(0);
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
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{severity_min = SeverityMinValue});
main_arguments(["-v" | Arguments], FilePaths, Directories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   State#state{severity_min = 0});
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
        Recursive =:= false,
        (Directories /= []) orelse
        (BeamOnly =:= true) orelse
        (SourceOnly =:= true) ->
            erlang:error(not_recursive);
        Recursive =:= true ->
            RegExp = if
                BeamOnly =:= true ->
                    ".*\.beam$";
                SourceOnly =:= true ->
                    ".*\.erl$";
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
                case Lines of
                    [Line] ->
                        io:format("~-5s~s:~w (~s)~n",
                                  ["", FileName, Line, ProblemName]);
                    [_ | _] ->
                        io:format("~-5s~s:~p (~s)~n",
                                  ["", FileName, Lines, ProblemName])
                end
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
        lists:ukeymerge(1, L, [{Severity, Message, Problems}])
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

help() ->
"Usage ~s [OPTION] [FILES] [DIRECTORIES]

  -b              Only process beam files recursively
  -c              Perform internal consistency checks
  -e              Only process source files recursively
  -h              List available command line flags
  -r              Recursively search directories
  -s SEVERITY     Set the minimum severity to use when reporting problems
                  (default is 50)
  -v              Verbose output (set the minimum severity to 0)
".

