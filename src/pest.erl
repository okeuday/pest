%#!/usr/bin/env escript
%%!
%-*-Mode:erlang;coding:utf-8;tab-width:4;c-basic-offset:4;indent-tabs-mode:()-*-
% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et nomod:
%%%------------------------------------------------------------------------
%%% @doc
%%% ==Primitive Erlang Security Tool (PEST)==
%%% @end
%%%
%%% MIT License
%%%
%%% Copyright (c) 2016-2017 Michael Truog <mjtruog at protonmail dot com>
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining a
%%% copy of this software and associated documentation files (the "Software"),
%%% to deal in the Software without restriction, including without limitation
%%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%%% and/or sell copies of the Software, and to permit persons to whom the
%%% Software is furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be included in
%%% all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%%% DEALINGS IN THE SOFTWARE.
%%%
%%% @version 0.6.0 {@date} {@time}
%%%------------------------------------------------------------------------

-ifndef(ESCRIPT).
-module(pest).
-endif.
-vsn("0.6.0").

-export([checks/0,
         checks_expand/2,
         checks_expand/3,
         checks_merge/2,
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
                                 message(),
                                 nonempty_list(problem())}).
-type file_path() :: string().
-type line() :: erl_anno:line().
-type options() :: list(consistency_checks |
                        {checks, checks()} |
                        {severity_min, severity()} |
                        {location, line | function} |
                        {functions, remote | any}).
-type location() :: line() |
                    {Function :: function_name(),
                     Arity :: arity()}.
-type warning() :: {severity(),
                    message(),
                    #{problem() := nonempty_list(location())}}.
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
            checks_info = false :: boolean(),
            dependency_store = undefined :: undefined | string(),
            dependency_load = [] :: list({severity(),
                                          message(),
                                          nonempty_list(problem())}),
            dependency_file_paths = [] :: list(file_path()),
            file_paths = [] :: list(file_path())
        }).
-record(warnings,
        {
            checks_lookup :: #{problem() := nonempty_list({severity(),
                                                           message()})},
            function_calls = [] :: list({{Module :: module(),
                                          Function :: function_name(),
                                          Arity :: arity()},
                                         line()}),
            instances = #{} :: #{problem() := nonempty_list(location())}
        }).

% erl_parse tree nodes represented as records
-type function_name() :: atom().
-record('clause',
        {
            anno :: erl_anno:anno(),
            pattern :: list(any()),
            guard :: list(list(any())),
            body :: list(erl_parse:abstract_expr())
        }).
-record('function',
        {
            anno :: erl_anno:anno(),
            function_name :: atom(),
            arity :: arity(),
            clauses :: list(#'clause'{})
        }).
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
%%  14..6  Erlang VM may be killed due to memory consumption
%%   5..0  Erlang VM may have a security weakness (potential exploit)

checks() ->
    [{90,
      "NIFs may cause undefined behavior",
      [{erlang, load_nif, 2}]},
     {90,
      "Port Drivers may cause undefined behavior",
      [{erl_ddll, load, 2},
       {erl_ddll, load_driver, 2},
       {erl_ddll, reload, 2},
       {erl_ddll, reload_driver, 2},
       {erl_ddll, try_load, 3}]},
     {80,
      "OS process creation may require input validation",
      [{erlang, open_port, 2}]},
     {80,
      "OS shell usage may require input validation",
      [{os, cmd, 1}]},
     {15,
      "Keep OpenSSL updated for crypto module use (run with \"-V crypto\")",
      application_modules(public_key) ++
      application_modules(snmp) ++
      application_modules(ssh) ++
      application_modules(ssl) ++
      [% encrypt_debug_info option usage
       {compile, file, 2},
       {compile, forms, 2},
       {compile, noenv_file, 2},
       {compile, noenv_forms, 2},
       % crypto encryption/decryption API
       {crypto, block_encrypt, 3},
       {crypto, block_decrypt, 3},
       {crypto, block_encrypt, 4},
       {crypto, block_decrypt, 4},
       {crypto, compute_key, 4},
       {crypto, ec_curve, 1},
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
       {crypto, verify, 5}]},
     {10,
      "Dynamic creation of atoms can exhaust atom memory",
      application_modules(xmerl) ++
      [{erlang, binary_to_atom, 2},
       {erlang, binary_to_term, 1}, % use 'safe' argument
       {erlang, list_to_atom, 1},
       {file, consult, 1},
       {file, eval, 1},
       {file, eval, 2},
       {file, path_consult, 2},
       {file, path_eval, 2},
       {file, path_script, 2},
       {file, path_script, 3},
       {file, script, 1},
       {file, script, 2}]}].

%%-------------------------------------------------------------------------

%%-------------------------------------------------------------------------
%% @doc
%% ===Expand a limited number of existing checks based on the provided dependencies.===
%% @end
%%-------------------------------------------------------------------------

-spec checks_expand(FilePath :: file_path(),
                    SeverityMin :: severity(),
                    Checks :: checks()) ->
    NewChecks :: checks().

checks_expand(FilePaths, 0, Checks) ->
    checks_expand(FilePaths, Checks);
checks_expand(FilePaths, SeverityMin, Checks)
    when is_integer(SeverityMin),
         SeverityMin > 0, SeverityMin =< 100 ->
    NewChecks = lists:filter(fun({Severity, _, _}) ->
        Severity >= SeverityMin
    end, Checks),
    checks_expand(FilePaths, NewChecks).

%%-------------------------------------------------------------------------
%% @doc
%% ===Expand the existing checks based on the provided dependencies.===
%% @end
%%-------------------------------------------------------------------------

-spec checks_expand(FilePath :: file_path(),
                    Checks :: checks()) ->
    NewChecks :: checks().

checks_expand(FilePaths, Checks) ->
    checks_expand_loop(FilePaths, Checks).

%%-------------------------------------------------------------------------
%% @doc
%% ===Merge existing checks.===
%% @end
%%-------------------------------------------------------------------------

-spec checks_merge(ChecksA :: checks(),
                   ChecksB :: checks()) ->
    Checks :: checks().

checks_merge(ChecksA, ChecksB) ->
    lists:foldl(fun({SeverityA, MessageA, ProblemsA}, ChecksNew0) ->
        case lists:keytake(MessageA, 2, ChecksNew0) of
            {value, {SeverityA, MessageA, ProblemsB}, ChecksNew1} ->
                lists:umerge(ChecksNew1,
                             [{SeverityA, MessageA,
                               lists:umerge(lists:usort(ProblemsA),
                                            lists:usort(ProblemsB))}]);
            false ->
                lists:umerge(ChecksNew0,
                             [{SeverityA, MessageA, lists:usort(ProblemsA)}])
        end
    end, lists:usort(ChecksB), lists:usort(ChecksA)).


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
    Location = proplists:get_value(location, Options, line),
    Functions = proplists:get_value(functions, Options, remote),
    case abstract_forms(FilePath) of
        {ok, _} when not (is_integer(SeverityMin) andalso
                          (SeverityMin >= 0) andalso (SeverityMin =< 100)) ->
            {error, severity_min};
        {ok, _} when not ((Location =:= line) orelse
                          (Location =:= function)) ->
            {error, location};
        {ok, _} when not ((Functions =:= remote) orelse
                          (Functions =:= any)) ->
            {error, functions};
        {ok, Forms} ->
            FileName = filename:rootname(filename:basename(FilePath)),
            Module = erlang:list_to_existing_atom(FileName),
            ChecksLookup = checks_lookup(Checks, SeverityMin),
            Warnings0 = #warnings{checks_lookup = ChecksLookup},
            WarningsN = erl_syntax_lib:fold(fun(TreeNode, Warnings1) ->
                case TreeNode of
                    #'function'{function_name = F,
                                arity = A} ->
                        analyze_checks(Warnings1, Location, {F, A});
                    #'call'{anno = Anno,
                            function = #'remote'{module = {atom, _, M},
                                                 function_name = {atom, _, F}},
                            args = Args} ->
                        % remote function call
                        analyze_store({M, F, length(Args)},
                                      erl_anno:line(Anno), Warnings1);
                    #'call'{anno = Anno,
                            function = {atom, _, F},
                            args = Args}
                        when (Functions =:= any) ->
                        % local function call
                        % (necessary to expand checks)
                        analyze_store({Module, F, length(Args)},
                                      erl_anno:line(Anno), Warnings1);
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
           checks_info = ChecksInfo,
           dependency_store = DependencyStore,
           dependency_load = DependencyLoad,
           dependency_file_paths = DependencyFilePaths,
           file_paths = FilePaths} = State,
    ChecksCore = checks(),
    if
        ConsistencyChecks =:= true ->
            ok = consistency_checks(ChecksCore);
        ConsistencyChecks =:= false ->
            ok
    end,
    Checks = checks_merge(DependencyLoad, ChecksCore),
    ChecksExpanded = checks_expand(DependencyFilePaths, SeverityMin, Checks),
    if
        DependencyStore =:= undefined ->
            ok;
        is_list(DependencyStore) ->
            ok = dependency_store(DependencyStore, ChecksExpanded),
            exit_code(0)
    end,
    if
        ChecksInfo =:= true ->
            io:format("~p~n", [ChecksExpanded]),
            exit_code(0);
        ChecksInfo =:= false ->
            ok
    end,
    Options = [{checks, ChecksExpanded},
               {severity_min, SeverityMin}],
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
    main_arguments(Arguments, [], [], [], [], #state{}).

main_arguments(["-b" | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories,
               #state{input_source_only = false} = State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{input_beam_only = true,
                               recursive = true});
main_arguments(["-c" | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{consistency_checks = true});
main_arguments(["-d", Dependency | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    case filelib:is_dir(Dependency) of
        true ->
            main_arguments(Arguments, FilePaths, Directories,
                           DependencyFilePaths,
                           [Dependency | DependencyDirectories], State);
        false ->
            main_arguments(Arguments, FilePaths, Directories,
                           [Dependency | DependencyFilePaths],
                           DependencyDirectories, State)
    end;
main_arguments(["-D", DependencyIdentifier | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories,
               #state{dependency_load = OldDependencyLoad} = State) ->
    {ok, PestData} = pest_data_find(pest),
    {dependency, Dependencies} = lists:keyfind(dependency, 1, PestData),
    {DependencyIdentifier,
     Checks} = lists:keyfind(DependencyIdentifier, 1, Dependencies),
    NewDependencyLoad = checks_merge(OldDependencyLoad, Checks),
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{dependency_load = NewDependencyLoad});
main_arguments(["-e" | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories,
               #state{input_beam_only = false} = State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{input_source_only = true,
                               recursive = true});
main_arguments(["-h" | _], _, _, _, _, _) ->
    io:format(help(), [filename:basename(?FILE)]),
    exit_code(0);
main_arguments(["-i" | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{checks_info = true});
main_arguments(["-m", ApplicationName | _], _, _, _, _, _) ->
    Application = erlang:list_to_atom(ApplicationName),
    io:format("~p~n", [application_modules(Application)]),
    exit_code(0);
main_arguments(["-p", Directory | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    true = code:add_pathz(Directory),
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories, State);
main_arguments(["-r" | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{recursive = true});
main_arguments(["-s", SeverityMin | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
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
                   DependencyFilePaths, DependencyDirectories,
                   State#state{severity_min = SeverityMinValue});
main_arguments(["-U", Component | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    case Component of
        "crypto" ->
            ok = update_crypto_data(),
            exit_code(0);
        "pest/" ++ Path ->
            case Path of
                "dependency/" ++ Identifier ->
                    main_arguments(Arguments, FilePaths, Directories,
                                   DependencyFilePaths, DependencyDirectories,
                                   State#state{dependency_store = Identifier});
                _ ->
                    erlang:error({invalid_pest_component, Component})
            end;
        _ ->
            erlang:error({invalid_component, Component})
    end;
main_arguments(["-v" | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    main_arguments(Arguments, FilePaths, Directories,
                   DependencyFilePaths, DependencyDirectories,
                   State#state{severity_min = 0});
main_arguments(["-V" | Arguments], _, _, _, _, _) ->
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
main_arguments(["-" ++ InvalidParameter | _], _, _, _, _, _) ->
    erlang:error({invalid_parameter, InvalidParameter});
main_arguments([Path | Arguments], FilePaths, Directories,
               DependencyFilePaths, DependencyDirectories, State) ->
    case filelib:is_dir(Path) of
        true ->
            main_arguments(Arguments, FilePaths, [Path | Directories],
                           DependencyFilePaths, DependencyDirectories, State);
        false ->
            main_arguments(Arguments, [Path | FilePaths], Directories,
                           DependencyFilePaths, DependencyDirectories, State)
    end;
main_arguments([], FilePaths0, Directories,
               DependencyFilePaths0, DependencyDirectories,
               #state{input_beam_only = BeamOnly,
                      input_source_only = SourceOnly,
                      recursive = Recursive,
                      checks_info = ChecksInfo,
                      dependency_store = DependencyStore} = State) ->
    {FilePathsFound,
     DependencyFilePathsFound}= if
        Recursive =:= false,
        (Directories /= []) orelse (DependencyDirectories /= []) ->
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
            RecursiveSearch = fun(DirectoryList) ->
                lists:foldl(fun(Directory, FilePathList0) ->
                    FilePathList0 ++
                    lists:reverse(filelib:fold_files(Directory, RegExp, true,
                                                     fun(FilePathElement,
                                                         FilePathListN) ->
                        [FilePathElement | FilePathListN]
                    end, FilePathList0))
                end, [], DirectoryList)
            end,
            {RecursiveSearch(lists:reverse(Directories)),
             RecursiveSearch(lists:reverse(DependencyDirectories))};
        true ->
            {[], []}
    end,
    FilePathsN = lists:reverse(FilePaths0) ++
                 FilePathsFound,
    DependencyFilePathsN = lists:reverse(DependencyFilePaths0) ++
                           DependencyFilePathsFound,
    if
        FilePathsN == [],
        ChecksInfo =:= false,
        DependencyStore =:= undefined ->
            io:format(help(), [filename:basename(?FILE)]),
            exit_code(1);
        true ->
            State#state{dependency_file_paths = DependencyFilePathsN,
                        file_paths = FilePathsN}
    end.

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
            ProblemsOutput1 = maps:fold(fun(Problem, Locations,
                                            ProblemsOutput0) ->
                ProblemName = case Problem of
                    {M, F, A} ->
                        lists:flatten(io_lib:format("~w:~w/~w", [M, F, A]));
                    M ->
                        lists:flatten(io_lib:format("~w:_/_", [M]))
                end,
                lists:ukeymerge(1, ProblemsOutput0, [{ProblemName, Locations}])
            end, [], Problems),
            lists:ukeymerge(1, FileOutput0, [{FilePath, ProblemsOutput1}])
        end, [], FileProblems),
        lists:ukeymerge(1, Output0, [{Key, FileOutput1}])
    end, [], Warnings)),
    lists:foreach(fun({{Severity, Message}, FileOutputN}) ->
        io:format("~3.. w: ~s~n", [Severity, Message]),
        lists:foreach(fun({FilePath, ProblemsOutputN}) ->
            FileName = filename:basename(FilePath),
            lists:foreach(fun({ProblemName, Locations}) ->
                FileLocations = case Locations of
                    [Location] ->
                        Location;
                    [_ | _] ->
                        Locations
                end,
                io:format("~-5s~s:~w (~s)~n",
                          ["", FileName, FileLocations, ProblemName])
            end, ProblemsOutputN)
        end, FileOutputN)
    end, OutputN).

checks_lookup(Checks, SeverityMin) ->
    checks_lookup(lists:reverse(Checks), #{}, SeverityMin).

checks_lookup([], Lookup, _) ->
    Lookup;
checks_lookup([{Severity, Message, Problems} | Checks], Lookup0, SeverityMin)
    when Severity >= SeverityMin ->
    LookupN = lists:foldl(fun(Problem, Lookup1) ->
        maps:put(Problem,
                 [{Severity, Message} | maps:get(Problem, Lookup1, [])],
                 Lookup1)
    end, Lookup0, Problems),
    checks_lookup(Checks, LookupN, SeverityMin);
checks_lookup([{_, _, _} | Checks], Lookup, SeverityMin) ->
    checks_lookup(Checks, Lookup, SeverityMin);
checks_lookup([InvalidCheck | _], _, _) ->
    erlang:error({invalid_check, InvalidCheck}).

checks_expand_loop(FilePaths, ChecksOld) ->
    ChecksLookup0 = checks_lookup(ChecksOld, 0),
    Options = [{checks, ChecksOld},
               {severity_min, 0},
               {location, function},
               {functions, any}],
    ChecksLookupN = lists:foldl(fun(FilePath, ChecksLookup1) ->
        FileName = filename:rootname(filename:basename(FilePath)),
        Module = erlang:list_to_atom(FileName),
        case maps:is_key(Module, ChecksLookup1) of
            true ->
                ChecksLookup1;
            false ->
                case analyze(FilePath, Options) of
                    ok ->
                        ChecksLookup1;
                    {warning, FileWarnings} ->
                        lists:foldl(fun({Severity, Message, Problems},
                                        ChecksLookup2) ->
                            Key = {Severity, Message},
                            maps:fold(fun(_, Locations, ChecksLookup3) ->
                                lists:foldl(fun({F, A}, ChecksLookup4) ->
                                    Call = {Module, F, A},
                                    KeysOld = maps:get(Call, ChecksLookup4, []),
                                    KeysNew = lists:umerge(KeysOld, [Key]),
                                    maps:put(Call, KeysNew, ChecksLookup4)
                                end, ChecksLookup3, Locations)
                            end, ChecksLookup2, Problems)
                        end, ChecksLookup1, FileWarnings);
                    {error, Reason} ->
                        erlang:error({FilePath, Reason})
                end
        end
    end, ChecksLookup0, FilePaths),
    ListLookupN = maps:fold(fun(Problem, Keys, ListLookup0) ->
        lists:foldl(fun(Key, ListLookup1) ->
            maps:put(Key,
                     [Problem | maps:get(Key, ListLookup1, [])],
                     ListLookup1)
        end, ListLookup0, Keys)
    end, #{}, ChecksLookupN),
    ChecksNewN = lists:reverse(maps:fold(fun({Severity, Message},
                                             Problems, ChecksNew0) ->
        lists:umerge(ChecksNew0, [{Severity, Message, lists:usort(Problems)}])
    end, [], ListLookupN)),
    if
        
        ChecksNewN == ChecksOld ->
            ChecksOld;
        true ->
            checks_expand_loop(FilePaths, ChecksNewN)
    end.

dependency_store(Dependency, Checks) ->
    PestData1 = case pest_data_find(pest) of
        {ok, PestData0} ->
            PestData0;
        error ->
            [{dependency, []}]
    end,
    {value,
     {dependency, Dependencies0},
     PestData2} = lists:keytake(dependency, 1, PestData1),
    DependenciesN = lists:keystore(Dependency, 1, Dependencies0,
                                   {Dependency, Checks}),
    PestDataN = lists:keystore(dependency, 1, PestData2,
                               {dependency, DependenciesN}),
    pest_data_store(pest, PestDataN),
    ok.

analyze_store(Call, Line,
              #warnings{function_calls = FunctionCalls} = Warnings) ->
    Warnings#warnings{function_calls = [{Call, Line} | FunctionCalls]}.
    
analyze_checks(#warnings{checks_lookup = ChecksLookup,
                         function_calls = FunctionCalls} = Warnings0,
               Location, CurrentFunction) ->
    lists:foldl(fun({Call, Line}, Warnings1) ->
        case maps:is_key(Call, ChecksLookup) of
            true ->
                analyze_checks_store(Warnings1, Call, Line,
                                     Location, CurrentFunction);
            false ->
                {Module, _, _} = Call,
                case maps:is_key(Module, ChecksLookup) of
                    true ->
                        analyze_checks_store(Warnings1, Module, Line,
                                             Location, CurrentFunction);
                    false ->
                        Warnings1
                end
        end
    end, Warnings0#warnings{function_calls = []}, lists:reverse(FunctionCalls)).

analyze_checks_store(#warnings{instances = Instances} = Warnings,
                     Problem, _, function, CurrentFunction) ->
    NewLocations = lists:umerge(maps:get(Problem, Instances, []),
                                [CurrentFunction]),
    NewInstances = maps:put(Problem, NewLocations, Instances),
    Warnings#warnings{instances = NewInstances};
analyze_checks_store(#warnings{instances = Instances} = Warnings,
                     Problem, Line, line, _) ->
    NewLocations = [Line | maps:get(Problem, Instances, [])],
    NewInstances = maps:put(Problem, NewLocations, Instances),
    Warnings#warnings{instances = NewInstances}.

-spec warnings_format(Warnings :: #warnings{}) ->
    list(warning()).

warnings_format(#warnings{checks_lookup = ChecksLookup,
                          instances = Instances}) ->
    OutputN = maps:fold(fun(Problem, Locations, Output0) ->
        Keys = maps:get(Problem, ChecksLookup),
        lists:foldl(fun(Key, Output1) ->
            maps:put(Key,
                     maps:put(Problem,
                              lists:reverse(Locations),
                              maps:get(Key, Output1, #{})),
                     Output1)
        end, Output0, Keys)
    end, #{}, Instances),
    lists:reverse(maps:fold(fun({Severity, Message}, Problems, L) ->
        lists:umerge(L, [{Severity, Message, Problems}])
    end, [], OutputN)).

-spec consistency_checks(Checks :: any()) ->
    ok.

consistency_checks([_ | _] = Checks) ->
    % internal consistency checks to make sure all the checks are valid
    lists:foldl(fun({Severity, Message, Problems}, Set0) ->
        if
            is_integer(Severity), Severity >= 0, Severity =< 100 ->
                ok;
            true ->
                erlang:error({invalid_severity, Severity})
        end,
        if
            is_list(Message), is_integer(hd(Message)) ->
                ok;
            true ->
                erlang:error({invalid_message, Message})
        end,
        if
            is_list(Problems) ->
                lists:foldl(fun(Problem, SetN) ->
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
                    case sets:is_element(Problem, SetN) of
                        true ->
                            erlang:error({duplicate_problem, Problem});
                        false ->
                            sets:add_element(Problem, SetN)
                    end
                end, Set0, Problems);
            true ->
                erlang:error({invalid_problems, Problems})
        end
    end, sets:new(), Checks),
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

application_modules(Application) when is_atom(Application) ->
    case application:load(Application) of
        ok ->
            {ok, Modules} = application:get_key(Application, modules),
            ModulesSorted = lists:sort(Modules),
            _ = application:unload(Application),
            ModulesSorted;
        {error, Reason} ->
            erlang:error({invalid_application, Reason})
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
    filename:join([filename:dirname(?FILE),
                   "..", "priv", "pest.dat"]).

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
    {CVE, LN} = lists:splitwith(fun(C0) ->
        (C0 >= $A andalso C0 =< $Z) orelse
        (C0 >= $0 andalso C0 =< $9) orelse
        (C0 == $-)
    end, L0),
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
    {PatchNumber, PatchString} = lists:splitwith(fun(C) ->
        (C >= $0) andalso (C =< $9)
    end, erlang:binary_to_list(VersionPatch)),
    LibrarySource = if
        PatchString == "" ->
            "package manager fork?";
        true ->
            "openssl mainline!"
    end,
    Fork = {erlang:binary_to_list(VersionMajor),
            erlang:binary_to_list(VersionMinor),
            PatchNumber},
    Vulnerabilities = case pest_data_find(crypto) of
        {ok, [{openssl, VulnerabilitiesData}]} ->
            VulnerabilitiesData;
        error ->
            []
    end,
    SecurityProblems = if
        % based on
        % https://en.wikipedia.org/wiki/OpenSSL#Major_version_releases
        Fork =< {"1", "0", "0"} ->
            ["OLD OpenSSL!"];
        true ->
            []
    end ++
    lists:flatmap(fun({CVE, Level, _Fix, Affected}) ->
        case version_info_openssl_check(Affected, Version) of
            true ->
                [CVE ++
                 "(" ++ string:to_upper(erlang:atom_to_list(Level)) ++ ")"];
            false ->
                []
        end
    end, Vulnerabilities),
    {length(SecurityProblems), 1 + length(Vulnerabilities),
     LibrarySource, SecurityProblems}.

version_info_openssl_check([], _) ->
    false;
version_info_openssl_check([Version | _], Version) ->
    true;
version_info_openssl_check([Affected | AffectedL], Version) ->
    case lists:splitwith(fun(C) -> C /= $- end, Affected) of
        {[_ | _], []} ->
            version_info_openssl_check(AffectedL, Version);
        {AffectedFrom, AffectedTo} ->
            case lists:prefix(AffectedFrom, Version) andalso
                 lists:last(Version) =< lists:last(AffectedTo) of
                true ->
                    true;
                false ->
                    version_info_openssl_check(AffectedL, Version)
            end
    end.

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
              [filename:basename(?FILE),
               Version, FileHash]).

help() ->
"Usage ~s [OPTION] [FILES] [DIRECTORIES]

  -b              Only process beam files recursively
  -c              Perform internal consistency checks
  -d DEPENDENCY   Expand the checks to include a dependency
                  (provide the dependency as a file path or directory)
  -D IDENTIFIER   Expand the checks to include a dependency from an identifier
  -e              Only process source files recursively
  -h              List available command line flags
  -i              Display checks information after expanding dependencies
  -m APPLICATION  Display a list of modules in an Erlang/OTP application
  -p DIRECTORY    Append a directory on the code server's search path list
  -r              Recursively search directories
  -s SEVERITY     Set the minimum severity to use when reporting problems
                  (default is 50)
  -U COMPONENT    Update local data related to a component
                  (valid components are: crypto, pest/dependency/IDENTIFIER)
  -v              Verbose output (set the minimum severity to 0)
  -V [COMPONENT]  Print version information
                  (valid components are: pest, crypto)
".

