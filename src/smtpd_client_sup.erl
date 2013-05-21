%%%-------------------------------------------------------------------
%%% @author misuzi
%%% @copyright (C) 2013, misuzi
%%% @doc
%%%
%%% @end
%%% Created : 2013-05-22 00:52:18.836164
%%%-------------------------------------------------------------------
-module(smtpd_client_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
        supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
        RestartStrategy = simple_one_for_one,
        MaxRestarts = 1000,
        MaxSecondsBetweenRestarts = 3600,

        SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

        Restart = temporary,
        Shutdown = 2000,
        Type = worker,

        AChild = {'smtpd_worker', {'smtpd_fsm', start_link, []},
                          Restart, Shutdown, Type, ['smtpd_fsm']},

        {ok, {SupFlags, [AChild]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================



