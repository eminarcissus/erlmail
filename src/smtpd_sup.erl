%%%---------------------------------------------------------------------------------------
%%% @author    Stuart Jackson <sjackson@simpleenigma.com> [http://erlsoft.org]
%%% @copyright 2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc       SMTPD supervisor definition file
%%% @reference See <a href="http://erlsoft.org/modules/erlmail" target="_top">Erlang Software Framework</a> for more information
%%% @reference See <a href="http://erlmail.googlecode.com" target="_top">ErlMail Google Code Repository</a> for more information
%%% @version   0.0.6
%%% @since     0.0.5
%%% @end
%%%
%%%
%%% The MIT License
%%%
%%% Copyright (c) 2007 Stuart Jackson, Simple Enigma, Inc. All Righs Reserved
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining a copy
%%% of this software and associated documentation files (the "Software"), to deal
%%% in the Software without restriction, including without limitation the rights
%%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%%% copies of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be included in
%%% all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
%%% THE SOFTWARE.
%%%
%%%
%%%---------------------------------------------------------------------------------------
-module(smtpd_sup).
-author('sjackson@simpleenigma.com').
-include("../include/smtp.hrl").

-behaviour(supervisor).

-export([init/1,start_link/0]).
%% Internal API
-export([start_client/0]).

start_link() ->
	ListenPort = erlmail_util:get_app_env(server_smtp_port, 8025),
	Protocol = erlmail_util:get_app_env(server_smtp_protocol,tcp),
	Module = erlmail_util:get_app_env(smtp_handler, smtp_session_handler),
	Certfile = erlmail_util:get_app_env(ssl_cert,"./cert/server.crt"),
	Keyfile = erlmail_util:get_app_env(ssl_key,"./cert/server.key"),
	SMTP_OPTION=[
		[{port,ListenPort},
		{protocol,Protocol},
		{certfile,Certfile}, %ssl listener option
		{keyfile,Keyfile}, %ssl listener option
		{sessionoptions,
		[
			{certfile,Certfile},
			{keyfile,Keyfile},
			{callbackoptions,[
			{auth,true}
			]}
		]}
	]
	],

    	supervisor:start_link({local, ?MODULE}, ?MODULE, [Module,SMTP_OPTION]).

%% A startup function for spawning new client connection handling FSM.
%% To be called by the TCP listener process.
start_client() -> supervisor:start_child(smtpd_client_sup, []).


init([Module,Option]) ->
    {ok,
        {_SupFlags = {one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [% gen_smtp_server
              {gen_smtp_server,
               {gen_smtp_server,start_link,[Module,Option]},
               permanent,
               2000,
               worker,
               [gen_smtp_server]
              }
            ]
        }
    }.
