%%%---------------------------------------------------------------------------------------
%%% @author    Stuart Jackson <sjackson@simpleenigma.com> [http://erlsoft.org]
%%% @copyright 2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc       SMTP server commands
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
-module(esmtpd_cmd).
-author('sjackson@simpleenigma.com').
-include("../include/smtp.hrl").
-include("../include/erlmail.hrl").

-export([command/2]).
-export([store_message/2,store_message/4]).
-export([out/3,send/2]).

-export([check_user/1,check_user/2]).


command(Line,#smtpd_fsm{state=auth,auth_method=AuthMethod,auth_state=AuthState,auth_engine=Engine}=State) when is_binary(Line) ->
	%Right now only plain support
	%So will not consider following stagse.but in fact here should be cut into different phases
	case Engine:AuthMethod(Line,AuthState) of 
		{true,Code} ->
			%When authenticated, it should return back to EHLO state
			NewState=State#smtpd_fsm{auth_state=authenticated},
			send(extension,NewState,Code),
			NewState#smtpd_fsm{cmd=undefined,state=ehlo};
		{false,Code} ->
			NewState=State#smtpd_fsm{auth_state=failed},
			send(extension,NewState,Code),
			NewState#smtpd_fsm{cmd=undefined,state=ehlo,auth_state=unauthenticated}
	end;
	
command(Line,State) when is_binary(Line) -> command(parse(Line),State);

command({greeting,_},State) ->
	out(greeting,State),
	send(State,220,erlmail_util:get_app_env(server_smtp_greeting,"ErlMail http://erlsoft.org (NO UCE)")),
	State;


%ehlo should be put into a new esmtp_cmd file to handle user request
command({ehlo = Command,Domain},State) when is_list(Domain), length(Domain) > 0 -> 
	%?D([Command,Domain,State]),
	out(Command,Domain,State),
	NewState=State#smtpd_fsm{host=Domain,cmd=ehlo},
	send(extension,NewState),
	NewState#smtpd_fsm{cmd=undefined,state=ehlo};
command({starttls = Command,[]},#smtpd_fsm{tls=false}=State) ->
	NewState=State#smtpd_fsm{cmd=starttls},
	send(extension,NewState),
	case start_tls(NewState) of 
		{ok,SSLSocket} -> 
			NewState#smtpd_fsm{cmd=undefined,ssl_socket=SSLSocket,tls=true};
		{error,Reason} ->
			?D(["SSL Start error",Reason]),
			State
	end;


%Auth should have aggresive mode(AUTH PLAIN base64(username/0username/0password)) and normal mode(AUTH XXXX) ,responde -> challenge
%Normal Mode
command({auth = Command,Method},#smtpd_fsm{auth_state=unauthenticated,extensions=Extensions}=State) when is_list(Method) ->
	Auth=get_ext(auth,Extensions),
	{value,{params,AvailableMethod}}=lists:keysearch(params,1,Auth#smtpd_ext.options),
	case erlmail_util:in_list_to_lower(Method,AvailableMethod) of
		false -> 
			send(extension,State#smtpd_fsm{cmd=auth},504),
			State;
		M -> 
			%?D([Command,M]),
			out(Command,M,State),
			NewState=State#smtpd_fsm{state=auth,auth_method=M},
			send(extension,NewState,334),
			NewState#smtpd_fsm{cmd=undefined,state=auth,auth_state=pre_auth}
	end;
%Aggressive Mode
%Right now I just copied the logic of normal mode, should find a way to make a general one
command({auth = Command,Method,Info},#smtpd_fsm{auth_state=unauthenticated,extensions=Extensions}=State) when is_list(Method), is_list(Info) ->
	Auth=get_ext(auth,Extensions),
	{value,{params,AvailableMethod}}=lists:keysearch(params,1,Auth#smtpd_ext.options),
	case erlmail_util:in_list_to_lower(Method,AvailableMethod) of	
		false -> 
			send(extension,State#smtpd_fsm{cmd=auth},504),
			State;
		M -> 
			%?D([Command,M]),
			%out(Command,M,State),
			NewState=State#smtpd_fsm{state=auth,auth_method=M,auth_state=pre_auth},
			command(list_to_binary(Info),NewState)
	end;



%% MAIL before HELO or EHLO
command({mail = Command,Param},#smtpd_fsm{host = undefined} = State) ->
	out(Command,Param,State),
	send(State,503),
	State;
command({mail = Command,Param},State) when length(Param) > 0 ->
	From = clean_email(Param),
	out(Command,From,State),
	NewState=State#smtpd_fsm{cmd=mail,mail = From, rcpt = undefined, to = undefined, messagename = undefined, data = undefined},
	send(NewState,250),
	NewState#smtpd_fsm{cmd=undefine,state=mail};
%% RCPT before MAIL
command({rcpt = Command,Param},#smtpd_fsm{mail = undefined} = State) ->
	out(Command,Param,State),
	send(State,503),
	State;
%% Too many Rcpt
command({rcpt = Command,Param},#smtpd_fsm{rcpt = RcptList} = State) when is_list(RcptList), length(RcptList) >= 100 ->
	out(Command,Param,State),
	send(State,452,"Too many recipients"),
	State;
command({rcpt = Command,Param},#smtpd_fsm{relay = Relay} = State) ->
	To = clean_email(Param),
	out(Command,To,State),
	?D({relay,Relay}),
	case check_user(erlmail_util:split_email(To),Relay) of
		true ->
			NewRcptList = case State#smtpd_fsm.rcpt of
				undefined -> [To];
				RcptList -> [To|RcptList]
			end,
			NewState=State#smtpd_fsm{cmd=rcpt,rcpt=NewRcptList},
			send(NewState,250),
			?D({rcpt,NewRcptList}),
			State#smtpd_fsm{cmd=undefined,rcpt=NewRcptList,state=rcpt};
		false ->
			send(State,550),
			State
	end;

command({data = Command,[]},#smtpd_fsm{rcpt = undefined} = State) ->
	out(Command,State),
	send(State,503),
	State;
command({data = Command,[]},State) ->
	out(Command,State),
	NewState=State#smtpd_fsm{cmd=data,data = <<>>},
	send(NewState,354),
	NewState#smtpd_fsm{cmd=undefined,state=data,data = <<>>};

command({noop = Command,[]},State) ->
	out(Command,State),
	send(State,250),
	State;
command({vrfy = Command,[]},State) ->
	out(Command,State),
	send(State,502),
	State;
command({expn = Command,[]},State) ->
	out(Command,State),
	send(State,502),
	State;
command({help = Command,_Param},State) ->
	out(Command,State),
	send(State,250,"http://erlsoft.org"),
	State;
command({quit = Command,[]},State) ->
	out(Command,State),
	send(State,221),
	gen_fsm:send_all_state_event(self(),stop),
	State;
command({rset = Command,[]},State) ->
	out(Command,State),
	send(State,250),
	State#smtpd_fsm{cmd = undefined, param = undefined, mail = undefined, rcpt = undefined, to = undefined, messagename = undefined, data = undefined};

%% Obsolete
command({send = Command,_Param},State) ->
	out(Command,State),
	send(State,502),
	State;
%% Obsolete
command({soml = Command,_Param},State) ->
	out(Command,State),
	send(State,502),
	State;
%% Obsolete
command({saml = Command,_Param},State) ->
	out(Command,State),
	send(State,502),
	State;




command({Command,Param},State) ->
	io:format("Unknown Command: ~p ~p~n",[Command,Param]),
	send(State,500),
	State.

check_user(Name) -> check_user(Name,undefined).
check_user(_Name,true) -> true;
check_user({_UserName,_DomainName} = Name,_Relay) ->
	case erlmail_store:status(Name) of
		{ok,User} when is_record(User,user) -> true;
		_Other -> false
	end.


%% @todo cehck relay state and store messages according to local or outgoing status. Only real differene is in the message name.

store_message(Message,State) when is_binary(Message) -> store_message(binary_to_list(Message),State);
store_message(Message,_State) when is_record(Message,message) ->
	case erlmail_antispam:pre_deliver(Message) of
		{ok,NewMessage} -> 
			erlmail_store:deliver(NewMessage),
			case erlmail_antispam:post_deliver(Message) of
				{ok,_M} -> ok;
				{error,Reason} -> {error,Reason}
			end;
		{error,Reason} -> {error,Reason}
	end;
store_message(Message,#smtpd_fsm{relay = _Relay} = State) ->
	lists:map(fun(To) -> 
		MessageName = erlmail_store:message_name(now()),
		store_message(MessageName,erlmail_util:split_email(To),Message,State)
		end,State#smtpd_fsm.rcpt).

store_message(MessageName,{UserName,DomainName},Message,#smtpd_fsm{relay = true} = State) -> 
	case check_user({UserName,DomainName}) of
		true ->
			store_message(#message{
				name={MessageName,UserName,DomainName},
				message=Message},State);
		false ->
			?D({relay,non_local}),
			SmtpOut = #outgoing_smtp{rcpt = erlmail_util:combine_email(UserName,DomainName)},
			store_message(#message{
				name={MessageName,SmtpOut,now()},
				message=Message},State)
	end;
store_message(MessageName,{UserName,DomainName},Message,#smtpd_fsm{relay = false} = State) -> 
	store_message(#message{
		name={MessageName,UserName,DomainName},
		message=Message},State).

send(#smtpd_fsm{cmd=ehlo}=State,250) -> send(extension,State) ;
send(extension,#smtpd_fsm{cmd=starttls}=State) ->
	send_msg(resp(starttls,220,{}),220,State);
send(extension,#smtpd_fsm{socket=Socket,cmd=ehlo,extensions=Extensions}=State) -> 
	[Head|Tail]=Extensions,
	EHLO_RES="250 "++Head#smtpd_ext.text++?CRLF,
	Res2=lists:foldl(fun(#smtpd_ext{name=auth}=Ext,Acc) ->
				{params,Params}=lists:keyfind(params,1,Ext#smtpd_ext.options),
				String = "250-" ++ Ext#smtpd_ext.text ++ " " ++ string:join(Params," ") ++ ?CRLF,
				[String|Acc] ;
			    (Ext,Acc) ->
				String =  "250-"++ Ext#smtpd_ext.text ++ ?CRLF ,
				[String|Acc] ;
			    ([],Acc) ->
				Acc
		end,EHLO_RES,Tail),
	send_msg(Res2,State);
send(State,Code) -> send(State,Code,resp(Code)).
%Respond to user (auth,foo/login/plain) commands
send(extension,#smtpd_fsm{cmd=auth,auth_method=AuthMethod,auth_state=AuthState}=State,Code)->
	send_msg(resp(auth,Code,{AuthMethod,AuthState}),Code,State);
send(extension,#smtpd_fsm{state=auth,auth_method=AuthMethod,auth_state=AuthState}=State,Code) ->
	send_msg(resp(auth,Code,{AuthMethod,AuthState}),Code,State);
send(State,Code,Message) when is_record(State,smtpd_fsm) -> send_msg(Message,Code,State).




parse(Bin)  when is_binary(Bin) -> parse(binary_to_list(Bin));
parse(Line) when is_list(Line)  ->
	%Split by space character
	case string:chr(Line,32) of
		0 -> {list_to_atom(http_util:to_lower(Line)),[]};
		Pos ->
			{Command,RespText} = lists:split(Pos-1,Line),
			%?D([Command]),
			case list_to_atom(http_util:to_lower(Command)) of
					auth -> parse(auth,string:strip(RespText));
					CMD -> {CMD,string:strip(RespText)}
			end
	end.
parse(auth,RespText) ->
	case string:chr(RespText,32) of
		0 -> 
			%?D(["Normal mode"]),
			{auth,string:strip(RespText)};
	Pos ->
		{Method,Info} = lists:split(Pos-1,RespText),
		%?D(["Aggressive Mode",Method,Info]),
		{auth,Method,string:strip(Info)}
	end.



out(Command,State) -> io:format("~p ~p~n",[State#smtpd_fsm.addr,Command]).
out(Command,Param,State) -> io:format("~p ~p ~p~n",[State#smtpd_fsm.addr,Command,Param]).



clean_email(String) -> 
	case re:run(String,"<(.*)>") of
		%{match,[{0,6},{1,4}]}=re:run("<good>","<(.*)>")
		%string:substr(String,1,1) -> "<goo"
		%Erlang string substr doesn't go from 0 but 1 
		{match,[{_,_},{Start,Length}]} -> string:substr(String,Start+1,Length);
		nomatch -> nomatch
	end.

resp(auth,504,_) -> "Unrecognized authentication type.";
%FIXME right here I didn't test whether fsm_state is right or not, but in fact it should be ehlo
%Further change might be done here

%rfc4954 : http://tools.ietf.org/rfc/rfc4954.txt
resp(auth,334,{plain,unauthenticated}) -> "Go ahead";
resp(auth,235,{_,authenticated}) -> "Authentication Succeeded";
resp(auth,432,{_,failed}) -> "A password transition is needed";
resp(auth,454,{_,failed}) -> "Temporary authentication failure";
resp(auth,534,{_,failed}) -> "Authentication mechanism is too weak";
resp(auth,535,{_,failed}) -> "Authentication credentials invalid";
resp(auth,500,{_,failed}) -> "Authentication Exchange line is too long";
resp(auth,501,{_,failed}) -> "Authentication canceled";
resp(auth,503,{_,failed}) -> "Already authenticated";
resp(auth,535,{_,failed}) -> "Unable to authenticate";
resp(auth,538,{_,failed}) -> "Encryption required for requested authentication mechanism";
%This should returned by requested any other commands except for auth command when auth is prerequisite for 
resp(_,530,{_,failed}) -> "Authentication required";

resp(starttls,220,_) -> "Go ahead";



resp(_,_,_) -> ?D("unknown command").
resp(211) -> "System Status"; % Need more info
resp(214) -> "For help please go to http://erlsoft.org/modules/erlmail/";
resp(220) -> "ErlMail (NO UCE)";
resp(221) -> "SMTP server closing transmission channel";
resp(250) -> "Requested mail action okay, completed";
resp(251) -> "User not local";
resp(252) -> "Cannot VRFY user, but will accept message and attempt deliver";
resp(354) -> "Mail input accepted";
resp(421) -> "Service Not avaiable, closing transmission channel";
resp(450) -> "Requestion action not taken: mailbox unavailable";
resp(451) -> "Requestion action aborted: local error in processing";
resp(452) -> "Requestion action not taken: insufficient system storage";
resp(500) -> "Syntax error, command unrecognized";
resp(501) -> "Syntax error in parameters or arguments";
resp(502) -> "Command not implimented";
resp(503) -> "Bad sequence of commands";
resp(504) -> "Command parameter not implimented";
resp(511) -> "No mailbox here by that name";
resp(550) -> "Reqested action not taken: mailbox unavailable";
resp(551) -> "User not local";
resp(552) -> "Requestion action not taken: insufficient system storage";
resp(553) -> "Requestion action not taken: mailbox name not allowed";
resp(554) -> "Transaction Failed".

get_ext(Name,[#smtpd_ext{name=Name}=Ext|Tail])->
	Ext;
get_ext(Name,[Ext|Tail]) ->
	get_ext(Name,Tail);
get_ext(Name,[]) ->
	undefined.
start_tls(State) ->
	ssl:start(),
	CAFile="./cert/ca.crt",
	Cert="./cert/server.crt",
	Key ="./cert/server.key",
	ssl:ssl_accept(State#smtpd_fsm.socket,[{cacertfile,CAFile},{certfile,Cert }, {keyfile,Key}]).
	
send_msg(Msg,#smtpd_fsm{socket=Socket,ssl_socket=SSLSocket}=State) ->
	case State#smtpd_fsm.tls of 
		true -> ssl:send(SSLSocket,Msg);
		false -> gen_tcp:send(Socket,Msg)
	end.
send_msg(Message,Code,#smtpd_fsm{socket=Socket,ssl_socket=SSLSocket}=State) ->
	Last = string:right(Message,2),
	Msg = case Last of
		?CRLF -> [integer_to_list(Code),32,Message];
		_      -> [integer_to_list(Code),32,Message,?CRLF]
	end,
	case State#smtpd_fsm.tls of 
		true -> ssl:send(SSLSocket,Msg);
		false -> gen_tcp:send(Socket,Msg)
	end.
