-module(dummy_auth).
-include("../include/smtp.hrl").
-include("../include/erlmail.hrl").
-export([auth/2]).


resp(success) ->
	ok;
resp(Msg) ->
	{error,Msg}.
auth(MailAdd,Password) ->
	case erlmail_util:split_email(MailAdd) of 
		{[],[]} -> resp(malformed);
		{_Username,_DomainName}=Username ->
			case erlmail_store:select(#user{name=Username}) of
				#user{password = Password} = User when Password /= [] -> 
					resp(success);
				_ -> 
					resp(auth_failed)
			end
	end.
