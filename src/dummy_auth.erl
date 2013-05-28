-module(dummy_auth).
-include("../include/smtp.hrl").
-include("../include/erlmail.hrl").
-export([plain/2]).


%Plain Authentication only have one stage so AuthState(pre_auth,post_auth) is not required
plain(Info, _ ) ->
	try binary:split(base64:decode(Info),<<0>>,[global]) of
		[MailAddress,MailAddress,Password] -> auth(erlmail_util:split_email(binary_to_list(MailAddress)),binary_to_list(Password));
		Malformed -> 
			?D(["Malformed Input",Malformed]),
			resp(malformed)
	catch 
		_:_ -> 
			?D(["Malformed Input",Info]),
			resp(malformed)
	end.

resp(success) ->
	{true,235};
resp(auth_failed) ->
	{false,535};
resp(malformed) ->
	{false,535}.
auth(Username,Password) ->
	?D([Username,Password]),
	case erlmail_store:select(#user{name=Username}) of
				#user{password = Password} = User when Password /= [] -> 
					resp(success);
				_ -> 
					resp(auth_failed)
	end.
