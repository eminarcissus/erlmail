-module(dummy_auth).
-include("../include/smtp.hrl").
-export([plain/2]).


plain(Info,State) ->
	true.
