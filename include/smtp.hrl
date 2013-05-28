-ifndef(D).
-define(D(X), io:format("DEBUG ~p:~p ~p~n",[?MODULE, ?LINE, X])).
-endif.
-ifndef(CRLF).
-define(CRLF,[13,10]).
-endif.
-ifndef(CRLF_BIN).
-define(CRLF_BIN, <<13,10>>).
-endif.


-define(SMTPD_PORT,25).
-define(SMTPD_MAX_CONN,25).
-define(SMTP_DATA_END, [13,10,46,13,10]). % End of data command "\r\n.\r\n"

-define(MAX_RESTART,    5).
-define(MAX_TIME,      60).
-define(TIMEOUT,   300000).

-record(smtpc,{
	       server = "127.0.0.1",
	       port = 25,
               socket = [],
               auth = [],
	       buff = <<>>,
               features = [],
               type = smtp, % smtp server type: [smtp:esmtp]
               state = helo % State of command, [helo,mail,rcpt,data]
              }).
-record(smtpd_ext,{
		name, %auth/ssl/utf-8
		text, %STARTSSL/AUTH/8BITMIME
		options=[]
	}).
%3 states is being employed here
%cmd is currently prompted command
%state stands for current status,for instance,if user requested mail from,it should in mail state which not available for auth or sth else
%auth_state contains unauthenticated,pre_auth,post_auth,authenticated status to represent the stage of authentication
-record(smtpd_fsm,{
                   socket      = [],
                   addr        = [],
                   relay       = false,
		   type	       = smtpd,
		   extensions  = [], %only used when under esmtp mode
		   auth_method = plain, %plain,login,oauth,cram-md5,digest-md5
		   auth_engine = dummy_auth, %should define a gen_auth module to implement auth engine later
		   auth_state  = unauthenticated, %unauthenticated,pre_auth,post_auth,authenticated
		   tls         = false, %starttls 
		   ssl_socket  = [],
		   state       = undefined, %used for state record
                   options     = [],
                   buff        = <<>>,
                   line        = [],
                   cmd         = undefined,
                   param       = undefined,
                   host        = undefined,
                   mail        = undefined,
                   rcpt        = undefined,
                   to          = undefined,
                   messagename = undefined,
                   data        = undefined
                  }).

-record(smtpd_state, {
                      listener,       % Listening socket
                      acceptor,       % Asynchronous acceptor's internal reference
                      module          % FSM handling module
                     }).


-record(outgoing_smtp,{
                       rcpt       = [],
                       tries      = 0,
                       next_retry = [],
                       response   = []
                      }).

