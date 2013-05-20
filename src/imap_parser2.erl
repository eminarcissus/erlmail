-module(imap_parser2).
%%% This is a replacement of the broken Leex/Yecc-based IMAP parser.
%%% The IMAP syntax does not lend itself well to a separate tokenizer and
%%% parser. For instance, certain places in the protocol allows free-text,
%%% and a word may be a keyword or not depending on where it occurs.
%%% The present implementation is a recursive-descent parser based directly
%%% on the RFC3501 (IMAP4rev1) syntax specification.

-export([parse_response/1,
         parse_response_line/1,
         parse_command/1]). % , parse_and_scan/1, format_error/1]).
%-compile(export_all). % For now

-include("imap.hrl").

%% Parser combinators
-define(SEQ(A,B), (fun(In1)-> {Res1,Rest1} = A(In1),
                              {Res2,Rest2} = B(Rest1),
                              {[Res1, Res2], Rest2}
                   end)).

-define(IS_resp_cond_state_FIRST(W),
        (W=:="ok" orelse W=:="no" orelse W=:="bad")).

parse_response(S) ->
    response(S).

parse_response_line(S) ->
    response_line(S).

parse_command(_S) ->
    'TODO'. % command(S).

%% Productions, alphabetically, as they occur in RFC3501.
%% Naming convention: A function name suffix of "_p1", "_p2", etc.,
%% means "the first 1 (, 2, ...) tokens of the production have already
%% been processed". This is used for a number of productions with
%% fixed prefixes.

%% address         = "(" addr-name SP addr-adl SP addr-mailbox SP
%%                   addr-host ")"
%%
%% addr-adl        = nstring
%%                     ; Holds route from [RFC-2822] route-addr if
%%                     ; non-NIL
%%
%% addr-host       = nstring
%%                     ; NIL indicates [RFC-2822] group syntax.
%%                     ; Otherwise, holds [RFC-2822] domain name
%%
%% addr-mailbox    = nstring
%%                     ; NIL indicates end of [RFC-2822] group; if
%%                     ; non-NIL and addr-host is NIL, holds
%%                     ; [RFC-2822] group name.
%%                     ; Otherwise, holds [RFC-2822] local-part
%%                     ; after removing [RFC-2822] quoting
%%
%%
%%
%%
%% addr-name       = nstring
%%                     ; If non-NIL, holds phrase from [RFC-2822]
%%                     ; mailbox after removing [RFC-2822] quoting
%%
%% append          = "APPEND" SP mailbox [SP flag-list] [SP date-time] SP
%%                   literal
%%
%% astring         = 1*ASTRING-CHAR / string
astring(S) ->
    case lists:splitwith(fun is_ASTRING_CHAR/1, S) of
        {[],_} -> string(S);
        {_Astring,_S2}=R -> R
    end.

%% ASTRING-CHAR   = ATOM-CHAR / resp-specials
is_ASTRING_CHAR(C) -> is_ATOM_CHAR(C) orelse is_resp_special(C).

%% atom            = 1*ATOM-CHAR
atom(S) ->
    case lists:splitwith(fun is_ATOM_CHAR/1, S) of
        {[],_} -> throw({parser_error, "Syntax error near '"++S++"': Expected atom."});
        {_Atom,_S2}=R -> R
    end.

%% ATOM-CHAR       = <any CHAR except atom-specials>
is_ATOM_CHAR(C) ->
    not is_atom_special(C).

%% atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
%%                   quoted-specials / resp-specials
is_atom_special($() -> true;
is_atom_special($)) -> true;
is_atom_special(${) -> true;
is_atom_special($\s) -> true;
is_atom_special(C) when C<$\s -> true;
is_atom_special(C) ->
    is_list_wildcard(C) orelse is_quoted_special(C) orelse is_resp_special(C).

%%
%% authenticate    = "AUTHENTICATE" SP auth-type *(CRLF base64)
%%
%% auth-type       = atom
%%                     ; Defined by [SASL]
%%
%% base64          = *(4base64-char) [base64-terminal]
%%
%% base64-char     = ALPHA / DIGIT / "+" / "/"
%%                     ; Case-sensitive
%%
%% base64-terminal = (2base64-char "==") / (3base64-char "=")
%%
%% body            = "(" (body-type-1part / body-type-mpart) ")"
%%
%% body-extension  = nstring / number /
%%                    "(" body-extension *(SP body-extension) ")"
%%                     ; Future expansion.  Client implementations
%%                     ; MUST accept body-extension fields.  Server
%%                     ; implementations MUST NOT generate
%%                     ; body-extension fields except as defined by
%%                     ; future standard or standards-track
%%                     ; revisions of this specification.
%%
%% body-ext-1part  = body-fld-md5 [SP body-fld-dsp [SP body-fld-lang
%%                   [SP body-fld-loc *(SP body-extension)]]]
%%                     ; MUST NOT be returned on non-extensible
%%                     ; "BODY" fetch
%%
%%
%%
%%
%% body-ext-mpart  = body-fld-param [SP body-fld-dsp [SP body-fld-lang
%%                   [SP body-fld-loc *(SP body-extension)]]]
%%                     ; MUST NOT be returned on non-extensible
%%                     ; "BODY" fetch
%%
%% body-fields     = body-fld-param SP body-fld-id SP body-fld-desc SP
%%                   body-fld-enc SP body-fld-octets
%%
%% body-fld-desc   = nstring
%%
%% body-fld-dsp    = "(" string SP body-fld-param ")" / nil
%%
%% body-fld-enc    = (DQUOTE ("7BIT" / "8BIT" / "BINARY" / "BASE64"/
%%                   "QUOTED-PRINTABLE") DQUOTE) / string
%%
%% body-fld-id     = nstring
%%
%% body-fld-lang   = nstring / "(" string *(SP string) ")"
%%
%% body-fld-loc    = nstring
%%
%% body-fld-lines  = number
%%
%% body-fld-md5    = nstring
%%
%% body-fld-octets = number
%%
%% body-fld-param  = "(" string SP string *(SP string SP string) ")" / nil
%%
%% body-type-1part = (body-type-basic / body-type-msg / body-type-text)
%%                   [SP body-ext-1part]
%%
%% body-type-basic = media-basic SP body-fields
%%                     ; MESSAGE subtype MUST NOT be "RFC822"
%%
%% body-type-mpart = 1*body SP media-subtype
%%                   [SP body-ext-mpart]
%%
%% body-type-msg   = media-message SP body-fields SP envelope
%%                   SP body SP body-fld-lines
%%
%% body-type-text  = media-text SP body-fields SP body-fld-lines
%%
%% capability      = ("AUTH=" auth-type) / atom
%%                     ; New capabilities MUST begin with "X" or be
%%                     ; registered with IANA as standard or
%%                     ; standards-track
%%
%%
%% capability-data = "CAPABILITY" *(SP capability) SP "IMAP4rev1"
%%                   *(SP capability)
%%                     ; Servers MUST implement the STARTTLS, AUTH=PLAIN,
%%                     ; and LOGINDISABLED capabilities
%%                     ; Servers which offer RFC 1730 compatibility MUST
%%                     ; list "IMAP4" as the first capability.
capability_data_p1(_S) ->
    throw('TODO').

%% CHAR8           = %x01-ff
%%                     ; any OCTET except NUL, %x00
%%
%% command         = tag SP (command-any / command-auth / command-nonauth /
%%                   command-select) CRLF
%%                     ; Modal based on state
%%
%% command-any     = "CAPABILITY" / "LOGOUT" / "NOOP" / x-command
%%                     ; Valid in all states
%%
%% command-auth    = append / create / delete / examine / list / lsub /
%%                   rename / select / status / subscribe / unsubscribe
%%                     ; Valid only in Authenticated or Selected state
%%
%% command-nonauth = login / authenticate / "STARTTLS"
%%                     ; Valid only when in Not Authenticated state
%%
%% command-select  = "CHECK" / "CLOSE" / "EXPUNGE" / copy / fetch / store /
%%                   uid / search
%%                     ; Valid only when in Selected state
command_select(S) ->
    case first_lowercase_word(S) of
        {"CHECK", Rest}   -> {check, Rest};
        {"CLOSE", Rest}   -> {close, Rest};
        {"EXPUNGE", Rest} -> {expunge, Rest};
        {"COPY", Rest}    -> copy_p1(Rest);
        {"FETCH", Rest}   -> fetch_p1(Rest);
        {"STORE", Rest}   -> store_p1(Rest);
        {"UID", Rest}     -> uid_p1(Rest);
        {"SEARCH", Rest}  -> search_p1(Rest);
        {Other, _Rest} ->
            throw({parser_error, "Syntax error near '"++Other++"', expecting command"})
    end.

%%
%% continue-req    = "+" SP (resp-text / base64) CRLF
continue_req_p1(_) -> throw('TODO').


%% copy            = "COPY" SP sequence-set SP mailbox
copy_p1(_) -> throw('TODO').

%%
%% create          = "CREATE" SP mailbox
%%                     ; Use of INBOX gives a NO error
%%
%% date            = date-text / DQUOTE date-text DQUOTE
%%
%% date-day        = 1*2DIGIT
%%                     ; Day of month
%%
%% date-day-fixed  = (SP DIGIT) / 2DIGIT
%%                     ; Fixed-format version of date-day
%%
%% date-month      = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" /
%%                   "Jul" / "Aug" / "Sep" / "Oct" / "Nov" / "Dec"
%%
%% date-text       = date-day "-" date-month "-" date-year
%%
%%
%% date-year       = 4DIGIT
%%
%% date-time       = DQUOTE date-day-fixed "-" date-month "-" date-year
%%                   SP time SP zone DQUOTE
%%
%% delete          = "DELETE" SP mailbox
%%                     ; Use of INBOX gives a NO error
%%
%% digit-nz        = %x31-39
%%                     ; 1-9
%%
%% envelope        = "(" env-date SP env-subject SP env-from SP
%%                   env-sender SP env-reply-to SP env-to SP env-cc SP
%%                   env-bcc SP env-in-reply-to SP env-message-id ")"
%%
%% env-bcc         = "(" 1*address ")" / nil
%%
%% env-cc          = "(" 1*address ")" / nil
%%
%% env-date        = nstring
%%
%% env-from        = "(" 1*address ")" / nil
%%
%% env-in-reply-to = nstring
%%
%% env-message-id  = nstring
%%
%% env-reply-to    = "(" 1*address ")" / nil
%%
%% env-sender      = "(" 1*address ")" / nil
%%
%% env-subject     = nstring
%%
%% env-to          = "(" 1*address ")" / nil
%%
%% examine         = "EXAMINE" SP mailbox
%%
%% fetch           = "FETCH" SP sequence-set SP ("ALL" / "FULL" / "FAST" /
%%                   fetch-att / "(" fetch-att *(SP fetch-att) ")")
fetch_p1(_) -> throw('TODO').

%% fetch-att       = "ENVELOPE" / "FLAGS" / "INTERNALDATE" /
%%                   "RFC822" [".HEADER" / ".SIZE" / ".TEXT"] /
%%                   "BODY" ["STRUCTURE"] / "UID" /
%%                   "BODY" section ["<" number "." nz-number ">"] /
%%                   "BODY.PEEK" section ["<" number "." nz-number ">"]
%%
%%
%%
%%
%% flag            = "\Answered" / "\Flagged" / "\Deleted" /
%%                   "\Seen" / "\Draft" / flag-keyword / flag-extension
%%                     ; Does not include "\Recent"
flag("\\"++S) ->
    {FlagName,S2} = atom(S),
    {{flag, FlagName}, S2};
flag(S) ->
    {FlagKeyword,S2} = atom(S),
    {{flag_keyword, FlagKeyword}, S2}.
%% flag(S) ->
%%     throw({parser_error, "Syntax error in flag, near \""++S++"\""}).



%% flag-extension  = "\" atom
%%                     ; Future expansion.  Client implementations
%%                     ; MUST accept flag-extension flags.  Server
%%                     ; implementations MUST NOT generate
%%                     ; flag-extension flags except as defined by
%%                     ; future standard or standards-track
%%                     ; revisions of this specification.
flag_extension("\\"++S) -> atom(S);
flag_extension(S) ->
    throw({parser_error, "Syntax error: Expected flag near '"++S++"'"}).
%%
%% flag-fetch      = flag / "\Recent"
%%
%% flag-keyword    = atom
%%
%% flag-list       = "(" [flag *(SP flag)] ")"
flag_list("()"++S) -> {{'TODO-flags', []}, S};
flag_list("("++S) ->
    {Flags, Rest} = collect_space_separated(fun flag/1, S),
    {{'TODO-flags', Flags}, Rest}.

%% flag-perm       = flag / "\*"
%%
%% greeting        = "*" SP (resp-cond-auth / resp-cond-bye) CRLF
%%
%% header-fld-name = astring
%%
%% header-list     = "(" header-fld-name *(SP header-fld-name) ")"
%%
%% list            = "LIST" SP mailbox SP list-mailbox
%%
%% list-mailbox    = 1*list-char / string
%%
%% list-char       = ATOM-CHAR / list-wildcards / resp-specials
%%
%% list-wildcards  = "%" / "*"
is_list_wildcard($%) -> true;
is_list_wildcard($*) -> true;
is_list_wildcard(_) -> false.

%%
%% literal         = "{" number "}" CRLF *CHAR8
%%                     ; Number represents the number of CHAR8s
literal_p1(_S) -> throw('TODO').


%% login           = "LOGIN" SP userid SP password
%%
%% lsub            = "LSUB" SP mailbox SP list-mailbox
%%
%%
%%
%%
%%
%%
%%
%%
%%
%% mailbox         = "INBOX" / astring
%%                     ; INBOX is case-insensitive.  All case variants of
%%                     ; INBOX (e.g., "iNbOx") MUST be interpreted as INBOX
%%                     ; not as an astring.  An astring which consists of
%%                     ; the case-insensitive sequence "I" "N" "B" "O" "X"
%%                     ; is considered to be INBOX and not an astring.
%%                     ;  Refer to section 5.1 for further
%%                     ; semantic details of mailbox names.
mailbox(S) ->
    %% TODO: Special handling of "INBOX" (case insensitivity)
    astring(S).

%% mailbox-data    =  "FLAGS" SP flag-list / "LIST" SP mailbox-list /
%%                    "LSUB" SP mailbox-list / "SEARCH" *(SP nz-number) /
%%                    "STATUS" SP mailbox SP "(" [status-att-list] ")" /
%%                    number SP "EXISTS" / number SP "RECENT"
mailbox_data_p1("flags",S) -> flag_list(require_one_space(S));
mailbox_data_p1("list",S) -> mailbox_list(require_one_space(S));
mailbox_data_p1("lsub", _S) -> throw('TODO');
mailbox_data_p1("search", _S) -> throw('TODO');
mailbox_data_p1("status", _S) -> throw('TODO');
mailbox_data_p1(W, _S) ->
    throw({parser_error, "Unknown response item \""++W++"\""}).
%% TODO: Handle number case.

%% mailbox-list    = "(" [mbx-list-flags] ")" SP
%%                    (DQUOTE QUOTED-CHAR DQUOTE / nil) SP mailbox
mailbox_list("()"++S) -> mailbox_list_p3([], S);
mailbox_list("("++S) ->
    {Mailboxes,S2} = collect_space_separated(fun mbx_list_flags/1, S),
    mailbox_list_p3(Mailboxes, expect_char($), S2)).

mailbox_list_p3(Mailboxes, S) ->
    S3 = require_one_space(S),
    case S3 of
        "\""++S4 ->
            case quoted_p1(S4) of
                {[C],S5} -> Foo=C;
                {_Cs,_} ->
                    Foo=S5=dummy,
                    throw({parser_error, "Syntax error: string must be of length 1 near \""++S4++"\""})
            end;
        _ ->
            case first_lowercase_word(S3) of
                {"nil", S5} -> Foo=nil;
                {W,_} ->
                    Foo=S5=dummy,
                    throw({parser_error, "Syntax error near '"++W++"'"})
            end
    end,
    S6 = require_one_space(S5),
    {Mailbox,S7} = mailbox(S6),
    {{'TODO-mailbox-list', Mailboxes, Foo, Mailbox}, S7}.


%% mbx-list-flags  = *(mbx-list-oflag SP) mbx-list-sflag
%%                   *(SP mbx-list-oflag) /
%%                   mbx-list-oflag *(SP mbx-list-oflag)
mbx_list_flags(S) ->
    {List, S2} = collect_space_separated(fun flag_extension/1, S),
    %% TODO: Check that at most one of \Noselect, \Marked, \Unmarked is present.
    {{'todo-mbc-list-flags', List}, S2}.

%%
%% mbx-list-oflag  = "\Noinferiors" / flag-extension
%%                     ; Other flags; multiple possible per LIST response
%%
%% mbx-list-sflag  = "\Noselect" / "\Marked" / "\Unmarked"
%%                     ; Selectability flags; only one per LIST response
%%
%% media-basic     = ((DQUOTE ("APPLICATION" / "AUDIO" / "IMAGE" /
%%                   "MESSAGE" / "VIDEO") DQUOTE) / string) SP
%%                   media-subtype
%%                     ; Defined in [MIME-IMT]
%%
%% media-message   = DQUOTE "MESSAGE" DQUOTE SP DQUOTE "RFC822" DQUOTE
%%                     ; Defined in [MIME-IMT]
%%
%% media-subtype   = string
%%                     ; Defined in [MIME-IMT]
%%
%% media-text      = DQUOTE "TEXT" DQUOTE SP media-subtype
%%                     ; Defined in [MIME-IMT]
%%
%% message-data    = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))
%%
%% msg-att         = "(" (msg-att-dynamic / msg-att-static)
%%                    *(SP (msg-att-dynamic / msg-att-static)) ")"
%%
%% msg-att-dynamic = "FLAGS" SP "(" [flag-fetch *(SP flag-fetch)] ")"
%%                     ; MAY change for a message
%%
%% msg-att-static  = "ENVELOPE" SP envelope / "INTERNALDATE" SP date-time /
%%                   "RFC822" [".HEADER" / ".TEXT"] SP nstring /
%%                   "RFC822.SIZE" SP number /
%%                   "BODY" ["STRUCTURE"] SP body /
%%                   "BODY" section ["<" number ">"] SP nstring /
%%                   "UID" SP uniqueid
%%                     ; MUST NOT change for a message
%%
%% nil             = "NIL"
%%
%% nstring         = string / nil
%%
%% number          = 1*DIGIT
%%                     ; Unsigned 32-bit integer
%%                     ; (0 <= n < 4,294,967,296)
%%
%% nz-number       = digit-nz *DIGIT
%%                     ; Non-zero unsigned 32-bit integer
%%                     ; (0 < n < 4,294,967,296)
%%
%% password        = astring
%%
%% quoted          = DQUOTE *QUOTED-CHAR DQUOTE
quoted_p1(S) ->quoted_p1(S, []).

quoted_p1([$"|S], Acc) -> {lists:reverse(Acc), S};
quoted_p1([$\\,$\\|S], Acc) -> quoted_p1(S, [$\\|Acc]);
quoted_p1([$\\,$"|S], Acc) -> quoted_p1(S, [$"|Acc]);
quoted_p1([$\\,_]=S, _Acc) ->
    throw({parser_error, "Bad escape sequence near '"++S++"'"});
quoted_p1([C|S], Acc) -> quoted_p1(S, [C|Acc]).

%% QUOTED-CHAR     = <any TEXT-CHAR except quoted-specials> /
%%                   "\" quoted-specials
%%
%% quoted-specials = DQUOTE / "\"
is_quoted_special($") -> true;
is_quoted_special($\\) -> true;
is_quoted_special(_) -> false.

%%
%% rename          = "RENAME" SP mailbox SP mailbox
%%                     ; Use of INBOX as a destination gives a NO error
%%
%% response        = *(continue-req / response-data) response-done
response(_) -> throw('TODO').

%% response_line is internal - not part of the RFC!
response_line([$+ | S]) -> continue_req_p1(S);
response_line([$* | S]) -> response_data_p1(S);
response_line(S)        -> response_done(S).

%%
%% response-data   = "*" SP (resp-cond-state / resp-cond-bye /
%%                   mailbox-data / message-data / capability-data) CRLF
response_data_p1(S) -> response_data_p2(require_one_space(S)).

response_data_p2(S) ->
    case first_lowercase_word(S) of
        {[],_} -> throw('TODO'); % mailbox-data or message-data
        {"bye",Rest} -> resp_cond_bye_p1(Rest); % TODO: eat CRLF?
        {"capability",Rest} -> capability_data_p1(Rest);
        {W,Rest} when ?IS_resp_cond_state_FIRST(W) ->
            resp_cond_state_p1(W,Rest);
        {W,Rest} ->
            mailbox_data_p1(W,Rest)
    end.


%% response-done   = response-tagged / response-fatal
response_done([$*|S]) -> response_fatal_p1(S);
response_done(S)      -> response_tagged(S).

%% response-fatal  = "*" SP resp-cond-bye CRLF
%%                     ; Server closes connection immediately
response_fatal_p1(S) -> response_fatal_p2(require_one_space(S)).

response_fatal_p2(_) -> throw('TODO').

%%
%% response-tagged = tag SP resp-cond-state CRLF
response_tagged(S) ->
    {Tag,S2} = tag(S),
    {Cond, S3} = resp_cond_state(require_one_space(S2)),
    {{'TODO-response_tagged', Tag, Cond}, S3}.

%% resp-cond-auth  = ("OK" / "PREAUTH") SP resp-text
%%                     ; Authentication condition
%%
%%
%%
%% resp-cond-bye   = "BYE" SP resp-text
resp_cond_bye_p1(S) -> {'TODO-bye', require_one_space(S)}.

%% resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
%%                     ; Status condition
resp_cond_state(S) ->
    {W,S2} = first_lowercase_word(S),
    resp_cond_state_p1(W,S2).

resp_cond_state_p1("ok",S)  -> {'TODO-ok', require_one_space(S)};
resp_cond_state_p1("no",S)  -> {'TODO-no', require_one_space(S)};
resp_cond_state_p1("bad",S) -> {'TODO-bad', require_one_space(S)}.

%% resp-specials   = "]"
is_resp_special($]) -> true;
is_resp_special(_) -> false.

%% resp-text       = ["[" resp-text-code "]" SP] text
%%
%% resp-text-code  = "ALERT" /
%%                   "BADCHARSET" [SP "(" astring *(SP astring) ")" ] /
%%                   capability-data / "PARSE" /
%%                   "PERMANENTFLAGS" SP "("
%%                   [flag-perm *(SP flag-perm)] ")" /
%%                   "READ-ONLY" / "READ-WRITE" / "TRYCREATE" /
%%                   "UIDNEXT" SP nz-number / "UIDVALIDITY" SP nz-number /
%%                   "UNSEEN" SP nz-number /
%%                   atom [SP 1*<any TEXT-CHAR except "]">]
%%
%% search          = "SEARCH" [SP "CHARSET" SP astring] 1*(SP search-key)
%%                     ; CHARSET argument to MUST be registered with IANA
search_p1(_) -> throw('TODO').

%% search-key      = "ALL" / "ANSWERED" / "BCC" SP astring /
%%                   "BEFORE" SP date / "BODY" SP astring /
%%                   "CC" SP astring / "DELETED" / "FLAGGED" /
%%                   "FROM" SP astring / "KEYWORD" SP flag-keyword /
%%                   "NEW" / "OLD" / "ON" SP date / "RECENT" / "SEEN" /
%%                   "SINCE" SP date / "SUBJECT" SP astring /
%%                   "TEXT" SP astring / "TO" SP astring /
%%                   "UNANSWERED" / "UNDELETED" / "UNFLAGGED" /
%%                   "UNKEYWORD" SP flag-keyword / "UNSEEN" /
%%                     ; Above this line were in [IMAP2]
%%                   "DRAFT" / "HEADER" SP header-fld-name SP astring /
%%                   "LARGER" SP number / "NOT" SP search-key /
%%                   "OR" SP search-key SP search-key /
%%                   "SENTBEFORE" SP date / "SENTON" SP date /
%%                   "SENTSINCE" SP date / "SMALLER" SP number /
%%                   "UID" SP sequence-set / "UNDRAFT" / sequence-set /
%%                   "(" search-key *(SP search-key) ")"
%%
%% section         = "[" [section-spec] "]"
%%
%% section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP header-list /
%%                   "TEXT"
%%                     ; top-level or MESSAGE/RFC822 part
%%
%% section-part    = nz-number *("." nz-number)
%%                     ; body part nesting
%%
%% section-spec    = section-msgtext / (section-part ["." section-text])
%%
%% section-text    = section-msgtext / "MIME"
%%                     ; text other than actual body part (headers, etc.)
%%
%% select          = "SELECT" SP mailbox
%%
%% seq-number      = nz-number / "*"
%%                     ; message sequence number (COPY, FETCH, STORE
%%                     ; commands) or unique identifier (UID COPY,
%%                     ; UID FETCH, UID STORE commands).
%%                     ; * represents the largest number in use.  In
%%                     ; the case of message sequence numbers, it is
%%                     ; the number of messages in a non-empty mailbox.
%%                     ; In the case of unique identifiers, it is the
%%                     ; unique identifier of the last message in the
%%                     ; mailbox or, if the mailbox is empty, the
%%                     ; mailbox's current UIDNEXT value.
%%                     ; The server should respond with a tagged BAD
%%                     ; response to a command that uses a message
%%                     ; sequence number greater than the number of
%%                     ; messages in the selected mailbox.  This
%%                     ; includes "*" if the selected mailbox is empty.
%%
%% seq-range       = seq-number ":" seq-number
%%                     ; two seq-number values and all values between
%%                     ; these two regardless of order.
%%                     ; Example: 2:4 and 4:2 are equivalent and indicate
%%                     ; values 2, 3, and 4.
%%                     ; Example: a unique identifier sequence range of
%%                     ; 3291:* includes the UID of the last message in
%%                     ; the mailbox, even if that value is less than 3291.
%%
%% sequence-set    = (seq-number / seq-range) *("," sequence-set)
%%                     ; set of seq-number values, regardless of order.
%%                     ; Servers MAY coalesce overlaps and/or execute the
%%                     ; sequence in any order.
%%                     ; Example: a message sequence number set of
%%                     ; 2,4:7,9,12:* for a mailbox with 15 messages is
%%                     ; equivalent to 2,4,5,6,7,9,12,13,14,15
%%                     ; Example: a message sequence number set of *:4,5:7
%%                     ; for a mailbox with 10 messages is equivalent to
%%                     ; 10,9,8,7,6,5,4,5,6,7 and MAY be reordered and
%%                     ; overlap coalesced to be 4,5,6,7,8,9,10.
%%
%% status          = "STATUS" SP mailbox SP
%%                   "(" status-att *(SP status-att) ")"
%%
%%
%% status-att      = "MESSAGES" / "RECENT" / "UIDNEXT" / "UIDVALIDITY" /
%%                   "UNSEEN"
%%
%% status-att-list =  status-att SP number *(SP status-att SP number)
%%
%% store           = "STORE" SP sequence-set SP store-att-flags
store_p1(_) -> throw('TODO').

%%
%% store-att-flags = (["+" / "-"] "FLAGS" [".SILENT"]) SP
%%                   (flag-list / (flag *(SP flag)))
%%
%% string          = quoted / literal
string("\""++S) -> quoted_p1(S);
string("{"++S)  -> literal_p1(S);
string(S) ->
    throw({parser_error, "Syntax error: expected string, but got '"++S++"'"}).

%% subscribe       = "SUBSCRIBE" SP mailbox
%%
%% tag             = 1*<any ASTRING-CHAR except "+">
tag(S) ->
    case lists:splitwith(fun is_ASTRING_CHAR_not_plus/1, S) of
        {[],_} -> throw({parser_error, "Syntax error near '"++S++"': Expected tag."});
        {_Tag,_S2}=R -> R
    end.

is_ASTRING_CHAR_not_plus($+) -> false;
is_ASTRING_CHAR_not_plus(C) -> is_ASTRING_CHAR(C).


%% text            = 1*TEXT-CHAR
%%
%% TEXT-CHAR       = <any CHAR except CR and LF>
%%
%% time            = 2DIGIT ":" 2DIGIT ":" 2DIGIT
%%                     ; Hours minutes seconds
%%
%% uid             = "UID" SP (copy / fetch / search / store)
%%                     ; Unique identifiers used instead of message
%%                     ; sequence numbers
uid_p1(_) -> throw('TODO').

%% uniqueid        = nz-number
%%                     ; Strictly ascending
%%
%% unsubscribe     = "UNSUBSCRIBE" SP mailbox
%%
%% userid          = astring
%%
%% x-command       = "X" atom <experimental command arguments>
%%
%% zone            = ("+" / "-") 4DIGIT
%%                     ; Signed four-digit value of hhmm representing
%%                     ; hours and minutes east of Greenwich (that is,
%%                     ; the amount that the given time differs from
%%                     ; Universal Time).  Subtracting the timezone
%%                     ; from the given time will give the UT form.
%%                     ; The Universal Time zone is "+0000".


%%%==================== Helper functions ====================
first_lowercase_word(S) -> first_lowercase_word(S, []).
first_lowercase_word([C|Rest],Acc) when (C>=$a andalso C=<$z) ->
    first_lowercase_word(Rest, [C|Acc]);
first_lowercase_word([C|Rest],Acc) when (C>=$A andalso C=<$Z) ->
    first_lowercase_word(Rest, [C + ($a - $A) |Acc]);
first_lowercase_word(L,Acc) -> {lists:reverse(Acc),L}.

require_one_space([$\s | S]) -> S;
require_one_space(S) ->
    throw({parser_error, "Exactly one space expected, but got '"++S++"'"}).

expect_char(C, [C|S]) -> S;
expect_char(C, S) ->
    throw({parser_error, "Syntax error: Expected '"++[C]++"', but got '"++S++"'"}).

collect_space_separated(F, S) ->
    {First, S2} = F(S),
    collect_space_separated(F, S2, [First]).
collect_space_separated(F, " "++S, Acc) ->
    {Item, S2} = F(S),
    collect_space_separated(F, S2, [Item|Acc]);
collect_space_separated(_F, S, Acc) ->
    {lists:reverse(Acc), S}.
