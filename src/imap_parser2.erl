-module(imap_parser2).
%%% This is a replacement of the broken Leex/Yecc-based IMAP parser.
%%% The IMAP syntax does not lend itself well to a separate tokenizer and
%%% parser. For instance, certain places in the protocol allows free-text,
%%% and a word may be a keyword or not depending on where it occurs.
%%% The present implementation is a recursive-descent parser based directly
%%% on the RFC3501 (IMAP4rev1) syntax specification.

%-export([parse/1, parse_and_scan/1, format_error/1]).
-compile(export_all). % For now

%% Parser combinators
-define(SEQ(A,B), (fun(In1)-> {Res1,Rest1} = A(In1),
                              {Res2,Rest2} = B(Rest1),
                              {[Res1, Res2], Rest2}
                   end)).


%% Productions, alphabetically, as they occur in RFC3501.
%% Naming convention: A function name suffix of "_m1", "_m2", etc.,
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
%%
%% ASTRING-CHAR   = ATOM-CHAR / resp-specials
%%
%% atom            = 1*ATOM-CHAR
%%
%% ATOM-CHAR       = <any CHAR except atom-specials>
%%
%% atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
%%                   quoted-specials / resp-specials
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
%%
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
        {"COPY", Rest}    -> copy_m1(Rest);
        {"FETCH", Rest}   -> fetch_m1(Rest);
        {"STORE", Rest}   -> store_m1(Rest);
        {"UID", Rest}     -> uid_m1(Rest);
        {"SEARCH", Rest}  -> search_m1(Rest);
        {Other, _Rest} ->
            throw({parser_error, "Syntax error near '"++Other++"', expecting command"})
    end.

%%
%% continue-req    = "+" SP (resp-text / base64) CRLF
continue_req_m1(_) -> throw('TODO').


%% copy            = "COPY" SP sequence-set SP mailbox
copy_m1(_) -> throw('TODO').

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
fetch_m1(_) -> throw('TODO').

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
%%
%% flag-extension  = "\" atom
%%                     ; Future expansion.  Client implementations
%%                     ; MUST accept flag-extension flags.  Server
%%                     ; implementations MUST NOT generate
%%                     ; flag-extension flags except as defined by
%%                     ; future standard or standards-track
%%                     ; revisions of this specification.
%%
%% flag-fetch      = flag / "\Recent"
%%
%% flag-keyword    = atom
%%
%% flag-list       = "(" [flag *(SP flag)] ")"
%%
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
%%
%% literal         = "{" number "}" CRLF *CHAR8
%%                     ; Number represents the number of CHAR8s
%%
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
%%
%% mailbox-data    =  "FLAGS" SP flag-list / "LIST" SP mailbox-list /
%%                    "LSUB" SP mailbox-list / "SEARCH" *(SP nz-number) /
%%                    "STATUS" SP mailbox SP "(" [status-att-list] ")" /
%%                    number SP "EXISTS" / number SP "RECENT"
%%
%% mailbox-list    = "(" [mbx-list-flags] ")" SP
%%                    (DQUOTE QUOTED-CHAR DQUOTE / nil) SP mailbox
%%
%% mbx-list-flags  = *(mbx-list-oflag SP) mbx-list-sflag
%%                   *(SP mbx-list-oflag) /
%%                   mbx-list-oflag *(SP mbx-list-oflag)
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
%%
%% QUOTED-CHAR     = <any TEXT-CHAR except quoted-specials> /
%%                   "\" quoted-specials
%%
%% quoted-specials = DQUOTE / "\"
%%
%% rename          = "RENAME" SP mailbox SP mailbox
%%                     ; Use of INBOX as a destination gives a NO error
%%
%% response        = *(continue-req / response-data) response-done
response([$+ | S]) ->
    ?SEQ(continue_req_m1, response_done)(S);
response([$* | S]) ->
    ?SEQ(response_data_m1, response_done)(S);
response(X) ->
    throw({parser_error, "Syntax error near '"++X++"', at beginning of response"}).

%%
%% response-data   = "*" SP (resp-cond-state / resp-cond-bye /
%%                   mailbox-data / message-data / capability-data) CRLF
response_data_m1(S) -> response_data_m2(require_one_space(S)).

response_data_m2(_) -> throw('TODO').


%% response-done   = response-tagged / response-fatal
response_done([$*|S]) -> response_fatal_m1(S);
response_done(S)      -> response_tagged(S).

%% response-fatal  = "*" SP resp-cond-bye CRLF
%%                     ; Server closes connection immediately
response_fatal_m1(S) -> response_fatal_m2(require_one_space(S)).

response_fatal_m2(_) -> throw('TODO').

%%
%% response-tagged = tag SP resp-cond-state CRLF
response_tagged(_) -> throw('TODO').

%% resp-cond-auth  = ("OK" / "PREAUTH") SP resp-text
%%                     ; Authentication condition
%%
%%
%%
%% resp-cond-bye   = "BYE" SP resp-text
%%
%% resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
%%                     ; Status condition
%%
%% resp-specials   = "]"
%%
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
search_m1(_) -> throw('TODO').

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
store_m1(_) -> throw('TODO').

%%
%% store-att-flags = (["+" / "-"] "FLAGS" [".SILENT"]) SP
%%                   (flag-list / (flag *(SP flag)))
%%
%% string          = quoted / literal
%%
%% subscribe       = "SUBSCRIBE" SP mailbox
%%
%% tag             = 1*<any ASTRING-CHAR except "+">
%%
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
uid_m1(_) -> throw('TODO').

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
first_lowercase_word([C|Rest],Acc) when (C>=$A andalso C=<$Z);
                                        (C>=$a andalso C=<$z) ->
    first_lowercase_word(Rest, [C|Acc]);
first_lowercase_word(L,Acc) -> {lists:reverse(Acc),L}.

require_one_space([$\s | S]) -> S;
require_one_space(S) ->
    throw({parser_error, "Exactly one space expected, but got '"++S++"'"}).
