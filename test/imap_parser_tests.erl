-module(imap_parser_tests).

-compile(export_all).

rfc_3501_delete_example() ->
    ["C: A682 LIST \"\" *",
     "S: * LIST () \"/\" blurdybloop",
     "S: * LIST (\\Noselect) \"/\" foo",
     "S: * LIST () \"/\" foo/bar",
     "S: A682 OK LIST completed",
     "C: A683 DELETE blurdybloop",
     "S: A683 OK DELETE completed",
     "C: A684 DELETE foo",
     "S: A684 NO Name \"foo\" has inferior hierarchical names",
     "C: A685 DELETE foo/bar",
     "S: A685 OK DELETE Completed",
     "C: A686 LIST \"\" *",
     "S: * LIST (\\Noselect) \"/\" foo",
     "S: A686 OK LIST completed",
     "C: A687 DELETE foo",
     "S: A687 OK DELETE Completed",
     "C: A82 LIST \"\" *",
     "S: * LIST () \".\" blurdybloop",
     "S: * LIST () \".\" foo",
     "S: * LIST () \".\" foo.bar",
     "S: A82 OK LIST completed",
     "C: A83 DELETE blurdybloop",
     "S: A83 OK DELETE completed",
     "C: A84 DELETE foo",
     "S: A84 OK DELETE Completed",
     "C: A85 LIST \"\" *",
     "S: * LIST () \".\" foo.bar",
     "S: A85 OK LIST completed",
     "C: A86 LIST \"\" %",
     "S: * LIST (\\Noselect) \".\" foo",
     "S: A86 OK LIST completed"].


parse_delete_example_test() ->
    [test_parser(X) || X <- rfc_3501_delete_example()].

test_parser(Line) ->
    R = try
        case Line of
            "C: "++Command -> imap_parser2:parse_command(Command);
            "S: "++Response -> imap_parser2:parse_response_line(Response)
        end
    catch Cls:Err ->
            Trace = erlang:get_stacktrace(),
            error_logger:error_msg("Parsing failed: ~p -> ~p\n** Stack trace: ~p\n", [Line, Err, Trace]),
            erlang:raise(Cls, Err, Trace)
    end,
    io:format(user, "  Parsed ~p -> ~p\n", [Line, R]),
    ok.
