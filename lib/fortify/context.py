CLIARGS = dict()

def _init_global_context(cli_args):
    """
    initialize the global context objects, which holds the parse CLI arguments data
    """
    global CLIARGS
    CLIARGS = cli_args
