import os
import sys
import locale

from datetime import datetime
import fortify.context as context
import fortify.constant as c

from fortify.utils.logger import Logger, init_global_logger, logger


# def check_blocking_io():
#     """Check stdin/stdout/stderr to make sure they are using blocking IO."""
#     handles = []

#     for handle in (sys.stdin, sys.stdout, sys.stderr):
#         # noinspection PyBroadException
#         try:
#             fd = handle.fileno()
#         except Exception:
#             continue  # not a real file handle, such as during the import sanity test

#         if not os.get_blocking(fd):
#             handles.append(getattr(handle, 'name', None) or '#%s' % fd)

#     if handles:
#         raise SystemExit('ERROR: Fortify requires blocking IO on stdin/stdout/stderr. '
#                          'Non-blocking file handles detected: %s' % ', '.join(_io for _io in handles))

# check_blocking_io()

def initialize_locale():
    """
    Set the locale to the users default setting and ensure
    the locale and filesystem encoding are UTF-8.
    """
    try:
        locale.setlocale(locale.LC_ALL, '')
        dummy, encoding = locale.getlocale()
    except (locale.Error, ValueError) as e:
        raise SystemExit(
            'ERROR: Fortify could not initialize the preferred locale: %s' % e
        )

    if not encoding or encoding.lower() not in ('utf-8', 'utf8'):
        raise SystemExit(
            'ERROR: Fortify requires the locale encoding to be UTF-8; Detected %s.' % encoding)

    fs_enc = sys.getfilesystemencoding()
    if fs_enc.lower() != 'utf-8':
        raise SystemExit(
            'ERROR: Fortify requires the filesystem encoding to be UTF-8; Detected %s.' % fs_enc)

initialize_locale()

from fortify.cli.parser import arg_helper as parser
from abc import ABC, abstractmethod

class CLI(ABC):
    """Standard template code for derivative programs"""
    def __init__(self, args):
        """
        Base init method for derivative cli programs
        """
        if not args:
            raise ValueError("A non-empty list for args is required")

        self.args = args
        self.parser = None

        init_global_logger(new_logger=Logger())

    @abstractmethod
    def run(self):
        """
        Run the Fortify command

        Subclass must implement this method, the majority of process start here
        """
        # Parse the CLI arguments
        self.parse()
        
        # show banner to user
        if not c.SUPPRESS_BANNER:
            logger.banner(self.logo)

        # load the fortify.yml config 
        self._load_config()


    @abstractmethod
    def initialize_parser(self, usage=None, desc=None, epilog=None):
        """
        Create a base parser for Fortify script

        Subclass must implement this method, and called super function to this method.
        """
        self.parser = parser.create_base_parser(
            prog_name=self.name,
            usage=usage,
            desc=desc,
            epilog=epilog
        )

    @abstractmethod
    def post_process_args(self, options):
        """
        Process the command line args

        Subclass need to implement this method. this method validates and transform the command line args.
        """

        return options

    def parse(self):
        """
        Parse the command line args

        this function used the parser stored in self.parser which are created by the initialize_parser.

        subclass needs to implement post_process_args and initialize_parser function which are called by this 
        function before and after parsing the arguments.
        """
        self.initialize_parser()

        try:
            options = self.parser.parse_args(self.args[1:])
        except SystemExit as ex:
            if ex.code != 0:
                self.parser.exit()
            raise
        # do post cli arg parsing check
        options = self.post_process_args(options)
        # save the CLI args in global context
        context._init_global_context(cli_args=options)
    
    def _load_config(self):
        """
        Load configuration file
        """
        config = {}

        self.config = config

    @classmethod
    def cli_execute(cls, args=None):
        """Instantiate and Execute the CLI application"""
        START_TIME = datetime.now()
        
        if args is None:
            args = sys.argv

        cli = cls(args)
        exit_code = cli.run()

        END_TIME = datetime.now()
        RUN_TIME = END_TIME - START_TIME

        if context.CLIARGS.verbosity > 0:
            logger.status(msg=f"APP INFO", status="STAT", seperation=False)
            logger.display(msg=f"RUN TIME: {RUN_TIME}", color="light_yellow")
        

