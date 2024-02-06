from fortify.release import __version__

import argparse

def version():
    """
    Show the current version
    """
    version = "v" + __version__

    return version

class FortifyVersion(argparse.Action):
    """Call back to show Fortify version"""
    def __call__ (self, parser, namespace, values, option_string=None):
        print(version())
        parser.exit()


def add_verbosity_options(parser): 
    """Add option for verbosity"""
    parser.add_argument('-v', '--verbose', dest='verbosity', default=0, action="count",
                    help="Causes Fortify to print more descriptive message.")


def create_base_parser(prog_name="", usage="", desc="", epilog=""):
    """Create a base argparse object for parsing CLI arguments"""
    parser = argparse.ArgumentParser(
        prog=prog_name,
        usage=usage,
        description=desc,
        epilog=epilog
    )

    parser.add_argument(
        '--version', 
        action=FortifyVersion, 
        nargs=0, 
        help="Show Fortify version."
    )
    
    add_verbosity_options(parser)

    return parser