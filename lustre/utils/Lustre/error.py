import exceptions

class LconfError (exceptions.Exception):
    def __init__(self, args):
        self.args = args

class OptionError (exceptions.Exception):
    def __init__(self, args):
        self.args = args

