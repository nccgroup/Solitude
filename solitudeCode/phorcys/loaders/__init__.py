import abc


class DumpLoader(object, metaclass = abc.ABCMeta):
    def __init__(self, dump_file):
        self.dump_file = dump_file
        self.flows = None

    def __str__(self):
        return self.dump_file

    @abc.abstractmethod
    def load(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __iter__(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __len__(self):
        raise NotImplementedError()
