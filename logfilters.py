import logging


class FilterLogMessages(logging.Filter):

    def __init__(self, filter_list):
        self.filter_list = filter_list

    def filter(self, record):
        for word in self.filter_list:
            #record.message = record.message(word, '**********')
            print("")

        return True


class CustomAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return 'test', kwargs
