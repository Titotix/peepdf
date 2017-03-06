
import logging.handlers
import traceback


class PdfParserHandler(logging.Handler):
    """
    Logging to peepdfObject errors attribute handler
    peepdfObject is any object which declare a method addError(errMsg)

    """

    def __init__(self, peepdfObject):
        self.peepdfObject = peepdfObject
        logging.Handler.__init__(self)

    def emit(self, record):
        if record.levelname == "ERROR" or record.levelname == "CRITICAL":
            self.peepdfObject.addError(record.getMessage())

def getExcMessage():
    return traceback.format_exc().splitlines()[-1]
