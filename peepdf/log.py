
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

class PDFObjectLogger():

    def __init__(self):
        self.logHandler = PdfParserHandler(self)
        self.logHandler.setLevel(logging.DEBUG)
        self.log = logging.getLogger(self.__class__.__module__ + "." + self.__class__.__name__)
        self.log.addHandler(self.logHandler)
        self.errors = []

    def addError(self, errorMessage):
        '''
            Add an error to the object

            @param errorMessage: The error message to be added (string)
        '''
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def getErrors(self):
        return self.errors

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True


def getExcMessage():
    return traceback.format_exc().splitlines()[-1]
