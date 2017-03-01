#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

'''
    This module contains classes and methods to analyse and modify PDF files
'''

import hashlib
import os
import random
import re
import sys
import traceback
import logging

from peepdf.PDFUtils import (
    numToHex, numToString, vtcheck
)
from peepdf.PDFCrypto import (
    computeObjectKey, computeUserPass, isUserPass, isOwnerPass,
    computeEncryptionKey, computeOwnerPass
)

from peepdf.PDFObjects import (
    PDFIndirectObject, PDFName, PDFReference, PDFBool,
    PDFDictionary, PDFString, PDFNum, PDFArray, PDFStream,
    PDFNull, PDFHexString, PDFObjectStream, PDFTrailer
)
from peepdf.constants import newLine
from peepdf.log import PdfParserHandler

log = logging.getLogger(__name__)

MAL_ALL = 1
MAL_HEAD = 2
MAL_EOBJ = 3
MAL_ESTREAM = 4
MAL_XREF = 5
MAL_BAD_HEAD = 6
pdfFile = None
isForceMode = False
isManualAnalysis = False
spacesChars = ['\x00', '\x09', '\x0a', '\x0c', '\x0d', '\x20']
delimiterChars = ['<<', '(', '<', '[', '{', '/', '%']
monitorizedEvents = ['/OpenAction ', '/AA ', '/Names ', '/AcroForm ', '/XFA ']
monitorizedActions = ['/JS ', '/JavaScript', '/Launch', '/SubmitForm', '/ImportData']
monitorizedElements = ['/EmbeddedFiles ',
                       '/EmbeddedFile',
                       '/JBIG2Decode',
                       'getPageNthWord',
                       'arguments.callee',
                       '/U3D',
                       '/PRC',
                       '/RichMedia',
                       '/Flash',
                       '.rawValue',
                       'keep.previous']
jsVulns = ['mailto',
           'Collab.collectEmailInfo',
           'util.printf',
           'getAnnots',
           'getIcon',
           'spell.customDictionaryOpen',
           'media.newPlayer',
           'doc.printSeps',
           'app.removeToolButton']
singUniqueName = 'CoolType.SING.uniqueName'
bmpVuln = 'BMP/RLE heap corruption'
vulnsDict = {'mailto': ('mailto', ['CVE-2007-5020']),
             'Collab.collectEmailInfo': ('Collab.collectEmailInfo', ['CVE-2007-5659']),
             'util.printf': ('util.printf', ['CVE-2008-2992']),
             '/JBIG2Decode': ('Adobe JBIG2Decode Heap Corruption', ['CVE-2009-0658']),
             'getIcon': ('getIcon', ['CVE-2009-0927']),
             'getAnnots': ('getAnnots', ['CVE-2009-1492']),
             'spell.customDictionaryOpen': ('spell.customDictionaryOpen', ['CVE-2009-1493']),
             'media.newPlayer': ('media.newPlayer', ['CVE-2009-4324']),
             '.rawValue': ('Adobe Acrobat Bundled LibTIFF Integer Overflow', ['CVE-2010-0188']),
             singUniqueName: (singUniqueName, ['CVE-2010-2883']),
             'doc.printSeps': ('doc.printSeps', ['CVE-2010-4091']),
             '/U3D': ('/U3D', ['CVE-2009-3953', 'CVE-2009-3959', 'CVE-2011-2462']),
             '/PRC': ('/PRC', ['CVE-2011-4369']),
             'keep.previous': ('Adobe Reader XFA oneOfChild Un-initialized memory vulnerability', ['CVE-2013-0640']),  # https://labs.portcullis.co.uk/blog/cve-2013-0640-adobe-reader-xfa-oneofchild-un-initialized-memory-vulnerability-part-1/
             bmpVuln: (bmpVuln, ['CVE-2013-2729']),
             'app.removeToolButton': ('app.removeToolButton', ['CVE-2013-3346'])}





class PDFCrossRefSection:
    def __init__(self):
        self.errors = []
        self.streamObject = None
        self.offset = 0
        self.size = 0
        self.subsections = []  # PDFCrossRefSubsection []
        self.bytesPerField = []

    def addEntry(self, objectId, newEntry):
        prevSubsection = 0
        errorMessage = ''
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            ret = subsection.addEntry(newEntry, objectId)
            if ret[0] != -1:
                break
            else:
                errorMessage = ret[1]
                self.addError(errorMessage)
            if subsection.getFirstObject() + subsection.getNumObjects() < objectId:
                prevSubsection = i
        else:
            try:
                newSubsection = PDFCrossRefSubSection(objectId, 1, [newEntry])
            except:
                errorMessage = 'Error creating new PDFCrossRefSubSection'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
            self.subsections.insert(prevSubsection, newSubsection)
        if errorMessage != '':
            return (-1, errorMessage)
        else:
            return (0, '')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def addSubsection(self, subsection):
        self.subsections.append(subsection)

    def delEntry(self, objectId):
        errorMessage = ''
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            numEntry = subsection.getIndex(objectId)
            if numEntry is not None:
                if subsection.getNumObjects() == 1:
                    self.subsections.remove(subsection)
                else:
                    ret = subsection.delEntry(objectId)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(ret[1])
                        continue
        if errorMessage != '':
            return (-1, errorMessage)
        else:
            return (0, '')

    def getBytesPerField(self):
        return self.bytesPerField

    def getErrors(self):
        return self.errors

    def getFreeObjectIds(self):
        ids = []
        for subsection in self.subsections:
            ids += subsection.getFreeObjectIds()
        return ids

    def getNewObjectIds(self):
        ids = []
        for subsection in self.subsections:
            ids += subsection.getNewObjectIds()
        return ids

    def getOffset(self):
        return self.offset

    def getSize(self):
        return self.size

    def getStats(self):
        stats = {}
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        if self.inStream():
            stats['Stream'] = str(self.streamObject)
        else:
            stats['Stream'] = None
        stats['Subsections'] = []
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            subStats = {}
            subStats['Entries'] = str(len(subsection.getEntries()))
            if subsection.isFaulty():
                subStats['Errors'] = str(len(subsection.getErrors()))
            else:
                subStats['Errors'] = None
            stats['Subsections'].append(subStats)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats

    def getSubsectionsArray(self):
        return self.subsections

    def getSubsectionsNumber(self):
        return len(self.subsections)

    def getXrefStreamObject(self):
        return self.streamObject

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True

    def inStream(self):
        if self.streamObject is not None:
            return True
        else:
            return False

    def setBytesPerField(self, array):
        self.bytesPerField = array

    def setOffset(self, offset):
        self.offset = offset

    def setSize(self, newSize):
        self.size = newSize

    def setXrefStreamObject(self, id):
        self.streamObject = id

    def toFile(self):
        output = 'xref' + newLine
        for subsection in self.subsections:
            output += subsection.toFile()
        return output

    def updateOffset(self, objectId, newOffset):
        for subsection in self.subsections:
            updatedEntry = subsection.getEntry(objectId)
            if updatedEntry is not None:
                updatedEntry.setObjectOffset(newOffset)
                ret = subsection.setEntry(objectId, updatedEntry)
                if ret[0] == -1:
                    self.addError(ret[1])
                return ret
        else:
            errorMessage = 'Object entry not found'
            self.addError(errorMessage)
            return (-1, errorMessage)


class PDFCrossRefSubSection:
    def __init__(self, firstObject, numObjects=0, newEntries=[], offset=0):
        self.errors = []
        self.offset = offset
        self.size = 0
        self.firstObject = int(firstObject)
        self.numObjects = int(numObjects)
        self.entries = newEntries

    def addEntry(self, newEntry, objectId=None):
        if objectId is None:
            self.entries.append(newEntry)
            self.numObjects += 1
            return (0, self.numObjects)
        else:
            numEntry = self.getIndex(objectId)
            if numEntry is not None:
                self.entries.insert(numEntry, newEntry)
                self.numObjects += 1
                return (0, self.numObjects)
            else:
                if self.firstObject == objectId + 1:
                    self.entries.insert(0, newEntry)
                    self.firstObject = objectId
                    self.numObjects += 1
                    return (0, self.numObjects)
                elif objectId == self.firstObject + self.numObjects:
                    self.entries.append(newEntry)
                    self.numObjects += 1
                    return (0, self.numObjects)
                else:
                    errorMessage = 'Unspecified error'
                    self.addError(errorMessage)
                    return (-1, errorMessage)
                return (0, self.numObjects)

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def delEntry(self, objectId):
        numEntry = self.getIndex(objectId)
        if numEntry is None:
            errorMessage = 'Entry not found'
            self.addError(errorMessage)
            return (-1, errorMessage)
        if numEntry == 0:
            self.entries.pop(numEntry)
            self.firstObject = objectId + 1
            self.numObjects -= 1
        elif numEntry == self.numObjects - 1:
            self.entries.pop(numEntry)
            self.numObjects -= 1
        else:
            entry = self.entries[numEntry]
            numPrevFree = self.getPrevFree(numEntry)
            numNextFree = self.getNextFree(numEntry)
            nextObject = self.getObjectId(numNextFree)
            if numPrevFree is not None:
                prevEntry = self.entries[numPrevFree]
                prevEntry.setNextObject(objectId)
                self.entries[numPrevFree] = prevEntry
            entry.setType('f')
            if nextObject is None:
                entry.setNextObject(0)
            else:
                entry.setNextObject(nextObject)
            entry.incGenNumber()
            self.entries[numEntry] = entry
        return (0, numEntry)

    def getEntries(self):
        return self.entries

    def getEntry(self, objectId):
        numEntry = self.getIndex(objectId)
        if numEntry is not None:
            return self.entries[numEntry]
        else:
            return None

    def getErrors(self):
        return self.errors

    def getFirstObject(self):
        return self.firstObject

    def getFreeObjectIds(self):
        ids = []
        for i in range(len(self.entries)):
            if self.entries[i].getType() == 'f':
                ids.append(self.getObjectId(i))
        return ids

    def getIndex(self, objectId):
        objectIds = range(self.firstObject, self.firstObject+self.numObjects)
        if objectId in objectIds:
            return objectIds.index(objectId)
        else:
            return None

    def getNextFree(self, numEntry):
        for i in range(numEntry + 1, self.numObjects):
            if self.entries[i].getType() == 'f':
                return i
        else:
            return None

    def getNewObjectIds(self):
        ids = []
        for i in range(len(self.entries)):
            if self.entries[i].getType() == 'n':
                ids.append(self.getObjectId(i))
        return ids

    def getNumObjects(self):
        return self.numObjects

    def getObjectId(self, numEntry):
        return self.firstObject + numEntry

    def getOffset(self):
        return self.offset

    def getPrevFree(self, numEntry):
        for i in range(numEntry):
            if self.entries[i].getType() == 'f':
                return i
        else:
            return None

    def getSize(self):
        return self.size

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True

    def setEntry(self, objectId, newEntry):
        numEntry = self.getIndex(objectId)
        if numEntry is not None:
            self.entries[numEntry] = newEntry
            return (0, numEntry)
        else:
            errorMessage = 'Entry not found'
            self.addError(errorMessage)
            return (-1, errorMessage)

    def setEntries(self, newEntries):
        self.entries = newEntries

    def setFirstObject(self, newFirst):
        self.firstObject = newFirst

    def setNumObjects(self, newNumObjects):
        self.numObjects = newNumObjects

    def setOffset(self, offset):
        self.offset = offset

    def setSize(self, newSize):
        self.size = newSize

    def toFile(self):
        output = str(self.firstObject) + ' ' + str(self.numObjects) + newLine
        for entry in self.entries:
            output += entry.toFile()
        return output


class PDFCrossRefEntry:
    def __init__(self, firstValue, secondValue, type, offset=0):
        self.errors = []
        self.offset = offset
        self.objectStream = None
        self.indexObject = None
        self.genNumber = None
        self.objectOffset = None
        self.nextObject = None
        self.entryType = type
        if type == 'f' or type == 0:
            self.nextObject = int(firstValue)
            self.genNumber = int(secondValue)
        elif type == 'n' or type == 1:
            self.objectOffset = int(firstValue)
            self.genNumber = int(secondValue)
        elif type == 2:
            self.objectStream = int(firstValue)
            self.indexObject = int(secondValue)
        else:
            if isForceMode:
                self.addError('Error parsing xref entry')
            else:
                return (-1, 'Error parsing xref entry')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def getEntryBytes(self, bytesPerField):
        bytesString = ''
        errorMessage = ''

        if self.entryType == 'f' or self.entryType == 0:
            type = 0
            firstValue = self.nextObject
            secondValue = self.genNumber
        elif self.entryType == 'n' or self.entryType == 1:
            type = 1
            firstValue = self.objectOffset
            secondValue = self.genNumber
        else:
            type = 2
            firstValue = self.objectStream
            secondValue = self.indexObject

        if bytesPerField[0] != 0:
            ret = numToHex(type, bytesPerField[0])
            if ret[0] == -1:
                errorMessage = ret[1]
                if isForceMode:
                    self.addError(ret[1])
                    ret = numToHex(0, bytesPerField[0])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if bytesPerField[1] != 0:
            ret = numToHex(firstValue, bytesPerField[1])
            if ret[0] == -1:
                errorMessage = ret[1]
                if isForceMode:
                    self.addError(ret[1])
                    ret = numToHex(0, bytesPerField[1])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if bytesPerField[2] != 0:
            ret = numToHex(secondValue, bytesPerField[2])
            if ret[0] == -1:
                errorMessage = ret[1]
                if isForceMode:
                    self.addError(ret[1])
                    ret = numToHex(0, bytesPerField[1])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, bytesString)

    def getErrors(self):
        return self.errors

    def getGenNumber(self):
        return self.genNumber

    def getIndexObject(self):
        return self.indexObject

    def getNextObject(self):
        return self.nextObject

    def getObjectOffset(self):
        return self.objectOffset

    def getObjectStream(self):
        return self.objectStream

    def getOffset(self):
        return self.offset

    def getType(self):
        return self.entryType

    def incGenNumber(self):
        self.genNumber += 1

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True

    def setGenNumber(self, newGenNumber):
        self.genNumber = newGenNumber

    def setIndexObject(self, index):
        self.indexObject = index

    def setNextObject(self, newNextObject):
        self.nextObject = newNextObject

    def setObjectOffset(self, newOffset):
        self.objectOffset = newOffset

    def setObjectStream(self, id):
        self.objectStream = id

    def setOffset(self, offset):
        self.offset = offset

    def setType(self, newType):
        self.entryType = newType

    def toFile(self):
        output = ''
        if self.entryType == 'n':
            ret = numToString(self.objectOffset, 10)
            if ret[0] != -1:
                output += ret[1]
        elif self.entryType == 'f':
            ret = numToString(self.nextObject, 10)
            if ret[0] != -1:
                output += ret[1]
        output += ' '
        ret = numToString(self.genNumber, 5)
        if ret[0] != -1:
            output += ret[1]
        output += ' '
        output += self.entryType
        if len(newLine) == 2:
            output += newLine
        else:
            output += ' ' + newLine
        return output


class PDFBody:
    def __init__(self):
        self.numObjects = 0  # int
        self.objects = {}  # PDFIndirectObjects{}
        self.numStreams = 0  # int
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.numURIs = 0
        self.streams = []
        self.nextOffset = 0
        self.encodedStreams = []
        self.faultyStreams = []
        self.faultyObjects = []
        self.referencedJSObjects = []
        self.containingJS = []
        self.containingURIs = []
        self.suspiciousEvents = {}
        self.suspiciousActions = {}
        self.suspiciousElements = {}
        self.vulns = {}
        self.javascriptCode = []
        self.javascriptCodePerObject = []
        self.URLs = []
        self.uriList = []
        self.uriListPerObject = []
        self.toUpdate = []
        self.xrefStreams = []
        self.objectStreams = []
        self.compressedObjects = []
        self.errors = []

    def addCompressedObject(self, id):
        if id not in self.compressedObjects:
            self.compressedObjects.append(id)

    def addObjectStream(self, id):
        if id not in self.objectStreams:
            self.objectStreams.append(id)

    def addXrefStream(self, id):
        if id not in self.xrefStreams:
            self.xrefStreams.append(id)

    def containsCompressedObjects(self):
        if len(self.compressedObjects) > 0:
            return True
        else:
            return False

    def containsObjectStreams(self):
        if len(self.objectStreams) > 0:
            return True
        else:
            return False

    def containsXrefStreams(self):
        if len(self.xrefStreams) > 0:
            return True
        else:
            return False

    def delObject(self, id):
        if id in self.objects:
            indirectObject = self.objects[id]
            return self.deregisterObject(indirectObject)
        else:
            return None

    def deregisterObject(self, pdfIndirectObject):
        type = ''
        errorMessage = ''
        if pdfIndirectObject is None:
            errorMessage = 'Indirect Object is None'
            log.error(errorMessage)
            return (-1, errorMessage)
        id = pdfIndirectObject.getId()
        if id in self.objects:
            self.objects.pop(id)
        pdfObject = pdfIndirectObject.getObject()
        if pdfObject is None:
            errorMessage = 'Object is None'
            log.error(errorMessage)
            return (-1, errorMessage)
        objectType = pdfObject.getType()
        self.numObjects -= 1
        if id in self.faultyObjects:
            self.faultyObjects.remove(id)
        self.updateStats(id, pdfObject, delete=True)
        if not pdfObject.updateNeeded:
            if objectType == 'stream':
                self.numStreams -= 1
                if id in self.streams:
                    self.streams.remove(id)
                if pdfObject.isEncoded():
                    if id in self.encodedStreams:
                        self.encodedStreams.remove(id)
                    self.numEncodedStreams -= 1
                    if id in self.faultyStreams:
                        self.faultyStreams.remove(id)
                        self.numDecodingErrors -= 1
                if pdfObject.hasElement('/Type'):
                    typeObject = pdfObject.getElementByName('/Type')
                    if typeObject is None:
                        errorMessage = '/Type element is None'
                        if isForceMode:
                            log.error(errorMessage)
                        else:
                            return (-1, errorMessage)
                    else:
                        type = typeObject.getValue()
                        if type == '/XRef':
                            if id in self.xrefStreams:
                                self.xrefStreams.remove(id)
                        elif type == '/ObjStm':
                            if id in self.objectStreams:
                                self.objectStreams.remove(id)
                            compressedObjectsDict = pdfObject.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                if compressedId in self.compressedObjects:
                                    self.compressedObjects.remove(compressedId)
                                self.delObject(compressedId)
                            del(compressedObjectsDict)
        objectErrors = pdfObject.getErrors()
        if objectErrors != []:
            index = 0
            errorsAux = list(self.errors)
            while True:
                if objectErrors[0] not in errorsAux:
                    break
                indexAux = errorsAux.index(objectErrors[0])
                if errorsAux[indexAux:indexAux+len(objectErrors)] == objectErrors:
                    for i in range(len(objectErrors)):
                        self.errors.pop(index+indexAux)
                    break
                else:
                    errorsAux = errorsAux[indexAux+len(objectErrors):]
                    index = indexAux+len(objectErrors)
        if type == '':
            type = objectType
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, type)

    def encodeChars(self):
        errorMessage = ''
        for id in self.objects:
            indirectObject = self.objects[id]
            if indirectObject is not None:
                object = indirectObject.getObject()
                if object is not None:
                    objectType = object.getType()
                    if objectType in ['string', 'name', 'array', 'dictionary', 'stream']:
                        ret = object.encodeChars()
                        if ret[0] == -1:
                            errorMessage = ret[1]
                            log.error(errorMessage)
                        indirectObject.setObject(object)
                        self.deregisterObject(indirectObject)
                        self.registerObject(indirectObject)
                else:
                    errorMessage = 'Bad object found while encoding strings'
                    log.error(errorMessage)
            else:
                errorMessage = 'Bad indirect object found while encoding strings'
                log.error(errorMessage)
        if errorMessage != '':
            # TODO return only the last error string...
            return (-1, errorMessage)
        return (0, '')

    def getCompressedObjects(self):
        return self.compressedObjects

    def getContainingJS(self):
        return self.containingJS

    def getContainingURIs(self):
        return self.containingURIs

    def getEncodedStreams(self):
        return self.encodedStreams

    def getFaultyObjects(self):
        return self.faultyObjects

    def getFaultyStreams(self):
        return self.faultyStreams

    def getIndirectObject(self, id):
        if id in self.objects:
            return self.objects[id]
        else:
            return None

    def getJSCode(self):
        return self.javascriptCode

    def getJSCodePerObject(self):
        return self.javascriptCodePerObject

    def getNextOffset(self):
        return self.nextOffset

    def getNumDecodingErrors(self):
        return self.numDecodingErrors

    def getNumEncodedStreams(self):
        return self.numEncodedStreams

    def getNumFaultyObjects(self):
        return len(self.faultyObjects)

    def getNumObjects(self):
        return self.numObjects

    def getNumStreams(self):
        return self.numStreams

    def getNumURIs(self):
        return len(self.uriList)

    def getObject(self, id, indirect=False):
        if id in self.objects:
            indirectObject = self.objects[id]
            if indirect:
                return indirectObject
            else:
                return indirectObject.getObject()
        else:
            return None

    def getObjects(self):
        return self.objects

    def getObjectsByString(self, toSearch):
        matchedObjects = []
        for indirectObject in self.objects.values():
            if indirectObject.contains(toSearch):
                matchedObjects.append(indirectObject.getId())
        return matchedObjects

    def getObjectsIds(self):
        sortedIdsOffsets = []
        sortedIds = []
        for indirectObject in self.objects.values():
            sortedIdsOffsets.append([indirectObject.getId(), indirectObject.getOffset()])
        sortedIdsOffsets = sorted(sortedIdsOffsets, key=lambda x: x[1])
        for i in range(len(sortedIdsOffsets)):
            sortedIds.append(sortedIdsOffsets[i][0])
        return sortedIds

    def getObjectStreams(self):
        return self.objectStreams

    def getStreams(self):
        return self.streams

    def getSuspiciousActions(self):
        return self.suspiciousActions

    def getSuspiciousElements(self):
        return self.suspiciousElements

    def getSuspiciousEvents(self):
        return self.suspiciousEvents

    def getURIs(self):
        return self.uriList

    def getURIsPerObject(self):
        return self.uriListPerObject

    def getURLs(self):
        return self.URLs

    def getVulns(self):
        return self.vulns

    def getXrefStreams(self):
        return self.xrefStreams

    def registerObject(self, pdfIndirectObject):
        type = ''
        errorMessage = ''
        if pdfIndirectObject is None:
            errorMessage = 'Indirect Object is None'
            log.error(errorMessage)
            return (-1, errorMessage)
        id = pdfIndirectObject.getId()
        pdfObject = pdfIndirectObject.getObject()
        if pdfObject is None:
            errorMessage = 'Object is None'
            log.error(errorMessage)
            return (-1, errorMessage)
        objectType = pdfObject.getType()
        self.numObjects += 1
        if pdfObject.isFaulty():
            self.faultyObjects.append(id)
        ret = self.updateStats(id, pdfObject)
        if ret[0] == -1:
            errorMessage = ret[1]
        if pdfObject.updateNeeded:
            self.toUpdate.append(id)
        else:
            if objectType == 'stream':
                self.numStreams += 1
                self.streams.append(id)
                if pdfObject.isEncoded():
                    self.encodedStreams.append(id)
                    self.numEncodedStreams += 1
                    if pdfObject.isFaultyDecoding():
                        self.faultyStreams.append(id)
                        self.numDecodingErrors += 1
                if pdfObject.hasElement('/Type'):
                    typeObject = pdfObject.getElementByName('/Type')
                    if typeObject is None:
                        errorMessage = '/Type element is None'
                        if isForceMode:
                            log.error(errorMessage)
                        else:
                            return (-1, errorMessage)
                    else:
                        type = typeObject.getValue()
                        if type == '/XRef':
                            self.addXrefStream(id)
                        elif type == '/ObjStm':
                            self.addObjectStream(id)
                            pdfObject.setCompressedObjectId(id)
                            compressedObjectsDict = pdfObject.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                self.addCompressedObject(compressedId)
                                offset = compressedObjectsDict[compressedId][0]
                                compressedObject = compressedObjectsDict[compressedId][1]
                                self.setObject(compressedId, compressedObject, offset)
                            del(compressedObjectsDict)
            elif objectType == 'dictionary':
                self.referencedJSObjects += pdfObject.getReferencedJSObjectIds()
                self.referencedJSObjects = list(set(self.referencedJSObjects))
        pdfIndirectObject.setObject(pdfObject)
        self.objects[id] = pdfIndirectObject
        self.errors += pdfObject.getErrors()
        if type == '':
            type = objectType
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, type)

    def setNextOffset(self, newOffset):
        self.nextOffset = newOffset

    def setObject(self, id=None, object=None, offset=None, modification=False):
        errorMessage = ''
        if id in self.objects:
            pdfIndirectObject = self.objects[id]
            self.deregisterObject(pdfIndirectObject)
            pdfIndirectObject.setObject(object)
            if offset is not None:
                pdfIndirectObject.setOffset(offset)
            size = 12 + 3*len(newLine) + len(str(object.getRawValue())) + len(str(id))
            pdfIndirectObject.setSize(size)
        else:
            if modification:
                errorMessage = 'Object not found'
                if isForceMode:
                    log.error(errorMessage)
                else:
                    return (-1, errorMessage)
            if id is None:
                id = self.numObjects+1
            if offset is None:
                offset = self.getNextOffset()
            pdfIndirectObject = PDFIndirectObject()
            pdfIndirectObject.setId(id)
            pdfIndirectObject.setObject(object)
            pdfIndirectObject.setGenerationNumber(0)
            pdfIndirectObject.setOffset(offset)
            size = 12 + 3*len(newLine) + len(str(object.getRawValue())) + len(str(id))
            pdfIndirectObject.setSize(size)
            self.setNextOffset(offset+size)
        ret = self.registerObject(pdfIndirectObject)
        if ret[0] == 0:
            if errorMessage != '':
                return (-1, errorMessage)
            else:
                objectType = ret[1]
                return (0, [id, objectType])
        else:
            return ret

    def setObjects(self, objects):
        self.objects = objects

    def updateObjects(self):
        errorMessage = ''
        for id in self.toUpdate:
            updatedElements = {}
            object = self.objects[id].getObject()
            if object is None:
                errorMessage = 'Object is None'
                if isForceMode:
                    log.error(errorMessage)
                    continue
                else:
                    return (-1, errorMessage)
            elementsToUpdate = object.getReferencesInElements()
            keys = elementsToUpdate.keys()
            for key in keys:
                ref = elementsToUpdate[key]
                refId = ref[0]
                if refId in self.objects:
                    refObject = self.objects[refId].getObject()
                    if refObject is None:
                        errorMessage = 'Referenced object is None'
                        if isForceMode:
                            log.error(errorMessage)
                            continue
                        else:
                            return (-1, errorMessage)
                    ref[1] = refObject.getValue()
                    updatedElements[key] = ref
                else:
                    errorMessage = 'Referenced object not found'
                    if isForceMode:
                        log.error(errorMessage)
                        continue
                    else:
                        return (-1, errorMessage)
            object.setReferencesInElements(updatedElements)
            object.resolveReferences()
            self.updateStats(id, object)
            if object.getType() == 'stream':
                self.numStreams += 1
                self.streams.append(id)
                if object.isEncoded():
                    self.encodedStreams.append(id)
                    self.numEncodedStreams += 1
                    if object.isFaultyDecoding():
                        self.faultyStreams.append(id)
                        self.numDecodingErrors += 1
                if object.hasElement('/Type'):
                    typeObject = object.getElementByName('/Type')
                    if typeObject is None:
                        errorMessage = 'Referenced element is None'
                        if isForceMode:
                            log.error(errorMessage)
                            continue
                        else:
                            return (-1, errorMessage)
                    else:
                        type = typeObject.getValue()
                        if type == '/XRef':
                            self.addXrefStream(id)
                        elif type == '/ObjStm':
                            self.addObjectStream(id)
                            object.setCompressedObjectId(id)
                            compressedObjectsDict = object.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                self.addCompressedObject(compressedId)
                                offset = compressedObjectsDict[compressedId][0]
                                compressedObject = compressedObjectsDict[compressedId][1]
                                self.setObject(compressedId, compressedObject, offset)
                            del(compressedObjectsDict)
        for id in self.referencedJSObjects:
            if id not in self.containingJS:
                object = self.objects[id].getObject()
                if object is None:
                    errorMessage = 'Object is None'
                    if isForceMode:
                        log.error(errorMessage)
                        continue
                    else:
                        return (-1, errorMessage)
                object.setReferencedJSObject(True)
                self.updateStats(id, object)
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, '')

    def updateOffsets(self):
        pass

    def updateStats(self, id, pdfObject, delete=False):
        if pdfObject is None:
            errorMessage = 'Object is None'
            log.error(errorMessage)
            return (-1, errorMessage)
        value = pdfObject.getValue()
        for event in monitorizedEvents:
            if value.find(event) != -1:
                printedEvent = event.strip()
                if printedEvent in self.suspiciousEvents:
                    if delete:
                        if id in self.suspiciousEvents[printedEvent]:
                            self.suspiciousEvents[printedEvent].remove(id)
                    elif id not in self.suspiciousEvents[printedEvent]:
                        self.suspiciousEvents[printedEvent].append(id)
                elif not delete:
                    self.suspiciousEvents[printedEvent] = [id]
        for action in monitorizedActions:
            index = value.find(action)
            if index != -1 and (action == '/JS ' or len(value) == index + len(action) or value[index+len(action)] in delimiterChars+spacesChars):
                printedAction = action.strip()
                if printedAction in self.suspiciousActions:
                    if delete:
                        if id in self.suspiciousActions[printedAction]:
                            self.suspiciousActions[printedAction].remove(id)
                    elif id not in self.suspiciousActions[printedAction]:
                        self.suspiciousActions[printedAction].append(id)
                elif not delete:
                    self.suspiciousActions[printedAction] = [id]
        for element in monitorizedElements:
            index = value.find(element)
            if index != -1 and (element == '/EmbeddedFiles ' or len(value) == index + len(element) or value[index+len(element)] in delimiterChars+spacesChars):
                printedElement = element.strip()
                if printedElement in self.suspiciousElements:
                    if delete:
                        if id in self.suspiciousElements[printedElement]:
                            self.suspiciousElements[printedElement].remove(id)
                    elif id not in self.suspiciousElements[printedElement]:
                        self.suspiciousElements[printedElement].append(id)
                elif not delete:
                    self.suspiciousElements[printedElement] = [id]
        if pdfObject.containsJS():
            if delete:
                jsCodeArray = pdfObject.getJSCode()
                if id in self.containingJS:
                    self.containingJS.remove(id)
                    for jsCode in jsCodeArray:
                        if jsCode in self.javascriptCode:
                            self.javascriptCode.remove(jsCode)
                            if [id, jsCode] in self.javascriptCodePerObject:
                                self.javascriptCodePerObject.remove([id, jsCode])
                        for vuln in jsVulns:
                            if jsCode.find(vuln) != -1:
                                if vuln in self.vulns and id in self.vulns[vuln]:
                                    self.vulns[vuln].remove(id)
            else:
                jsCode = pdfObject.getJSCode()
                if id not in self.containingJS:
                    self.containingJS.append(id)
                for js in jsCode:
                    if js not in self.javascriptCode:
                        self.javascriptCode.append(js)
                        if [id, js] not in self.javascriptCodePerObject:
                            self.javascriptCodePerObject.append([id, js])
                for code in jsCode:
                    for vuln in jsVulns:
                        if code.find(vuln) != -1:
                            if vuln in self.vulns:
                                self.vulns[vuln].append(id)
                            else:
                                self.vulns[vuln] = [id]
        if pdfObject.containsURIs():
            uris = pdfObject.getURIs()
            if delete:
                if id in self.containingURIs:
                    self.containingURIs.remove(id)
                    for uri in uris:
                        if uri in self.uriList:
                            self.uriList.remove(uri)
                            if [id, uri] in self.uriListPerObject:
                                self.uriListPerObject.remove([id, uri])
            else:
                if id not in self.containingURIs:
                    self.containingURIs.append(id)
                for uri in uris:
                    self.uriList.append(uri)
                    if [id, uri] not in self.uriListPerObject:
                        self.uriListPerObject.append([id, uri])
        # Extra checks
        objectType = pdfObject.getType()
        if objectType == 'stream':
            vulnFound = None
            streamContent = pdfObject.getStream()
            if len(streamContent) > 327 and streamContent[236:240] == 'SING' and streamContent[327] != '\0':
                # CVE-2010-2883
                # http://opensource.adobe.com/svn/opensource/tin/src/SING.cpp
                # http://community.websense.com/blogs/securitylabs/archive/2010/09/10/brief-analysis-on-adobe-reader-sing-table-parsing-vulnerability-cve-2010-2883.aspx
                vulnFound = singUniqueName
            elif streamContent.count('AAL/AAAC/wAAAv8A') > 1000:
                # CVE-2013-2729
                # Adobe Reader BMP/RLE heap corruption
                # http://blog.binamuse.com/2013/05/readerbmprle.html
                vulnFound = bmpVuln
            if vulnFound is not None:
                if vulnFound in self.suspiciousElements:
                    if delete:
                        if id in self.suspiciousElements[vulnFound]:
                            self.suspiciousElements[vulnFound].remove(id)
                    elif id not in self.suspiciousElements[vulnFound]:
                        self.suspiciousElements[vulnFound].append(id)
                elif not delete:
                    self.suspiciousElements[vulnFound] = [id]
        return (0, '')


class PDFFile:
    def __init__(self):
        self.fileName = ''
        self.path = ''
        self.size = 0
        self.md5 = ''
        self.sha1 = ''
        self.sha256 = ''
        self.detectionRate = []
        self.detectionReport = ''
        self.body = []  # PDFBody[]
        self.binary = False
        self.binaryChars = ''
        self.linearized = False
        self.encryptDict = None
        self.encrypted = False
        self.fileId = ''
        self.encryptionAlgorithms = []
        self.encryptionKey = ''
        self.encryptionKeyLength = 128
        self.ownerPass = ''
        self.userPass = ''
        self.JSCode = ''
        self.crossRefTable = []  # PDFCrossRefSection[]
        self.comments = []  # string[]
        self.version = ''
        self.headerOffset = 0
        self.garbageHeader = ''
        self.suspiciousElements = {}
        self.updates = 0
        self.endLine = ''
        self.trailer = []  # PDFTrailer[]
        self.errors = []
        self.numObjects = 0
        self.numStreams = 0
        self.numURIs = 0
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.maxObjectId = 0

    def getVtInfo(self, vt_key):
        ret = vtcheck(self.getMD5(), vt_key)
        if ret[0] == -1:
            self.addError(ret[1])
        else:
            self.parseVtReport(ret[1])

    def parseVtReport(self, vtJsonDict):
        if vtJsonDict.has_key('response_code'):
            if vtJsonDict['response_code'] == 1:
                if vtJsonDict.has_key('positives') and vtJsonDict.has_key('total'):
                    self.setDetectionRate([vtJsonDict['positives'], vtJsonDict['total']])
                else:
                    self.addError('Missing elements in the response from VirusTotal!!')
                if vtJsonDict.has_key('permalink'):
                    self.setDetectionReport(vtJsonDict['permalink'])
            else:
                self.setDetectionRate(None)
        else:
            self.addError('Bad response from VirusTotal!!')

    def addBody(self, newBody):
        if newBody is not None and isinstance(newBody, PDFBody):
            self.body.append(newBody)
            return (0, '')
        else:
            return (-1, 'Bad PDFBody supplied')

    def addCrossRefTableSection(self, newSectionArray):
        if newSectionArray is not None and isinstance(newSectionArray, list) and len(newSectionArray) == 2 and (newSectionArray[0] is None or isinstance(newSectionArray[0], PDFCrossRefSection)) and (newSectionArray[1] is None or isinstance(newSectionArray[1], PDFCrossRefSection)):
            self.crossRefTable.append(newSectionArray)
            return (0, '')
        else:
            return (-1, 'Bad PDFCrossRefSection array supplied')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def addNumDecodingErrors(self, num):
        self.numDecodingErrors += num

    def addNumEncodedStreams(self, num):
        self.numEncodedStreams += num

    def addNumObjects(self, num):
        self.numObjects += num

    def addNumStreams(self, num):
        self.numStreams += num

    def addNumURIs(self, num):
        self.numURIs += num

    def addTrailer(self, newTrailerArray):
        if newTrailerArray is not None and isinstance(newTrailerArray, list) and len(newTrailerArray) == 2 and (newTrailerArray[0] is None or isinstance(newTrailerArray[0], PDFTrailer)) and (newTrailerArray[1] is None or isinstance(newTrailerArray[1], PDFTrailer)):
            self.trailer.append(newTrailerArray)
            return (0, '')
        else:
            return (-1, 'Bad PDFTrailer array supplied')

    def createObjectStream(self, version=None, id=None, objectIds=[]):
        errorMessage = ''
        tmpStreamObjects = ''
        tmpStreamObjectsInfo = ''
        compressedStream = ''
        compressedDict = {}
        firstObjectOffset = ''
        if version is None:
            version = self.updates
        if objectIds == []:
            objectIds = self.body[version].getObjectsIds()
        numObjects = len(objectIds)
        if id is None:
            id = self.maxObjectId + 1
        for compressedId in objectIds:
            object = self.body[version].getObject(compressedId)
            if object is None:
                errorMessage = 'Object '+str(compressedId)+' cannot be compressed: it does not exist'
                if isForceMode:
                    self.addError(errorMessage)
                    numObjects -= 1
                else:
                    return (-1, errorMessage)
            else:
                objectType = object.getType()
                if objectType == 'stream':
                    errorMessage = 'Stream objects cannot be compressed'
                    self.addError(errorMessage)
                    numObjects -= 1
                else:
                    if objectType == 'dictionary' and object.hasElement('/U') and object.hasElement('/O') and object.hasElement('/R'):
                        errorMessage = 'Encryption dictionaries cannot be compressed'
                        self.addError(errorMessage)
                        numObjects -= 1
                    object.setCompressedIn(id)
                    offset = len(tmpStreamObjects)
                    tmpStreamObjectsInfo += str(compressedId)+' '+str(offset)+' '
                    tmpStreamObjects += object.toFile()
                    ret = self.body[version].setObject(compressedId, object, offset, modification=True)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(ret[1])
        firstObjectOffset = str(len(tmpStreamObjectsInfo))
        compressedStream = tmpStreamObjectsInfo + tmpStreamObjects
        compressedDict = {
            '/Type': PDFName('ObjStm'),
            '/N': PDFNum(str(numObjects)),
            '/First': PDFNum(firstObjectOffset),
            '/Length': PDFNum(str(len(compressedStream)))
        }
        try:
            objectStream = PDFObjectStream('', compressedStream, compressedDict, {}, {})
        except Exception as e:
            errorMessage = 'Error creating PDFObjectStream'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1, errorMessage)
        # Filters
        filterObject = PDFName('FlateDecode')
        ret = objectStream.setElement('/Filter', filterObject)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        objectStreamOffset = self.body[version].getNextOffset()
        if self.encrypted:
            ret = computeObjectKey(id, 0, self.encryptionKey, self.encryptionKeyLength/8)
            if ret[0] == -1:
                errorMessage = ret[1]
                self.addError(ret[1])
            else:
                key = ret[1]
                ret = objectStream.encrypt(key)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(ret[1])
        self.body[version].setNextOffset(objectStreamOffset+len(objectStream.getRawValue()))
        self.body[version].setObject(id, objectStream, objectStreamOffset)
        # Xref stream
        ret = self.createXrefStream(version)
        if ret[0] == -1:
            return ret
        xrefStreamId, xrefStream = ret[1]
        xrefStreamOffset = self.body[version].getNextOffset()
        ret = self.body[version].setObject(xrefStreamId, xrefStream, xrefStreamOffset)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        self.binary = True
        self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, id)

    def createXrefStream(self, version, id=None):
        size = 0
        elementsDict = {}
        elementsTrailerDict = {}
        stream = ''
        errorMessage = ''
        indexArray = []
        xrefStream = None
        xrefStreamId = None
        bytesPerFieldArray = []

        if version is None:
            version = self.updates
        # Trailer update
        if len(self.trailer) > version:
            if self.trailer[version][1] is not None:
                trailerDict = self.trailer[version][1].getTrailerDictionary()
                if trailerDict is not None:
                    elementsTrailerDict = dict(trailerDict.getElements())
                    elementsDict = dict(elementsTrailerDict)
                del(trailerDict)
            if self.trailer[version][0] is not None:
                trailerDict = self.trailer[version][0].getTrailerDictionary()
                if trailerDict is not None:
                    trailerElementsDict = dict(trailerDict.getElements())
                    if len(trailerElementsDict) > 0:
                        for key in trailerElementsDict:
                            if key not in elementsTrailerDict:
                                elementsTrailerDict[key] = trailerElementsDict[key]
                                elementsDict[key] = trailerElementsDict[key]
                    del(trailerElementsDict)
                del(trailerDict)
        self.createXrefStreamSection(version)
        if len(self.crossRefTable) <= version:
            errorMessage = 'Cross Reference Table not found'
            self.addError(errorMessage)
            return (-1, errorMessage)
        section = self.crossRefTable[version][1]
        xrefStreamId = section.getXrefStreamObject()
        bytesPerField = section.getBytesPerField()
        for num in bytesPerField:
            try:
                bytesPerFieldArray.append(PDFNum(str(num)))
            except:
                errorMessage = 'Error creating PDFNum in bytesPerField'
                return (-1, errorMessage)
        subsections = section.getSubsectionsArray()
        for subsection in subsections:
            firstObject = subsection.getFirstObject()
            numObjects = subsection.getNumObjects()
            indexArray.append(PDFNum(str(firstObject)))
            indexArray.append(PDFNum(str(numObjects)))
            entries = subsection.getEntries()
            for entry in entries:
                ret = entry.getEntryBytes(bytesPerField)
                if ret[0] == -1:
                    self.addError(ret[1])
                    return (-1, ret[1])
                stream += ret[1]
            if size < firstObject + numObjects:
                size = firstObject + numObjects
        elementsDict['/Type'] = PDFName('XRef')
        elementsDict['/Size'] = PDFNum(str(size))
        elementsTrailerDict['/Size'] = PDFNum(str(size))
        elementsDict['/Index'] = PDFArray('', indexArray)
        elementsDict['/W'] = PDFArray('', bytesPerFieldArray)
        elementsDict['/Length'] = PDFNum(str(len(stream)))
        try:
            xrefStream = PDFStream('', stream, elementsDict, {})
        except Exception as e:
            errorMessage = 'Error creating PDFStream'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1, errorMessage)
        # Filters
        filterObject = PDFName('FlateDecode')
        if id is not None:
            xrefStreamObject = self.getObject(id, version)
            if xrefStreamObject is not None:
                filterObject = xrefStreamObject.getElementByName('/Filter')
        ret = xrefStream.setElement('/Filter', filterObject)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        try:
            trailerStream = PDFTrailer(PDFDictionary(elements=elementsTrailerDict))
        except Exception as e:
            errorMessage = 'Error creating PDFTrailer'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1, errorMessage)
        trailerStream.setXrefStreamObject(xrefStreamId)
        try:
            trailerSection = PDFTrailer(PDFDictionary(elements=dict(elementsTrailerDict)))  # PDFDictionary())
        except Exception as e:
            errorMessage = 'Error creating PDFTrailer'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1, errorMessage)
        self.trailer[version] = [trailerSection, trailerStream]
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, [xrefStreamId, xrefStream])

    def createXrefStreamSection(self, version=None):
        lastId = 0
        lastFreeObject = 0
        errorMessage = ''
        xrefStreamId = None
        xrefEntries = [PDFCrossRefEntry(0, 65535, 0)]
        if version is None:
            version = self.updates
        actualStream = self.crossRefTable[version][1]
        if actualStream is not None:
            xrefStreamId = actualStream.getXrefStreamObject()
        sortedObjectsByOffset = self.body[version].getObjectsIds()
        sortedObjectsIds = sorted(sortedObjectsByOffset, key=lambda x: int(x))
        indirectObjects = self.body[version].getObjects()
        for id in sortedObjectsIds:
            while id != lastId+1:
                lastFreeEntry = xrefEntries[lastFreeObject]
                lastFreeEntry.setNextObject(lastId+1)
                xrefEntries[lastFreeObject] = lastFreeEntry
                lastFreeObject = lastId+1
                lastId += 1
                xrefEntries.append(PDFCrossRefEntry(0, 65535, 0))
            indirectObject = indirectObjects[id]
            if indirectObject is not None:
                object = indirectObject.getObject()
                if object is not None:
                    if object.isCompressed():
                        objectStreamId = object.getCompressedIn()
                        objectStream = self.body[version].getObject(objectStreamId)
                        index = objectStream.getObjectIndex(id)
                        if index is None:
                            errorMessage = 'Compressed object not found in object stream'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        entry = PDFCrossRefEntry(objectStreamId, index, 2)
                    else:
                        offset = indirectObject.getOffset()
                        entry = PDFCrossRefEntry(offset, 0, 1)
                    xrefEntries.append(entry)
                    lastId = id
        if actualStream is None:
            offset += len(str(object.getRawValue()))
            xrefEntries.append(PDFCrossRefEntry(offset, 0, 1))
            lastId += 1
            xrefStreamId = lastId
        subsection = PDFCrossRefSubSection(0, lastId+1, xrefEntries)
        xrefSection = PDFCrossRefSection()
        xrefSection.addSubsection(subsection)
        xrefSection.setXrefStreamObject(xrefStreamId)
        xrefSection.setBytesPerField([1, 2, 2])
        self.crossRefTable[version] = [None, xrefSection]
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, lastId)

    def decrypt(self, password=''):
        badPassword = False
        fatalError = False
        errorMessage = ''
        passType = None
        encryptionAlgorithms = []
        algorithm = None
        stmAlgorithm = None
        strAlgorithm = None
        embedAlgorithm = None
        computedUserPass = ''
        dictO = ''
        dictU = ''
        perm = 0
        revision = 0
        fileId = self.getFileId()
        self.removeError(errorType='Decryption error')
        if self.encryptDict is None or self.encryptDict[1] == []:
            errorMessage = 'Decryption error: /Encrypt dictionary not found!!'
            if isForceMode:
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Getting /Encrypt elements
        encDict = self.encryptDict[1]
        # Filter
        if '/Filter' in encDict:
            filter = encDict['/Filter']
            if filter is not None and filter.getType() == 'name':
                filter = filter.getValue()
                if filter != '/Standard':
                    errorMessage = 'Decryption error: Filter not supported!!'
                    if isForceMode:
                        fatalError = True
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            else:
                errorMessage = 'Decryption error: Bad format for /Filter!!'
                if isForceMode:
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Filter not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Algorithm version
        if "/V" in encDict:
            algVersion = encDict['/V']
            if algVersion is not None and algVersion.getType() == 'integer':
                algVersion = algVersion.getRawValue()
                if algVersion == 4 or algVersion == 5:
                    stmAlgorithm = ['Identity', 40]
                    strAlgorithm = ['Identity', 40]
                    embedAlgorithm = ['Identity', 40]
                    algorithms = {}
                    if "/CF" in encDict:
                        cfDict = encDict['/CF']
                        if cfDict is not None and cfDict.getType() == 'dictionary':
                            cfDict = cfDict.getElements()
                            for cryptFilter in cfDict:
                                cryptFilterDict = cfDict[cryptFilter]
                                if cryptFilterDict is not None and cryptFilterDict.getType() == 'dictionary':
                                    algorithms[cryptFilter] = []
                                    defaultKeyLength = 40
                                    cfmValue = ''
                                    cryptFilterDict = cryptFilterDict.getElements()
                                    if "/CFM" in cryptFilterDict:
                                        cfmValue = cryptFilterDict['/CFM']
                                        if cfmValue is not None and cfmValue.getType() == 'name':
                                            cfmValue = cfmValue.getValue()
                                            if cfmValue == 'None':
                                                algorithms[cryptFilter].append('Identity')
                                            elif cfmValue == '/V2':
                                                algorithms[cryptFilter].append('RC4')
                                            elif cfmValue == '/AESV2':
                                                algorithms[cryptFilter].append('AES')
                                                defaultKeyLength = 128
                                            elif cfmValue == '/AESV3':
                                                algorithms[cryptFilter].append('AES')
                                                defaultKeyLength = 256
                                            else:
                                                errorMessage = 'Decryption error: Unsupported encryption!!'
                                                if isForceMode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1, errorMessage)
                                        else:
                                            errorMessage = 'Decryption error: Bad format for /CFM!!'
                                            if isForceMode:
                                                cfmValue = ''
                                                self.addError(errorMessage)
                                            else:
                                                return (-1, errorMessage)
                                    if "/Length" in cryptFilterDict and cfmValue != '/AESV3':
                                        # Length is key length in bits
                                        keyLength = cryptFilterDict['/Length']
                                        if keyLength is not None and keyLength.getType() == 'integer':
                                            keyLength = keyLength.getRawValue()
                                            if keyLength % 8 != 0:
                                                keyLength = defaultKeyLength
                                                self.addError('Decryption error: Key length not valid!!')
                                            # Check if the length element contains bytes instead of bits as usual
                                            if keyLength < 40:
                                                keyLength *= 8
                                        else:
                                            keyLength = defaultKeyLength
                                            self.addError('Decryption error: Bad format for /Length!!')
                                    else:
                                        keyLength = defaultKeyLength
                                    algorithms[cryptFilter].append(keyLength)
                        else:
                            errorMessage = 'Decryption error: Bad format for /CF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if "/StmF" in encDict:
                        stmF = encDict['/StmF']
                        if stmF is not None and stmF.getType() == 'name':
                            stmF = stmF.getValue()
                            if stmF in algorithms:
                                stmAlgorithm = algorithms[stmF]
                        else:
                            errorMessage = 'Decryption error: Bad format for /StmF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if "/StrF" in encDict:
                        strF = encDict['/StrF']
                        if strF is not None and strF.getType() == 'name':
                            strF = strF.getValue()
                            if strF in algorithms:
                                strAlgorithm = algorithms[strF]
                        else:
                            errorMessage = 'Decryption error: Bad format for /StrF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if "/EEF" in encDict:
                        eeF = encDict['/EEF']
                        if eeF is not None and eeF.getType() == 'name':
                            eeF = eeF.getValue()
                            if eeF in algorithms:
                                embedAlgorithm = algorithms[eeF]
                        else:
                            embedAlgorithm = stmAlgorithm
                            errorMessage = 'Decryption error: Bad format for /EEF!!'
                            if isForceMode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    else:
                        embedAlgorithm = stmAlgorithm
                    if stmAlgorithm not in encryptionAlgorithms:
                        encryptionAlgorithms.append(stmAlgorithm)
                    if strAlgorithm not in encryptionAlgorithms:
                        encryptionAlgorithms.append(strAlgorithm)
                    if embedAlgorithm not in encryptionAlgorithms and embedAlgorithm != ['Identity', 40]:  # Not showing default embedAlgorithm
                        encryptionAlgorithms.append(embedAlgorithm)
            else:
                errorMessage = 'Decryption error: Bad format for /V!!'
                if isForceMode:
                    algVersion = 0
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Algorithm version not found!!'
            if isForceMode:
                algVersion = 0
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)

        # Key length
        if "/Length" in encDict:
            keyLength = encDict['/Length']
            if keyLength is not None and keyLength.getType() == 'integer':
                keyLength = keyLength.getRawValue()
                if keyLength % 8 != 0:
                    keyLength = 40
                    self.addError('Decryption error: Key length not valid!!')
            else:
                keyLength = 40
                self.addError('Decryption error: Bad format for /Length!!')
        else:
            keyLength = 40

        # Setting algorithms
        if algVersion == 1 or algVersion == 2:
            algorithm = ['RC4', keyLength]
            stmAlgorithm = strAlgorithm = embedAlgorithm = algorithm
        elif algVersion == 3:
            errorMessage = 'Decryption error: Algorithm not supported!!'
            if isForceMode:
                algorithm = ['Unpublished', keyLength]
                stmAlgorithm = strAlgorithm = embedAlgorithm = algorithm
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        elif algVersion == 5:
            algorithm = ['AES', 256]
        if algorithm is not None and algorithm not in encryptionAlgorithms:
            encryptionAlgorithms.append(algorithm)
        self.setEncryptionAlgorithms(encryptionAlgorithms)

        # Standard encryption: /R /P /O /U
        # Revision
        if "/R" in encDict:
            revision = encDict['/R']
            if revision is not None and revision.getType() == 'integer':
                revision = revision.getRawValue()
                if revision < 2 or revision > 5:
                    errorMessage = 'Decryption error: Algorithm revision not supported!!'
                    if isForceMode:
                        fatalError = True
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            else:
                errorMessage = 'Decryption error: Bad format for /R!!'
                if isForceMode:
                    revision = 0
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Algorithm revision not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Permission
        if "/P" in encDict:
            perm = encDict['/P']
            if perm is not None and perm.getType() == 'integer':
                perm = perm.getRawValue()
            else:
                errorMessage = 'Decryption error: Bad format for /P!!'
                if isForceMode:
                    perm = 0
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Permission number not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Owner pass
        if "/O" in encDict:
            dictO = encDict['/O']
            if dictO is not None and dictO.getType() in ['string', 'hexstring']:
                dictO = dictO.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /O!!'
                if isForceMode:
                    dictO = ''
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Owner password not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Owner encrypted string
        if "/OE" in encDict:
            dictOE = encDict['/OE']
            if dictOE is not None and dictOE.getType() in ['string', 'hexstring']:
                dictOE = dictOE.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /OE!!'
                if isForceMode:
                    dictOE = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            dictOE = ''
            if revision == 5:
                errorMessage = 'Decryption error: /OE not found!!'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        # User pass
        if "/U" in encDict:
            dictU = encDict['/U']
            if dictU is not None and dictU.getType() in ['string', 'hexstring']:
                dictU = dictU.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /U!!'
                if isForceMode:
                    dictU = ''
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: User password not found!!'
            if isForceMode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # User encrypted string
        if "/UE" in encDict:
            dictUE = encDict['/UE']
            if dictUE is not None and dictUE.getType() in ['string', 'hexstring']:
                dictUE = dictUE.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /UE!!'
                if isForceMode:
                    dictUE = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            dictUE = ''
            if revision == 5:
                errorMessage = 'Decryption error: /UE not found!!'
                if isForceMode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        # Metadata encryption
        if "/EncryptMetadata" in encDict:
            encryptMetadata = encDict['/EncryptMetadata']
            if encryptMetadata is not None and encryptMetadata.getType() == 'bool':
                encryptMetadata = encryptMetadata.getValue() != 'false'
            else:
                errorMessage = 'Decryption error: Bad format for /EncryptMetadata!!'
                if isForceMode:
                    encryptMetadata = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            encryptMetadata = True
        if not fatalError:
            # Checking user password
            if revision != 5:
                ret = computeUserPass(password, dictO, fileId, perm, keyLength, revision, encryptMetadata)
                if ret[0] != -1:
                    computedUserPass = ret[1]
                else:
                    errorMessage = ret[1]
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            if isUserPass(password, computedUserPass, dictU, revision):
                passType = 'USER'
            elif isOwnerPass(password, dictO, dictU, computedUserPass, keyLength, revision):
                passType = 'OWNER'
            else:
                badPassword = True
                if password == '':
                    errorMessage = 'Decryption error: Default user password not working here!!'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                else:
                    errorMessage = 'Decryption error: User password not working here!!'
                    if isForceMode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
        self.setOwnerPass(dictO)
        self.setUserPass(dictU)
        if not fatalError and not badPassword:
            ret = computeEncryptionKey(password, dictO, dictU, dictOE, dictUE, fileId, perm, keyLength, revision, encryptMetadata, passType)
            if ret[0] != -1:
                encryptionKey = ret[1]
            else:
                errorMessage = ret[1]
                if isForceMode:
                    encryptionKey = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
            self.setEncryptionKey(encryptionKey)
            self.setEncryptionKeyLength(keyLength)
            # Computing objects passwords and decryption
            numKeyBytes = self.encryptionKeyLength/8
            for v in range(self.updates+1):
                indirectObjectsIds = list(set(self.body[v].getObjectsIds()))
                for id in indirectObjectsIds:
                    indirectObject = self.body[v].getObject(id, indirect=True)
                    if indirectObject is not None:
                        generationNum = indirectObject.getGenerationNumber()
                        object = indirectObject.getObject()
                        if object is not None and not object.isCompressed():
                            objectType = object.getType()
                            if objectType in ['string', 'hexstring', 'array', 'dictionary'] or \
                                    (objectType == 'stream' and (object.getElement('/Type') is None or
                                                                 (object.getElement('/Type').getValue() not in ['/XRef', '/Metadata'] or
                                                                  (object.getElement('/Type').getValue() == '/Metadata' and encryptMetadata)))):
                                key = self.encryptionKey
                                # Removing already set global stats before modifying the object contents
                                self.body[v].updateStats(id, object, delete=True)
                                # Computing keys and decrypting objects
                                if objectType in ['string', 'hexstring', 'array', 'dictionary']:
                                    if revision < 5:
                                        ret = computeObjectKey(id, generationNum, self.encryptionKey, numKeyBytes, strAlgorithm[0])
                                        if ret[0] == -1:
                                            errorMessage = ret[1]
                                            self.addError(ret[1])
                                        else:
                                            key = ret[1]
                                    ret = object.decrypt(key, strAlgorithm[0])
                                else:
                                    if object.getElement('/Type') is not None and object.getElement('/Type').getValue() == '/EmbeddedFile':
                                        if revision < 5:
                                            ret = computeObjectKey(id, generationNum, self.encryptionKey, numKeyBytes, embedAlgorithm[0])
                                            if ret[0] == -1:
                                                errorMessage = ret[1]
                                                self.addError(ret[1])
                                            else:
                                                key = ret[1]
                                        altAlgorithm = embedAlgorithm[0]
                                    else:
                                        if revision < 5:
                                            ret = computeObjectKey(id, generationNum, self.encryptionKey, numKeyBytes, stmAlgorithm[0])
                                            if ret[0] == -1:
                                                errorMessage = ret[1]
                                                self.addError(ret[1])
                                            else:
                                                key = ret[1]
                                        altAlgorithm = stmAlgorithm[0]
                                    ret = object.decrypt(key, strAlgorithm[0], altAlgorithm)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
                                ret = self.body[v].setObject(id, object)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, '')

    def deleteObject(self, id):
        # Remove references too
        pass

    def encodeChars(self):
        errorMessage = ''
        for i in range(self.updates+1):
            ret = self.body[i].encodeChars()
            if ret[0] == -1:
                errorMessage = ret[1]
                self.addError(errorMessage)
            trailerArray = self.trailer[i]
            if trailerArray[0] is not None:
                ret = trailerArray[0].encodeChars()
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
                self.trailer[i] = trailerArray
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, '')

    def encrypt(self, password=''):
        # TODO: AESV2 and V3
        errorMessage = ''
        encryptDictId = None
        encryptMetadata = True
        permissionNum = 1073741823
        dictOE = ''
        dictUE = ''
        ret = self.getTrailer()
        if not ret:
            errorMessage = 'Trailer not found'
            self.addError(errorMessage)
            return (-1, errorMessage)

        trailer, trailerStream = ret[1]
        if trailerStream is not None:
            trailer = trailerStream

        encryptDict = trailer.getDictEntry('/Encrypt')
        if encryptDict is not None:
            encryptDictType = encryptDict.getType()
            if encryptDictType == 'reference':
                encryptDictId = encryptDict.getId()
        fileId = self.getMD5()
        if fileId == '':
            fileId = hashlib.md5(str(random.random())).hexdigest()
        md5Object = PDFString(fileId)
        fileIdArray = PDFArray(elements=[md5Object, md5Object])
        trailer.setDictEntry('/ID', fileIdArray)
        self.setTrailer([trailer, trailerStream])

        ret = computeOwnerPass(password, password, 128, revision=3)
        if ret[0] != -1:
            dictO = ret[1]
        else:
            if isForceMode:
                self.addError(ret[1])
            else:
                return (-1, ret[1])
        self.setOwnerPass(dictO)
        ret = computeUserPass(password, dictO, fileId, permissionNum, 128, revision=3)
        if ret[0] != -1:
            dictU = ret[1]
        else:
            if isForceMode:
                self.addError(ret[1])
            else:
                return (-1, ret[1])
        self.setUserPass(dictU)
        ret = computeEncryptionKey(password, dictO, dictU, dictOE, dictUE, fileId, permissionNum, 128, revision=3, encryptMetadata=encryptMetadata, passwordType='USER')
        if ret[0] != -1:
            encryptionKey = ret[1]
        else:
            encryptionKey = ''
            if isForceMode:
                self.addError(ret[1])
            else:
                return (-1, "Creating or modifing /Encrypt dictionnary failed: "
                        "{}".format(ret[1]))
        self.setEncryptionKey(encryptionKey)
        self.setEncryptionKeyLength(128)
        encryptDict = PDFDictionary(elements={
            '/V': PDFNum('2'),
            '/Length': PDFNum('128'),
            '/Filter': PDFName('Standard'),
            '/R': PDFNum('3'),
            '/P': PDFNum(str(permissionNum)),
            '/O': PDFString(dictO),
            '/U': PDFString(dictU)
        })
        if encryptDictId is not None:
            ret = self.setObject(encryptDictId, encryptDict)
            if ret[0] == -1:
                errorMessage = '/Encrypt dictionary has not been created/modified : ' + ret[1]
                self.addError(errorMessage)
                return (-1, errorMessage)
        else:
            if trailerStream is not None:
                trailerStream.setDictEntry('/Encrypt', encryptDict)
            else:
                trailer.setDictEntry('/Encrypt', encryptDict)
            self.setTrailer([trailer, trailerStream])

        numKeyBytes = self.encryptionKeyLength/8
        for v in range(self.updates+1):
            indirectObjects = self.body[v].getObjects()
            for id in indirectObjects:
                indirectObject = indirectObjects[id]
                if indirectObject is not None:
                    generationNum = indirectObject.getGenerationNumber()
                    object = indirectObject.getObject()
                    if object is not None and not object.isCompressed():
                        objectType = object.getType()
                        if objectType in ['string', 'hexstring', 'array', 'dictionary'] or (objectType == 'stream' and (object.getElement('/Type') is None or (object.getElement('/Type').getValue() not in ['/XRef', '/Metadata'] or (object.getElement('/Type').getValue() == '/Metadata' and encryptMetadata)))):
                            ret = computeObjectKey(id, generationNum, self.encryptionKey, numKeyBytes)
                            if ret[0] == -1:
                                errorMessage = ret[1]
                                self.addError(ret[1])
                            else:
                                key = ret[1]
                                ret = object.encrypt(key)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
                                ret = self.body[v].setObject(id, object)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
        if errorMessage != '':
            return (-1, errorMessage)
        self.setEncrypted(True)
        return (0, '')

    def getBasicMetadata(self, version):
        basicMetadata = {}

        # Getting creation information
        infoObject = self.getInfoObject(version)
        if infoObject is not None:
            author = infoObject.getElementByName('/Author')
            if author is not None and author != []:
                basicMetadata['author'] = author.getValue()

            subject = infoObject.getElementByName('/Subject')
            if subject is not None and subject != []:
                basicMetadata['subject'] = subject.getValue()

            title = infoObject.getElementByName('/Title')
            if title is not None and title != []:
                basicMetadata['title'] = title.getValue()

            creator = infoObject.getElementByName('/Creator')
            if creator is not None and creator != []:
                basicMetadata['creator'] = creator.getValue()

            producer = infoObject.getElementByName('/Producer')
            if producer is not None and producer != []:
                basicMetadata['producer'] = producer.getValue()

            creationDate = infoObject.getElementByName('/CreationDate')
            if creationDate is not None and creationDate != []:
                basicMetadata['creation'] = creationDate.getValue()

        if "author" not in basicMetadata:
            ids = self.getObjectsByString('<dc:creator>', version)
            if ids is not None and ids != []:
                for id in ids:
                    author = self.getMetadataElement(id, version, 'dc:creator')
                    if author is not None:
                        basicMetadata['author'] = author
                        break

        if "creator" not in basicMetadata:
            ids = self.getObjectsByString('<xap:CreatorTool>', version)
            if ids is not None and ids != []:
                for id in ids:
                    creator = self.getMetadataElement(id, version, 'xap:CreatorTool')
                    if creator is not None:
                        basicMetadata['creator'] = creator
                        break

        if "creator" not in basicMetadata:
            ids = self.getObjectsByString('<xmp:CreatorTool>', version)
            if ids is not None and ids != []:
                for id in ids:
                    creator = self.getMetadataElement(id, version, 'xmp:CreatorTool')
                    if creator is not None:
                        basicMetadata['creator'] = creator
                        break

        if "producer" not in basicMetadata:
            ids = self.getObjectsByString('<pdf:Producer>', version)
            if ids is not None and ids != []:
                for id in ids:
                    producer = self.getMetadataElement(id, version, 'pdf:Producer')
                    if producer is not None:
                        basicMetadata['producer'] = producer
                        break

        if "creation" not in basicMetadata:
            ids = self.getObjectsByString('<xap:CreateDate>', version)
            if ids is not None and ids != []:
                for id in ids:
                    creation = self.getMetadataElement(id, version, 'xap:CreateDate')
                    if creation is not None:
                        basicMetadata['creation'] = creation
                        break

        if "creation" not in basicMetadata:
            ids = self.getObjectsByString('<xmp:CreateDate>', version)
            if ids is not None and ids != []:
                for id in ids:
                    creation = self.getMetadataElement(id, version, 'xmp:CreateDate')
                    if creation is not None:
                        basicMetadata['creation'] = creation
                        break

        if "modification" not in basicMetadata:
            ids = self.getObjectsByString('<xap:ModifyDate>', version)
            if ids is not None and ids != []:
                for id in ids:
                    modification = self.getMetadataElement(id, version, 'xap:ModifyDate')
                    if modification is not None:
                        basicMetadata['modification'] = modification
                        break

        if "modification" not in basicMetadata:
            ids = self.getObjectsByString('<xmp:ModifyDate>', version)
            if ids is not None and ids != []:
                for id in ids:
                    modification = self.getMetadataElement(id, version, 'xmp:ModifyDate')
                    if modification is not None:
                        basicMetadata['modification'] = modification
                        break

        return basicMetadata

    def getCatalogObject(self, version=None, indirect=False):
        if version is None:
            catalogObjects = []
            catalogIds = self.getCatalogObjectId()
            for i in xrange(len(catalogIds)):
                id = catalogIds[i]
                if id is not None:
                    catalogObject = self.getObject(id, i, indirect)
                    catalogObjects.append(catalogObject)
                else:
                    catalogObjects.append(None)
            return catalogObjects
        else:
            catalogId = self.getCatalogObjectId(version)
            if catalogId is not None:
                catalogObject = self.getObject(catalogId, version, indirect)
                return catalogObject
            else:
                return None

    def getCatalogObjectId(self, version=None):
        if version is None:
            catalogIds = []
            for v in range(self.updates+1):
                catalogId = None
                trailer, streamTrailer = self.trailer[v]
                if trailer is not None:
                    catalogId = trailer.getCatalogId()
                if catalogId is None and streamTrailer is not None:
                    catalogId = streamTrailer.getCatalogId()
                catalogIds.append(catalogId)
            return catalogIds
        else:
            catalogId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer is not None:
                catalogId = trailer.getCatalogId()
            if catalogId is None and streamTrailer is not None:
                catalogId = streamTrailer.getCatalogId()
            return catalogId

    def getChangeLog(self, version=None):
        lastVersionObjects = []
        actualVersionObjects = []
        addedObjects = []
        removedObjects = []
        modifiedObjects = []
        notMatchingObjects = []
        changes = []
        if version is None:
            version = self.updates + 1
        else:
            version += 1
        for i in range(version):
            actualVersionObjects = self.body[i].getObjectsIds()
            if i != 0:
                xrefNewObjects = []
                xrefFreeObjects = []
                crossRefSection = self.crossRefTable[i][0]
                crossRefStreamSection = self.crossRefTable[i][1]
                if crossRefSection is not None:
                    xrefNewObjects += crossRefSection.getNewObjectIds()
                    xrefFreeObjects += crossRefSection.getFreeObjectIds()
                if crossRefStreamSection is not None:
                    xrefNewObjects += crossRefStreamSection.getNewObjectIds()
                    xrefFreeObjects += crossRefStreamSection.getFreeObjectIds()
                for id in actualVersionObjects:
                    if id not in lastVersionObjects:
                        addedObjects.append(id)
                        lastVersionObjects.append(id)
                    else:
                        modifiedObjects.append(id)
                    if id not in xrefNewObjects or id in xrefFreeObjects:
                        notMatchingObjects.append(id)
                for id in lastVersionObjects:
                    if id not in actualVersionObjects:
                        if id in xrefFreeObjects:
                            removedObjects.append(id)
                            lastVersionObjects.remove(id)
                        if id in xrefNewObjects:
                            notMatchingObjects.append(id)
                changes.append([addedObjects, modifiedObjects, removedObjects, notMatchingObjects])
                addedObjects = []
                removedObjects = []
                modifiedObjects = []
                notMatchingObjects = []
            else:
                lastVersionObjects = actualVersionObjects
        return changes

    def getDetectionRate(self):
        return self.detectionRate

    def getDetectionReport(self):
        return self.detectionReport

    def getEndLine(self):
        return self.endLine

    def getEncryptDict(self):
        return self.encryptDict

    def getEncryptionAlgorithms(self):
        return self.encryptionAlgorithms

    def getEncryptionKey(self):
        return self.encryptionKey

    def getEncryptionKeyLength(self):
        return self.encryptionKeyLength

    def getErrors(self):
        return self.errors

    def getFileId(self):
        return self.fileId

    def getFileName(self):
        return self.fileName

    def getGarbageHeader(self):
        return self.garbageHeader

    def getHeaderOffset(self):
        return self.headerOffset

    def getInfoObject(self, version=None, indirect=False):
        if version is None:
            infoObjects = []
            infoIds = self.getInfoObjectId()
            for i in xrange(len(infoIds)):
                id = infoIds[i]
                if id is not None:
                    infoObject = self.getObject(id, i, indirect)
                    infoObjects.append(infoObject)
                else:
                    infoObjects.append(None)
            return infoObjects
        else:
            infoId = self.getInfoObjectId(version)
            if infoId is not None:
                infoObject = self.getObject(infoId, version, indirect)
                if infoObject is None and version == 0 and self.getLinearized():
                    # Linearized documents can store Info object in the next update
                    infoObject = self.getObject(infoId, None, indirect)
                    return infoObject
                return infoObject
            else:
                return None

    def getInfoObjectId(self, version=None):
        if version is None:
            infoIds = []
            for v in range(self.updates+1):
                infoId = None
                trailer, streamTrailer = self.trailer[v]
                if trailer is not None:
                    infoId = trailer.getInfoId()
                if infoId is None and streamTrailer is not None:
                    infoId = streamTrailer.getInfoId()
                infoIds.append(infoId)
            else:
                return infoIds
        else:
            infoId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer is not None:
                infoId = trailer.getInfoId()
            if infoId is None and streamTrailer is not None:
                infoId = streamTrailer.getInfoId()
            return infoId

    def getJavascriptCode(self, version=None, perObject=False):
        jsCode = []
        if version is None:
            for version in range(self.updates+1):
                if perObject:
                    jsCode.append(self.body[version].getJSCodePerObject())
                else:
                    jsCode.append(self.body[version].getJSCode())
        else:
            if version <= self.updates and not version < 0:
                if perObject:
                    jsCode.append(self.body[version].getJSCodePerObject())
                else:
                    jsCode.append(self.body[version].getJSCode())
        return jsCode

    def getLinearized(self):
        return self.linearized

    def getMD5(self):
        return self.md5

    def getMetadata(self, version=None):
        matchingObjects = self.getObjectsByString('/Metadata', version)
        return matchingObjects

    def getMetadataElement(self, objectId, version, element):
        metadataObject = self.getObject(objectId, version)
        if metadataObject is not None:
            if metadataObject.getType() == 'stream':
                stream = metadataObject.getStream()
                matches = re.findall('<'+element+'>(.*)</'+element+'>', stream)
                if matches != []:
                    return matches[0]
                else:
                    return None
            else:
                return None
        else:
            return None

    def getNumUpdates(self):
        return self.updates

    def getObject(self, id, version=None, indirect=False):
        '''
            Returns the specified object
        '''
        if version is None:
            for i in range(self.updates, -1, -1):
                if indirect:
                    object = self.body[i].getIndirectObject(id)
                else:
                    object = self.body[i].getObject(id)
                if object is None:
                    continue
                else:
                    return object
            else:
                return None
        else:
            if version > self.updates or version < 0:
                return None
            if indirect:
                return self.body[version].getIndirectObject(id)
            else:
                return self.body[version].getObject(id)

    def getObjectsByString(self, toSearch, version=None):
        ''' Returns the object containing the specified string. '''
        matchedObjects = []
        if version is None:
            for i in range(self.updates + 1):
                matchedObjects.append(self.body[i].getObjectsByString(toSearch))
            return matchedObjects
        else:
            if version > self.updates or version < 0:
                return None
            return self.body[version].getObjectsByString(toSearch)

    def getOffsets(self, version=None):
        offsetsArray = []

        if version is None:
            versions = range(self.updates+1)
        else:
            versions = [version]

        for version in versions:
            offsets = {}
            trailer = None
            xref = None
            objectStreamsOffsets = {}
            indirectObjects = self.body[version].getObjects()
            sortedObjectsIds = self.body[version].getObjectsIds()
            compressedObjects = self.body[version].getCompressedObjects()
            objectStreams = self.body[version].getObjectStreams()
            ret = self.getXrefSection(version)
            if ret is not None:
                xref, streamXref = ret[1]
            ret = self.getTrailer(version)
            if ret is not None:
                trailer, streamTrailer = ret[1]
            if objectStreams != []:
                for objStream in objectStreams:
                    if objStream in indirectObjects:
                        indirectObject = indirectObjects[objStream]
                        if indirectObject is not None:
                            objectStreamsOffsets[objStream] = indirectObject.getOffset()
            if version == 0:
                offsets['header'] = (self.headerOffset, 0)
            for id in sortedObjectsIds:
                indirectObject = indirectObjects[id]
                if indirectObject is not None:
                    objectOffset = indirectObject.getOffset()
                    object = indirectObject.getObject()
                    if object is not None and object.isCompressed():
                        compressedIn = object.getCompressedIn()
                        if compressedIn in objectStreamsOffsets:
                            objectOffset = objectStreamsOffsets[compressedIn] + objectOffset + 20
                    size = indirectObject.getSize()
                    if "objects" in offsets:
                        offsets['objects'].append((id, objectOffset, size))
                    else:
                        offsets['objects'] = [(id, objectOffset, size)]
            if xref is not None:
                xrefOffset = xref.getOffset()
                xrefSize = xref.getSize()
                offsets['xref'] = (xrefOffset, xrefSize)
            else:
                offsets['xref'] = None
            if trailer is not None:
                trailerOffset = trailer.getOffset()
                trailerSize = trailer.getSize()
                eofOffset = trailer.getEOFOffset()
                offsets['trailer'] = (trailerOffset, trailerSize)
                offsets['eof'] = (eofOffset, 0)
            else:
                offsets['trailer'] = None
                offsets['eof'] = None
            offsets['compressed'] = compressedObjects
            offsetsArray.append(offsets)
        return offsetsArray

    def getOwnerPass(self):
        return self.ownerPass

    def getPath(self):
        return self.path

    def getReferencesIn(self, id, version=None):
        '''
            Get the references in an object
        '''
        if version is None:
            for i in range(self.updates, -1, -1):
                indirectObjectsDict = self.body[i].getObjects()
                if id in indirectObjectsDict:
                    indirectObject = indirectObjectsDict[id]
                    if indirectObject is None:
                        return None
                    else:
                        return indirectObject.getReferences()
            else:
                return None
        else:
            if version > self.updates or version < 0:
                return None
            indirectObjectsDict = self.body[version].getObjects()
            if id in indirectObjectsDict:
                indirectObject = indirectObjectsDict[id]
                if indirectObject is None:
                    return None
                else:
                    return indirectObject.getReferences()
            else:
                return None

    def getReferencesTo(self, id, version=None):
        '''
            Get the references to the specified object in the document
        '''
        matchedObjects = []
        if version is None:
            for i in range(self.updates + 1):
                indirectObjectsDict = self.body[i].getObjects()
                for indirectObject in indirectObjectsDict.values():
                    if indirectObject is not None:
                        object = indirectObject.getObject()
                        if object is not None:
                            value = object.getValue()
                            if re.findall('\D'+str(id)+'\s{1,3}\d{1,3}\s{1,3}R', value) != []:
                                matchedObjects.append(indirectObject.id)
        else:
            if version > self.updates or version < 0:
                return None
            indirectObjectsDict = self.body[version].getObjects()
            for indirectObject in indirectObjectsDict.values():
                if indirectObject is not None:
                    object = indirectObject.getObject()
                    if object is not None:
                        value = object.getValue()
                        if re.findall('\D'+str(id)+'\s{1,3}\d{1,3}\s{1,3}R', value) != []:
                            matchedObjects.append(indirectObject.id)
        return matchedObjects

    def getSHA1(self):
        return self.sha1

    def getSHA256(self):
        return self.sha256

    def getSize(self):
        return self.size

    def getStats(self):
        stats = {}
        stats['File'] = self.fileName
        stats['MD5'] = self.md5
        stats['SHA1'] = self.sha1
        stats['SHA256'] = self.sha256
        stats['Size'] = str(self.size)
        stats['Detection'] = self.detectionRate
        stats['Detection report'] = self.detectionReport
        stats['Version'] = self.version
        stats['Binary'] = str(self.binary)
        stats['Linearized'] = str(self.linearized)
        stats['Encrypted'] = str(self.encrypted)
        stats['Encryption Algorithms'] = self.encryptionAlgorithms
        stats['Updates'] = str(self.updates)
        stats['Objects'] = str(self.numObjects)
        stats['Streams'] = str(self.numStreams)
        stats['URIs'] = str(self.numURIs)
        stats['Comments'] = str(len(self.comments))
        stats['Errors'] = self.errors
        stats['Versions'] = []
        for version in range(self.updates+1):
            statsVersion = {}
            catalogId = None
            infoId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer is not None:
                catalogId = trailer.getCatalogId()
                infoId = trailer.getInfoId()
            if catalogId is None and streamTrailer is not None:
                catalogId = streamTrailer.getCatalogId()
            if infoId is None and streamTrailer is not None:
                infoId = streamTrailer.getInfoId()
            if catalogId is not None:
                statsVersion['Catalog'] = str(catalogId)
            else:
                statsVersion['Catalog'] = None
            if infoId is not None:
                statsVersion['Info'] = str(infoId)
            else:
                statsVersion['Info'] = None
            objectsById = sorted(self.body[version].getObjectsIds(), key=lambda x: int(x))
            statsVersion['Objects'] = [str(self.body[version].getNumObjects()), objectsById]
            if self.body[version].containsCompressedObjects():
                compressedObjects = self.body[version].getCompressedObjects()
                statsVersion['Compressed Objects'] = [str(len(compressedObjects)), compressedObjects]
            else:
                statsVersion['Compressed Objects'] = None
            numFaultyObjects = self.body[version].getNumFaultyObjects()
            if numFaultyObjects > 0:
                statsVersion['Errors'] = [str(numFaultyObjects), self.body[version].getFaultyObjects()]
            else:
                statsVersion['Errors'] = None
            numStreams = self.body[version].getNumStreams()
            statsVersion['Streams'] = [str(numStreams), self.body[version].getStreams()]
            if self.body[version].containsXrefStreams():
                xrefStreams = self.body[version].getXrefStreams()
                statsVersion['Xref Streams'] = [str(len(xrefStreams)), xrefStreams]
            else:
                statsVersion['Xref Streams'] = None
            if self.body[version].containsObjectStreams():
                objectStreams = self.body[version].getObjectStreams()
                statsVersion['Object Streams'] = [str(len(objectStreams)), objectStreams]
            else:
                statsVersion['Object Streams'] = None
            if numStreams > 0:
                statsVersion['Encoded'] = [str(self.body[version].getNumEncodedStreams()), self.body[version].getEncodedStreams()]
                numDecodingErrors = self.body[version].getNumDecodingErrors()
                if numDecodingErrors > 0:
                    statsVersion['Decoding Errors'] = [str(numDecodingErrors), self.body[version].getFaultyStreams()]
                else:
                    statsVersion['Decoding Errors'] = None
            else:
                statsVersion['Encoded'] = None
            containingURIs = self.body[version].getContainingURIs()
            if len(containingURIs) > 0:
                statsVersion['URIs'] = [str(len(containingURIs)), containingURIs]
            else:
                statsVersion['URIs'] = None
            containingJS = self.body[version].getContainingJS()
            if len(containingJS) > 0:
                statsVersion['Objects with JS code'] = [str(len(containingJS)), containingJS]
            else:
                statsVersion['Objects with JS code'] = None
            actions = self.body[version].getSuspiciousActions()
            events = self.body[version].getSuspiciousEvents()
            vulns = self.body[version].getVulns()
            elements = self.body[version].getSuspiciousElements()
            urls = self.body[version].getURLs()
            if len(events) > 0:
                statsVersion['Events'] = events
            else:
                statsVersion['Events'] = None
            if len(actions) > 0:
                statsVersion['Actions'] = actions
            else:
                statsVersion['Actions'] = None
            if len(vulns) > 0:
                statsVersion['Vulns'] = vulns
            else:
                statsVersion['Vulns'] = None
            if len(elements) > 0:
                statsVersion['Elements'] = elements
            else:
                statsVersion['Elements'] = None
            if len(urls) > 0:
                statsVersion['URLs'] = urls
            else:
                statsVersion['URLs'] = None
            stats['Versions'].append(statsVersion)
        return stats

    def getSuspiciousComponents(self):
        pass

    def getTrailer(self, version=None):
        if version is None:
            for i in range(self.updates, -1, -1):
                trailerArray = self.trailer[i]
                if trailerArray is None or trailerArray == []:
                    continue
                else:
                    return (i, trailerArray)
            else:
                # self.addError('Trailer not found in file')
                return None
        else:
            if version > self.updates or version < 0:
                # self.addError('Bad version getting trailer')
                return None
            trailerArray = self.trailer[version]
            if trailerArray is None or trailerArray == []:
                return None
            else:
                return (version, trailerArray)

    def getTree(self, version=None):
        '''
            Returns the logical structure (tree) of the document
        '''
        tree = []

        if version is None:
            versions = range(self.updates+1)
        else:
            versions = [version]

        for version in versions:
            objectsIn = {}
            trailer = None
            streamTrailer = None
            catalogId = None
            infoId = None
            ids = self.body[version].getObjectsIds()
            ret = self.getTrailer(version)
            if ret is not None:
                trailer, streamTrailer = ret[1]
            # Getting info and catalog id
            if trailer is not None:
                catalogId = trailer.getCatalogId()
                infoId = trailer.getInfoId()
            if catalogId is None and streamTrailer is not None:
                catalogId = streamTrailer.getCatalogId()
            if infoId is None and streamTrailer is not None:
                infoId = streamTrailer.getInfoId()
            for id in ids:
                referencesIds = []
                object = self.getObject(id, version)
                if object is not None:
                    type = object.getType()
                    if type == 'dictionary' or type == 'stream':
                        elements = object.getElements()
                        if infoId == id:
                            type = '/Info'
                        else:
                            dictType = object.getDictType()
                            if dictType != '':
                                type = dictType
                            else:
                                if type == 'dictionary' and len(elements) == 1:
                                    type = elements.keys()[0]
                    references = self.getReferencesIn(id, version)
                    for i in range(len(references)):
                        referencesIds.append(int(references[i].split()[0]))
                    if references is None:
                        objectsIn[id] = (type, [])
                    else:
                        objectsIn[id] = (type, referencesIds)
            tree.append([catalogId, objectsIn])
        return tree

    def getUpdates(self):
        return self.updates

    def getURLs(self, version=None):
        urls = []
        if version is None:
            for version in range(self.updates+1):
                urls += self.body[version].getURLs()
        else:
            if version <= self.updates and not version < 0:
                urls = self.body[version].getURLs()
        return urls

    def getURIs(self, version=None, perObject=False):
        uris = []
        if version is None:
            for version in range(self.updates+1):
                if perObject:
                    uris.append(self.body[version].getURIsPerObject())
                else:
                    uris.append(self.body[version].getURIs())
        else:
            if version <= self.updates and not version < 0:
                if perObject:
                    uris.append(self.body[version].getURIsPerObject())
                else:
                    uris.append(self.body[version].getURIs())
        return uris

    def getUserPass(self):
        return self.userPass

    def getVersion(self):
        return self.version

    def getXrefSection(self, version=None):
        if version is None:
            for i in range(self.updates, -1, -1):
                xrefArray = self.crossRefTable[i]
                if xrefArray is None or xrefArray == []:
                    continue
                else:
                    return (i, xrefArray)
            else:
                # self.addError('Xref section not found in file')
                return None
        else:
            if version > self.updates or version < 0:
                return None
            xrefArray = self.crossRefTable[version]
            if xrefArray is None or xrefArray == []:
                return None
            else:
                return (version, xrefArray)

    def headerToFile(self, malformedOptions, headerFile):
        headerGarbage = ''
        if MAL_ALL in malformedOptions or MAL_HEAD in malformedOptions:
            if headerFile is None:
                if self.garbageHeader == '':
                    headerGarbage = 'MZ'+'_'*100
                else:
                    headerGarbage = self.garbageHeader
            else:
                headerGarbage = open(headerFile, 'rb').read()
            headerGarbage += newLine
        if MAL_ALL in malformedOptions or MAL_BAD_HEAD in malformedOptions:
            output = headerGarbage + '%PDF-1.\0' + newLine
        else:
            output = headerGarbage + '%PDF-' + self.version + newLine
        if self.binary or headerGarbage != '':
            self.binary = True
            self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
            output += '%' + self.binaryChars + newLine
        return output

    def isEncrypted(self):
        return self.encrypted

    def makePDF(self, pdfType, content):
        offset = 0
        numObjects = 3
        self.version = '1.7'
        xrefEntries = []
        staticIndirectObjectSize = 13+3*len(newLine)
        self.setHeaderOffset(offset)
        if pdfType == 'open_action_js':
            self.binary = True
            self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
            offset = 16
        else:
            offset = 10

        # Body
        body = PDFBody()
        xrefEntries.append(PDFCrossRefEntry(0, 65535, 'f'))
        # Catalog (1)
        catalogElements = {'/Type': PDFName('Catalog'), '/Pages': PDFReference('2')}
        if pdfType == 'open_action_js':
            catalogElements['/OpenAction'] = PDFReference('4')
        catalogDictionary = PDFDictionary(elements=catalogElements)
        catalogSize = staticIndirectObjectSize + len(catalogDictionary.getRawValue())
        body.setObject(object=catalogDictionary, offset=offset)
        xrefEntries.append(PDFCrossRefEntry(offset, 0, 'n'))
        offset += catalogSize
        # Pages root node (2)
        pagesDictionary = PDFDictionary(elements={'/Type': PDFName('Pages'), '/Kids': PDFArray(elements=[PDFReference('3')]), '/Count': PDFNum('1')})
        pagesSize = len(pagesDictionary.getRawValue())+staticIndirectObjectSize
        body.setObject(object=pagesDictionary, offset=offset)
        xrefEntries.append(PDFCrossRefEntry(offset, 0, 'n'))
        offset += pagesSize
        # Page node (3)
        mediaBoxArray = PDFArray(elements=[PDFNum('0'), PDFNum('0'), PDFNum('600'), PDFNum('800')])
        pageDictionary = PDFDictionary(elements={'/Type': PDFName('Page'), '/Parent': PDFReference('2'), '/MediaBox': mediaBoxArray, '/Resources': PDFDictionary()})
        pageSize = len(pageDictionary.getRawValue())+staticIndirectObjectSize
        body.setObject(object=pageDictionary, offset=offset)
        xrefEntries.append(PDFCrossRefEntry(offset, 0, 'n'))
        offset += pageSize
        if pdfType == 'open_action_js':
            # Action object (4)
            actionDictionary = PDFDictionary(elements={'/Type': PDFName('Action'), '/S': PDFName('JavaScript'), '/JS': PDFReference('5')})
            actionSize = len(actionDictionary.getRawValue())+staticIndirectObjectSize
            body.setObject(object=actionDictionary, offset=offset)
            xrefEntries.append(PDFCrossRefEntry(offset, 0, 'n'))
            offset += actionSize
            # JS stream (5)
            try:
                jsStream = PDFStream(rawStream=content, elements={'/Length': PDFNum(str(len(content)))})
            except Exception as e:
                errorMessage = 'Error creating PDFStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
            ret = jsStream.setElement('/Filter', PDFName('FlateDecode'))
            if ret[0] == -1:
                self.addError(ret[1])
                return ret
            jsSize = len(jsStream.getRawValue())+staticIndirectObjectSize
            ret = body.setObject(object=jsStream, offset=offset)
            if ret[0] == -1:
                self.addError(ret[1])
                return ret
            xrefEntries.append(PDFCrossRefEntry(offset, 0, 'n'))
            offset += jsSize
            numObjects = 5
        body.setNextOffset(offset)
        self.addBody(body)
        self.addNumObjects(body.getNumObjects())
        self.addNumStreams(body.getNumStreams())
        self.addNumEncodedStreams(body.getNumEncodedStreams())
        self.addNumDecodingErrors(body.getNumDecodingErrors())

        # xref table
        subsection = PDFCrossRefSubSection(0, numObjects+1, xrefEntries)
        xrefSection = PDFCrossRefSection()
        xrefSection.addSubsection(subsection)
        xrefSection.setOffset(offset)
        xrefOffset = offset
        xrefSectionSize = len(xrefEntries)*20+10
        xrefSection.setSize(xrefSectionSize)
        offset += xrefSectionSize
        self.addCrossRefTableSection([xrefSection, None])

        # Trailer
        trailerDictionary = PDFDictionary(elements={'/Size': PDFNum(str(numObjects+1)), '/Root': PDFReference('1')})
        trailerSize = len(trailerDictionary.getRawValue())+25
        trailer = PDFTrailer(trailerDictionary, str(xrefOffset))
        trailer.setOffset(offset)
        trailer.setSize(trailerSize)
        trailer.setEOFOffset(offset+trailerSize)
        self.addTrailer([trailer, None])
        self.setSize(offset+trailerSize+5)
        self.updateStats()
        return (0, '')

    def replace(self, string1, string2):
        errorMessage = ''
        stringFound = False
        for i in range(self.updates + 1):
            objects = self.getObjectsByString(string1, i)
            for id in objects:
                object = self.getObject(id, i)
                if object is not None:
                    ret = object.replace(string1, string2)
                    if ret[0] == -1 and not stringFound:
                        errorMessage = ret[1]
                    else:
                        stringFound = True
                        ret = self.setObject(id, object, i)
                        if ret[0] == -1:
                            errorMessage = ret[1]
        if not stringFound:
            return (-1, 'String not found')
        if errorMessage != '':
            return (-1, errorMessage)
        else:
            return (0, '')

    def removeError(self, errorMessage='', errorType=None):
        '''
            Removes the error message from the errors array. If an errorType is given, then all the error messages belonging to this type are removed.

            @param errorMessage: The error message to be removed (string)
            @param errorType: All the error messages of this type will be removed (string)
        '''
        if errorMessage in self.errors:
            self.errors.remove(errorMessage)
        if errorType is not None:
            lenErrorType = len(errorType)
            for error in self.errors:
                if error[:lenErrorType] == errorType:
                    self.errors.remove(error)

    def save(self, filename, version=None, malformedOptions=[], headerFile=None):
        maxId = 0
        offset = 0
        lastXrefSectionOffset = 0
        prevXrefSectionOffset = 0
        prevXrefStreamOffset = 0
        indirectObjects = {}
        xrefStreamObjectId = None
        xrefStreamObject = None
        try:
            if version is None:
                version = self.updates
            outputFileContent = self.headerToFile(malformedOptions, headerFile)
            offset = len(outputFileContent)
            for v in range(version+1):
                xrefStreamObjectId = None
                xrefStreamObject = None
                sortedObjectsIds = self.body[v].getObjectsIds()
                indirectObjects = self.body[v].getObjects()
                section, streamSection = self.crossRefTable[v]
                trailer, streamTrailer = self.trailer[v]
                if section is not None:
                    numSubSectionsInXref = section.getSubsectionsNumber()
                else:
                    numSubSectionsInXref = 0
                if streamSection is not None:
                    numSubSectionsInXrefStream = streamSection.getSubsectionsNumber()
                else:
                    numSubSectionsInXrefStream = 0
                if streamSection is not None:
                    xrefStreamObjectId = streamSection.getXrefStreamObject()
                    if xrefStreamObjectId in indirectObjects:
                        xrefStreamObject = indirectObjects[xrefStreamObjectId]
                        sortedObjectsIds.remove(xrefStreamObjectId)
                for id in sortedObjectsIds:
                    if id > maxId:
                        maxId = id
                    indirectObject = indirectObjects[id]
                    if indirectObject is not None:
                        object = indirectObject.getObject()
                        if object is not None:
                            objectType = object.getType()
                            if not object.isCompressed():
                                indirectObject.setOffset(offset)
                                if numSubSectionsInXref != 0:
                                    ret = section.updateOffset(id, offset)
                                    if ret[0] == -1:
                                        ret = section.addEntry(id, PDFCrossRefEntry(offset, 0, 'n'))
                                        if ret[0] == -1:
                                            self.addError(ret[1])
                                if numSubSectionsInXrefStream != 0:
                                    ret = streamSection.updateOffset(id, offset)
                                    if ret[0] == -1:
                                        ret = streamSection.addEntry(id, PDFCrossRefEntry(offset, 0, 'n'))
                                        if ret[0] == -1:
                                            self.addError(ret[1])
                                objectFileOutput = indirectObject.toFile()
                                if objectType == 'stream' and MAL_ESTREAM in malformedOptions:
                                    objectFileOutput = objectFileOutput.replace(newLine+'endstream', '')
                                elif MAL_ALL in malformedOptions or MAL_EOBJ in malformedOptions:
                                    objectFileOutput = objectFileOutput.replace(newLine+'endobj', '')
                                outputFileContent += objectFileOutput
                                offset = len(outputFileContent)
                                indirectObject.setSize(offset-indirectObject.getOffset())
                                indirectObjects[id] = indirectObject

                if xrefStreamObject is not None:
                    if numSubSectionsInXref != 0:
                        ret = section.updateOffset(xrefStreamObjectId, offset)
                        if ret[0] == -1:
                            self.addError(ret[1])
                    ret = streamSection.updateOffset(xrefStreamObjectId, offset)
                    if ret[0] == -1:
                        self.addError(ret[1])
                    xrefStreamObject.setOffset(offset)
                    if xrefStreamObjectId > maxId:
                        maxId = xrefStreamObjectId
                    streamSection.setSize(maxId+1)
                    if streamTrailer is not None:
                        streamTrailer.setNumObjects(maxId+1)
                        if prevXrefStreamOffset != 0:
                            streamTrailer.setPrevCrossRefSection(prevXrefStreamOffset)
                        self.trailer[v][1] = streamTrailer
                    self.crossRefTable[v][1] = streamSection
                    ret = self.createXrefStream(v, xrefStreamObjectId)
                    if ret[0] == -1:
                        return (-1, ret[1])
                    xrefStreamObjectId, newXrefStream = ret[1]
                    xrefStreamObject.setObject(newXrefStream)
                    objectFileOutput = xrefStreamObject.toFile()
                    if MAL_ALL in malformedOptions or MAL_ESTREAM in malformedOptions:
                        objectFileOutput = objectFileOutput.replace(newLine+'endstream', '')
                    outputFileContent += objectFileOutput
                    prevXrefStreamOffset = offset
                    lastXrefSectionOffset = offset
                    offset = len(outputFileContent)
                    xrefStreamObject.setSize(offset-xrefStreamObject.getOffset())
                    indirectObjects[xrefStreamObjectId] = xrefStreamObject
                self.body[v].setNextOffset(offset)

                if section is not None and MAL_ALL not in malformedOptions and MAL_XREF not in malformedOptions:
                    section.setOffset(offset)
                    lastXrefSectionOffset = offset
                    outputFileContent += section.toFile()
                    offset = len(outputFileContent)
                    section.setSize(offset-section.getOffset())
                    self.crossRefTable[v][0] = section

                if trailer is not None:
                    trailer.setLastCrossRefSection(lastXrefSectionOffset)
                    trailer.setOffset(offset)
                    if trailer.getCatalogId() is not None and trailer.getSize() != 0:
                        trailer.setNumObjects(maxId+1)
                        if prevXrefSectionOffset != 0:
                            trailer.setPrevCrossRefSection(prevXrefSectionOffset)
                    outputFileContent += trailer.toFile()
                    offset = len(outputFileContent)
                    trailer.setSize(offset-trailer.getOffset())
                    self.trailer[v][0] = trailer
                prevXrefSectionOffset = lastXrefSectionOffset
                self.body[v].setObjects(indirectObjects)
                offset = len(outputFileContent)
            open(filename, 'wb').write(outputFileContent)
            self.setMD5(hashlib.md5(outputFileContent).hexdigest())
            self.setSize(len(outputFileContent))
            self.path = os.path.realpath(filename)
            self.fileName = filename
        except:
            return (-1, 'Unspecified error')
        return (0, '')

    def setDetectionRate(self, newRate):
        self.detectionRate = newRate

    def setDetectionReport(self, detectionReportLink):
        self.detectionReport = detectionReportLink

    def setEncryptDict(self, dict):
        self.encryptDict = dict

    def setEncrypted(self, status):
        self.encrypted = status

    def setEncryptionAlgorithms(self, encryptionAlgorithms):
        self.encryptionAlgorithms = encryptionAlgorithms

    def setEncryptionKey(self, key):
        self.encryptionKey = key

    def setEncryptionKeyLength(self, length):
        self.encryptionKeyLength = length

    def setEndLine(self, eol):
        self.endLine = eol

    def setFileId(self, fid):
        self.fileId = fid

    def setFileName(self, name):
        self.fileName = name

    def setGarbageHeader(self, garbage):
        self.garbageHeader = garbage

    def setHeaderOffset(self, offset):
        self.headerOffset = offset

    def setLinearized(self, status):
        self.linearized = status

    def setMaxObjectId(self, id):
        if int(id) > self.maxObjectId:
            self.maxObjectId = int(id)

    def setMD5(self, md5):
        self.md5 = md5

    def setObject(self, id, object, version=None, mod=False):
        errorMessage = ''
        if object is None:
            return (-1, 'Object is None')
        if version is None:
            for i in range(self.updates, -1, -1):
                ret = self.body[i].setObject(id, object, modification=mod)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    return (-1, errorMessage)
                else:
                    objectType = object.getType()
                    if objectType == 'dictionary' and object.hasElement('/Linearized'):
                        self.setLinearized(True)
                    return ret
        else:
            if version > self.updates or version < 0:
                return (-1, 'Bad file version')
            ret = self.body[version].setObject(id, object, modification=mod)
            if ret[0] == -1:
                self.addError(ret[1])
                return (-1, ret[1])
            else:
                objectType = object.getType()
                if objectType == 'dictionary' and object.hasElement('/Linearized'):
                    self.setLinearized(True)
                return ret

    def setOwnerPass(self, password):
        self.ownerPass = password

    def setPath(self, path):
        self.path = path

    def setSHA1(self, sha1):
        self.sha1 = sha1

    def setSHA256(self, sha256):
        self.sha256 = sha256

    def setSize(self, size):
        self.size = size

    def setTrailer(self, trailerArray, version=None):
        errorMessage = ''
        if version is None:
            for i in range(self.updates, -1, -1):
                if len(self.trailer) > i:
                    self.trailer[i] = trailerArray
                else:
                    errorMessage = 'Trailer not found'
                    self.addError(errorMessage)
        else:
            if version > self.updates or version < 0:
                return (-1, 'Bad file version')
            self.trailer[version] = trailerArray
        if errorMessage != '':
            return (-1, errorMessage)
        return (0, '')

    def setUpdates(self, num):
        self.updates = num

    def setUserPass(self, password):
        self.userPass = password

    def setVersion(self, version):
        self.version = version

    def updateStats(self, recursiveUpdate=False):
        self.numObjects = 0
        self.numStreams = 0
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.encrypted = False

        for v in range(self.updates+1):
            if recursiveUpdate:
                # TODO
                self.updateBody(v)
                self.updateCrossRefTable(v)
                self.updateTrailer(v)

            # body.updateObjects()
            self.addNumObjects(self.body[v].getNumObjects())
            self.addNumStreams(self.body[v].getNumStreams())
            self.addNumEncodedStreams(self.body[v].getNumEncodedStreams())
            self.addNumDecodingErrors(self.body[v].getNumDecodingErrors())
            self.addNumURIs(self.body[v].getNumURIs())
            trailer, streamTrailer = self.trailer[v]
            if trailer is not None:
                if trailer.getDictEntry('/Encrypt') is not None:
                    self.setEncrypted(True)
            if streamTrailer is not None:
                if streamTrailer.getDictEntry('/Encrypt') is not None:
                    self.setEncrypted(True)
        return (0, '')

    def updateBody(self, version):
        # TODO
        pass

    def updateCrossRefTable(self, version):
        # TODO
        pass

    def updateTrailer(self, version):
        # TODO
        pass


class PDFParser:


    def __init__(self):
        self.commentChar = '%'
        self.comments = []
        self.delimiters = [
            ('<<', '>>', 'dictionary'),
            ('(', ')', 'string'),
            ('<', '>', 'hexadecimal'),
            ('[', ']', 'array'),
            ('{', '}', ''),
            ('/', '', 'name'),
            ('%', '', 'comment'),
        ]
        self.fileParts = []
        self.charCounter = 0

    def parse(self, fileName, forceMode=False, looseMode=False, manualAnalysis=False):
        '''
            Main method to parse a PDF document
            @param fileName The name of the file to be parsed
            @param forceMode Boolean to specify if ignore errors or not. Default value: False.
            @param looseMode Boolean to set the loose mode when parsing objects. Default value: False.
            @return A PDFFile instance
        '''
        global isForceMode, pdfFile, isManualAnalysis
        isFirstBody = True
        linearizedFound = False
        errorMessage = ''
        versionLine = ''
        binaryLine = ''
        headerOffset = 0
        garbageHeader = ''
        pdfFile = PDFFile()
        pdfHandler = PdfParserHandler(pdfFile)
        pdfHandler.setLevel(logging.DEBUG)
        log.addHandler(pdfHandler)

        pdfFile.setPath(fileName)
        pdfFile.setFileName(os.path.basename(fileName))
        isForceMode = forceMode
        isManualAnalysis = manualAnalysis

        # Reading the file header
        log.debug("start parsing")
        file = open(fileName, 'rb')
        log.debug("Search and read file header")
        for line in file:
            if versionLine == '':
                pdfHeaderIndex = line.find('%PDF-')
                psHeaderIndex = line.find('%!PS-Adobe-')
                if pdfHeaderIndex != -1 or psHeaderIndex != -1:
                    index = line.find('\r')
                    if index != -1 and index+1 < len(line) and line[index+1] != '\n':
                        index += 1
                        versionLine = line[:index]
                        binaryLine = line[index:]
                        break
                    else:
                        versionLine = line
                    if pdfHeaderIndex != -1:
                        headerOffset += pdfHeaderIndex
                    else:
                        headerOffset += psHeaderIndex
                    pdfFile.setHeaderOffset(headerOffset)
                else:
                    garbageHeader += line
            else:
                binaryLine = line
                break
            headerOffset += len(line)
        file.close()

        # Getting the specification version
        log.debug("Getting specification version")
        versionLine = versionLine.replace('\r', '')
        versionLine = versionLine.replace('\n', '')
        matchVersion = re.findall('%(PDF-|!PS-Adobe-\d{1,2}\.\d{1,2}\sPDF-)(\d{1,2}\.\d{1,2})', versionLine)
        if matchVersion == []:
            log.error("Bad PDF header ({})".format(versionLine))
            if isForceMode:
                pdfFile.setVersion(versionLine)
            else:
                sys.exit()
        else:
            pdfFile.setVersion(matchVersion[0][1])
        if garbageHeader != '':
            pdfFile.setGarbageHeader(garbageHeader)

        # Getting the end of line
        if len(binaryLine) > 3:
            if binaryLine[-2:] == '\r\n':
                pdfFile.setEndLine('\r\n')
            else:
                if binaryLine[-1] == '\r':
                    pdfFile.setEndLine('\r')
                elif binaryLine[-1] == '\n':
                    pdfFile.setEndLine('\n')
                else:
                    pdfFile.setEndLine('\n')

            # Does it contain binary characters??
            if binaryLine[0] == '%' and ord(binaryLine[1]) >= 128 and ord(binaryLine[2]) >= 128 and ord(binaryLine[3]) >= 128 and ord(binaryLine[4]) >= 128:
                pdfFile.binary = True
                pdfFile.binaryChars = binaryLine[1:5]
            else:
                pdfFile.binary = False

        # Reading the rest of the file
        log.debug("Parsing file content")
        fileContent = open(fileName, 'rb').read()
        pdfFile.setSize(len(fileContent))
        pdfFile.setMD5(hashlib.md5(fileContent).hexdigest())
        pdfFile.setSHA1(hashlib.sha1(fileContent).hexdigest())
        pdfFile.setSHA256(hashlib.sha256(fileContent).hexdigest())

        # Getting the number of updates in the file
        while fileContent.find('%%EOF') != -1:
            self.readUntilSymbol(fileContent, '%%EOF')
            self.readUntilEndOfLine(fileContent)
            self.fileParts.append(fileContent[:self.charCounter])
            fileContent = fileContent[self.charCounter:]
            self.charCounter = 0
        else:
            if self.fileParts == []:
                errorMessage = '%%EOF not found'
                log.error(errorMessage)
                if forceMode:
                    self.fileParts.append(fileContent)
                else:
                    sys.exit()
        log.debug("Getting {} updates in PDF file".format(len(self.fileParts) - 1))
        pdfFile.setUpdates(len(self.fileParts) - 1)

        # Getting the body, cross reference table and trailer of each part of the file
        for i in range(len(self.fileParts)):
            bodyOffset = 0
            xrefOffset = 0
            trailerOffset = 0
            xrefObject = None
            xrefContent = None
            xrefSection = None
            xrefStreamSection = None
            streamTrailer = None
            trailer = None
            pdfIndirectObject = None
            if not pdfFile.isEncrypted():
                encryptDict = None
                encryptDictId = None
            if pdfFile.getFileId() == '':
                fileId = None
            content = self.fileParts[i]
            if i == 0:
                bodyOffset = 0
            else:
                bodyOffset = len(self.fileParts[i-1])

            # Getting the content for each section
            bodyContent, xrefContent, trailerContent = self.parsePDFSections(content, forceMode, looseMode)
            if xrefContent is not None:
                xrefOffset = bodyOffset + len(bodyContent)
                trailerOffset = xrefOffset + len(xrefContent)
                bodyContent = bodyContent.strip('\r\n')
                xrefContent = xrefContent.strip('\r\n')
                trailerContent = trailerContent.strip('\r\n')
            else:
                if trailerContent is not None:
                    xrefOffset = -1
                    trailerOffset = bodyOffset + len(bodyContent)
                    bodyContent = bodyContent.strip('\r\n')
                    trailerContent = trailerContent.strip('\r\n')
                else:
                    log.error("PDF section not found")
                    if not forceMode:
                        sys.exit()

            # Converting the body content in PDFObjects
            body = PDFBody()
            rawIndirectObjects = self.getIndirectObjects(bodyContent, looseMode)
            if rawIndirectObjects != []:
                for j in range(len(rawIndirectObjects)):
                    relativeOffset = 0
                    auxContent = str(bodyContent)
                    rawObject = rawIndirectObjects[j][0]
                    objectHeader = rawIndirectObjects[j][1]
                    while True:
                        index = auxContent.find(objectHeader)
                        if index == -1:
                            relativeOffset = index
                            break
                        relativeOffset += index
                        checkHeader = bodyContent[relativeOffset-1:relativeOffset+len(objectHeader)]
                        if not re.match('\d{1,10}'+objectHeader, checkHeader):
                            break
                        else:
                            auxContent = auxContent[index+len(objectHeader):]
                            relativeOffset += len(objectHeader)
                    ret = self.createPDFIndirectObject(rawObject, forceMode, looseMode)
                    if ret[0] != -1:
                        pdfIndirectObject = ret[1]
                        if pdfIndirectObject is not None:
                            if relativeOffset == -1:
                                pdfIndirectObject.setOffset(relativeOffset)
                            else:
                                pdfIndirectObject.setOffset(bodyOffset + relativeOffset)
                            ret = body.registerObject(pdfIndirectObject)
                            if ret[0] == -1:
                                log.error(ret[1])
                            type = ret[1]
                            pdfObject = pdfIndirectObject.getObject()
                            if pdfObject is not None:
                                objectType = pdfObject.getType()
                                if objectType == 'dictionary':
                                    if isFirstBody and not linearizedFound:
                                        if pdfObject.hasElement('/Linearized'):
                                            pdfFile.setLinearized(True)
                                            linearizedFound = True
                                elif objectType == 'stream' and type == '/XRef':
                                    xrefObject = pdfIndirectObject
                                    ret = self.createPDFCrossRefSectionFromStream(pdfIndirectObject)
                                    if ret[0] != -1:
                                        xrefStreamSection = ret[1]
                            else:
                                log.error("Object is None."
                                          "Happen while parsing indirect object (offset: {})".format(
                                              pdfIndirectObject.getOffset())
                                          )
                                if not forceMode:
                                    sys.exit()
                        else:
                            log.error("Indirect object is None")
                            if not forceMode:
                                sys.exit()
                    else:
                        log.error("Error parsing object: {0} ({1})".format(objectHeader, ret[1]))
                        if not forceMode:
                            sys.exit()
            else:
                log.error("No indirect objects found in the body")
            if pdfIndirectObject is not None:
                body.setNextOffset(pdfIndirectObject.getOffset())
            ret = body.updateObjects()
            if ret[0] == -1:
                log.error(ret[1])
            pdfFile.addBody(body)
            pdfFile.addNumObjects(body.getNumObjects())
            pdfFile.addNumStreams(body.getNumStreams())
            pdfFile.addNumURIs(body.getNumURIs())
            pdfFile.addNumEncodedStreams(body.getNumEncodedStreams())
            pdfFile.addNumDecodingErrors(body.getNumDecodingErrors())
            isFirstBody = False

            # Converting the cross reference table content in PDFObjects
            if xrefContent is not None:
                ret = self.createPDFCrossRefSection(xrefContent, xrefOffset)
                if ret[0] != -1:
                    xrefSection = ret[1]
            pdfFile.addCrossRefTableSection([xrefSection, xrefStreamSection])

            # Converting the trailer content in PDFObjects
            if body.containsXrefStreams():
                ret = self.createPDFTrailerFromStream(xrefObject, trailerContent)
                if ret[0] != -1:
                    streamTrailer = ret[1]
                ret = self.createPDFTrailer(trailerContent, trailerOffset, streamPresent=True)
                if ret[0] != -1:
                    trailer = ret[1]
                if streamTrailer is not None and not pdfFile.isEncrypted():
                    encryptDict = streamTrailer.getDictEntry('/Encrypt')
                    if encryptDict is not None:
                        pdfFile.setEncrypted(True)
                    elif trailer is not None:
                        encryptDict = trailer.getDictEntry('/Encrypt')
                        if encryptDict is not None:
                            pdfFile.setEncrypted(True)
                    if trailer is not None:
                        fileId = trailer.getDictEntry('/ID')
                    if fileId is None:
                        fileId = streamTrailer.getDictEntry('/ID')
            else:
                ret = self.createPDFTrailer(trailerContent, trailerOffset)
                if ret[0] != -1 and not pdfFile.isEncrypted():
                    trailer = ret[1]
                    encryptDict = trailer.getDictEntry('/Encrypt')
                    if encryptDict is not None:
                        pdfFile.setEncrypted(True)
                    fileId = trailer.getDictEntry('/ID')
            if pdfFile.getEncryptDict() is None and encryptDict is not None:
                log.debug("PDF is encrypted")
                objectType = encryptDict.getType()
                if objectType == 'reference':
                    encryptDictId = encryptDict.getId()
                    encryptObject = pdfFile.getObject(encryptDictId, i)
                    if encryptObject is not None:
                        objectType = encryptObject.getType()
                        encryptDict = encryptObject
                    else:
                        if i == pdfFile.updates:
                            log.error("/Encrypt dictionary not found")
                if objectType == 'dictionary':
                    pdfFile.setEncryptDict([encryptDictId, encryptDict.getElements()])

            if fileId is not None and pdfFile.getFileId() == '':
                objectType = fileId.getType()
                if objectType == 'array':
                    fileIdElements = fileId.getElements()
                    if fileIdElements is not None and fileIdElements != []:
                        if fileIdElements[0] is not None:
                            fileId = fileIdElements[0].getValue()
                            pdfFile.setFileId(fileId)
                        elif fileIdElements[1] is not None:
                            fileId = fileIdElements[1].getValue()
                            pdfFile.setFileId(fileId)
            pdfFile.addTrailer([trailer, streamTrailer])
        if pdfFile.isEncrypted() and pdfFile.getEncryptDict() is not None:
            ret = pdfFile.decrypt()
            if ret[0] == -1:
                log.error(ret[1])
            else:
                log.debug("PDF file decryption success")
        return (0, pdfFile)

    def parsePDFSections(self, content, forceMode=False, looseMode=False):
        '''
            Method to parse the different sections of a version of a PDF document.
            @param content The raw content of the version of the PDF document.
            @param forceMode Boolean to specify if ignore errors or not. Default value: False.
            @param looseMode Boolean to set the loose mode when parsing objects. Default value: False.
            @return An array with the different sections found: body, trailer and cross reference table
        '''
        bodyContent = None
        xrefContent = None
        trailerContent = None

        global pdfFile
        indexTrailer = content.find('trailer')
        if indexTrailer != -1:
            restContent = content[:indexTrailer]
            auxTrailer = content[indexTrailer:]
            indexEOF = auxTrailer.find('%%EOF')
            if indexEOF == -1:
                trailerContent = auxTrailer
            else:
                trailerContent = auxTrailer[:indexEOF+5]
            indexXref = restContent.find('xref')
            if indexXref != -1:
                bodyContent = restContent[:indexXref]
                xrefContent = restContent[indexXref:]
            else:
                bodyContent = restContent
                if forceMode:
                    log.error("Xref section not found")
            return [bodyContent, xrefContent, trailerContent]

        indexTrailer = content.find('startxref')
        if indexTrailer != -1:
            restContent = content[:indexTrailer]
            auxTrailer = content[indexTrailer:]
            indexEOF = auxTrailer.find('%%EOF')
            if indexEOF == -1:
                trailerContent = auxTrailer
            else:
                trailerContent = auxTrailer[:indexEOF+5]
            bodyContent = restContent
            return [bodyContent, xrefContent, trailerContent]

        return [content, xrefContent, trailerContent]

    def createPDFIndirectObject(self, rawIndirectObject, forceMode=False, looseMode=False):
        '''
            Create a PDFIndirectObject instance from the raw content of the PDF file
            @param rawIndirectObject string with the raw content of the PDF body.
            @param forceMode specifies if the parsing process should ignore errors or not (boolean).
            @param looseMode specifies if the parsing process should search for the endobj tag or not (boolean).
            @return A tuple (status,statusContent), where statusContent is the PDFIndirectObject in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        self.charCounter = 0
        pdfIndirectObject = PDFIndirectObject()
        ret, id = self.readUntilNotRegularChar(rawIndirectObject)
        pdfIndirectObject.setId(int(id))
        ret, genNum = self.readUntilNotRegularChar(rawIndirectObject)
        pdfIndirectObject.setGenerationNumber(int(genNum))
        ret = self.readSymbol(rawIndirectObject, 'obj')
        if ret[0] == -1:
            return ret
        rawObject = rawIndirectObject[self.charCounter:]
        ret = self.readObject(rawObject, forceMode=forceMode, looseMode=looseMode)
        if ret[0] == -1:
            return ret
        object = ret[1]
        pdfIndirectObject.setObject(object)
        ret = self.readSymbol(rawIndirectObject, 'endobj', False)
        pdfIndirectObject.setSize(self.charCounter)
        pdfFile.setMaxObjectId(id)
        return (0, pdfIndirectObject)

    def createPDFArray(self, rawContent):
        '''
            Create a PDFArray instance from the raw content of the PDF file
            @param rawContent string with the raw content of the PDF body.
            @return A tuple (status,statusContent), where statusContent is the PDFArray in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        realCounter = self.charCounter
        self.charCounter = 0
        elements = []
        ret = self.readObject(rawContent)
        if ret[0] == -1:
            pdfObject = None
            # TODO create Exception specific
            if ret[1] != 'Empty content reading object':
                log.error(ret[1])
                if not isForceMode:
                    return ret
        else:
            pdfObject = ret[1]
        while pdfObject is not None:
            elements.append(pdfObject)
            ret = self.readObject(rawContent[self.charCounter:])
            if ret[0] == -1:
                pdfObject = None
                if ret[1] != 'Empty content reading object':
                    log.error(ret[1])
                    if not isForceMode:
                        return ret
            else:
                pdfObject = ret[1]
        try:
            pdfArray = PDFArray(rawContent, elements)
        except Exception as e:
            errorMessage = 'Error creating PDFArray'
            if e.message != '':
                errorMessage += ': '+e.message
            return (-1, errorMessage)
        self.charCounter = realCounter
        return (0, pdfArray)

    def createPDFDictionary(self, rawContent):
        '''
            Create a PDFDictionary instance from the raw content of the PDF file
            @param rawContent string with the raw content of the PDF body.
            @return A tuple (status,statusContent), where statusContent is the PDFDictionary in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = {}
        rawNames = {}
        ret = self.readObject(rawContent[self.charCounter:], 'name')
        if ret[0] == -1:
            name = None
            if ret[1] != 'Empty content reading object':
                log.error(ret[1])
                if not isForceMode:
                    return ret
        else:
            name = ret[1]
        while name is not None:
            key = name.getValue()
            rawNames[key] = name
            rawValue = rawContent[self.charCounter:]
            ret = self.readObject(rawValue)
            if ret[0] == -1:
                log.error("Bad object for {} key [[{}]]".format(key, ret[1]))
                if isForceMode:
                    ret = self.readUntilSymbol(rawContent, '/')
                    if ret[0] == -1:
                        elements[key] = PDFString(rawValue)
                    else:
                        elements[key] = PDFString(ret[1])
                    self.readSpaces(rawContent)
                else:
                    return (-1, 'Bad object for '+str(key)+' key')
            else:
                value = ret[1]
                elements[key] = value
            ret = self.readObject(rawContent[self.charCounter:], 'name')
            if ret[0] == -1:
                name = None
                if ret[1] != 'Empty content reading object':
                    log.error(ret[1])
                    if not isForceMode:
                        return ret
            else:
                name = ret[1]
                if name is not None and name.getType() != 'name':
                    errorMessage = 'Name object not found in dictionary key'
                    name = None
                    log.error(errorMessage)
                    if not isForceMode:
                        return (-1, errorMessage)
        try:
            pdfDictionary = PDFDictionary(rawContent, elements, rawNames)
        except Exception as e:
            errorMessage = 'Error creating PDFDictionary'
            if e.message != '':
                errorMessage += ': '+e.message
            return (-1, errorMessage)
        self.charCounter = realCounter
        return (0, pdfDictionary)

    def createPDFStream(self, dict, stream):
        '''
            Create a PDFStream or PDFObjectStream instance from the raw content of the PDF file
            @param dict Raw content of the dictionary object.
            @param stream Raw content of the stream.
            @return A tuple (status,statusContent), where statusContent is the PDFStream or PDFObjectStream in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = {}
        rawNames = {}
        ret = self.readObject(dict[self.charCounter:], 'name')
        if ret[0] == -1:
            name = None
            if ret[1] != 'Empty content reading object':
                log.error(ret[1])
                if not isForceMode:
                    return ret
        else:
            name = ret[1]
        while name is not None:
            key = name.getValue()
            rawNames[key] = name
            ret = self.readObject(dict[self.charCounter:])
            if ret[0] == -1:
                value = None
                if ret[1] != 'Empty content reading object':
                    log.error(ret[1])
                    if not isForceMode:
                        return ret
            else:
                value = ret[1]
            elements[key] = value
            ret = self.readObject(dict[self.charCounter:], 'name')
            if ret[0] == -1:
                name = None
                if ret[1] != 'Empty content reading object':
                    log.error(ret[1])
                    if not isForceMode:
                        return ret
            else:
                name = ret[1]
        if "/Type" in elements and elements['/Type'].getValue() == '/ObjStm':
            try:
                pdfStream = PDFObjectStream(dict, stream, elements, rawNames, {})
            except Exception as e:
                errorMessage = 'Error creating PDFObjectStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        else:
            #try:
            pdfStream = PDFStream(dict, stream, elements, rawNames)
            #except Exception as e:
            #    errorMessage = 'Error creating PDFStream'
            #    if e.message != '':
            #        errorMessage += ': '+e.message
            #    return (-1, errorMessage)
        self.charCounter = realCounter
        return (0, pdfStream)

    def createPDFCrossRefSection(self, rawContent, offset):
        '''
            Create a PDFCrossRefSection instance from the raw content of the PDF file
            @param rawContent String with the raw content of the PDF body (string)
            @param offset Offset of the cross reference section in the PDF file (int)
            @return A tuple (status,statusContent), where statusContent is the PDFCrossRefSection in case status = 0 or an error in case status = -1
        '''
        global isForceMode, pdfFile
        if not isinstance(rawContent, str):
            return (-1, 'Empty xref content')
        entries = []
        auxOffset = 0
        subSectionSize = 0
        self.charCounter = 0
        pdfCrossRefSection = PDFCrossRefSection()
        pdfCrossRefSection.setOffset(offset)
        pdfCrossRefSection.setSize(len(rawContent))
        pdfCrossRefSubSection = None
        beginSubSectionRE = re.compile('(\d{1,10})\s(\d{1,10})\s*$')
        entryRE = re.compile('(\d{10})\s(\d{5})\s([nf])')
        ret = self.readSymbol(rawContent, 'xref')
        if ret[0] == -1:
            return ret
        auxOffset += self.charCounter
        lines = self.getLines(rawContent[self.charCounter:])
        if lines == []:
            if isForceMode:
                pdfCrossRefSubSection = PDFCrossRefSubSection(0, offset=-1)
                log.error("No entries in xref section")
            else:
                return (-1, 'No entries in xref section!!')
        else:
            for line in lines:
                match = re.findall(beginSubSectionRE, line)
                if match != []:
                    if pdfCrossRefSubSection is not None:
                        pdfCrossRefSubSection.setSize(subSectionSize)
                        pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
                        pdfCrossRefSubSection.setEntries(entries)
                        subSectionSize = 0
                        entries = []
                    try:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(match[0][0], match[0][1], offset=auxOffset)
                    except Exception as e:
                        return (-1, 'Error creating PDFCrossRefSubSection: {}'.format(e))
                else:
                    match = re.findall(entryRE, line)
                    if match != []:
                        try:
                            pdfCrossRefEntry = PDFCrossRefEntry(match[0][0], match[0][1], match[0][2], offset=auxOffset)
                        except:
                            return (-1, 'Error creating PDFCrossRefEntry')
                        entries.append(pdfCrossRefEntry)
                    else:
                        # TODO: comments in line or spaces/\n\r...?
                        if isForceMode:
                            if pdfCrossRefSubSection is not None:
                                pdfCrossRefSubSection.addError('Bad format for cross reference entry: '+line)
                            else:
                                pdfCrossRefSubSection = PDFCrossRefSubSection(0, offset=-1)
                                log.error("Bad xref section")
                        else:
                            return (-1, 'Bad format for cross reference entry')
                auxOffset += len(line)
                subSectionSize += len(line)
            # TODO this else statement sounds stricly useless, even confusing
            else:
                if not pdfCrossRefSubSection:
                    errMsg = "Missing xref section header"
                    if isForceMode:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(0, len(entries), offset=auxOffset)
                        log.error(errMsg)
                    else:
                        return (-1, errMsg)
        pdfCrossRefSubSection.setSize(subSectionSize)
        pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
        pdfCrossRefSubSection.setEntries(entries)
        return (0, pdfCrossRefSection)

    def createPDFCrossRefSectionFromStream(self, objectStream):
        '''
            Create a PDFCrossRefSection instance from the raw content of the PDF file
            @param objectStream Object stream object (PDFIndirectObject).
            @return A tuple (status,statusContent), where statusContent is the PDFCrossRefSection in case status = 0 or an error in case status = -1
        '''
        index = 0
        firstEntry = 0
        entries = []
        numObjects = 0
        numSubsections = 1
        bytesPerField = [1, 2, 1]
        entrySize = 4
        subsectionIndexes = []
        if objectStream is not None:
            pdfCrossRefSection = PDFCrossRefSection()
            pdfCrossRefSection.setXrefStreamObject(objectStream.getId())
            xrefObject = objectStream.getObject()
            if xrefObject is not None:
                if xrefObject.hasElement('/Size'):
                    sizeObject = xrefObject.getElementByName('/Size')
                    if sizeObject is not None and sizeObject.getType() == 'integer':
                        numObjects = sizeObject.getRawValue()
                        subsectionIndexes = [0, numObjects]
                    else:
                        errorMessage = 'Bad object type for /Size element'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                else:
                    errorMessage = 'Element /Size not found'
                    if isForceMode:
                        pdfCrossRefSection.addError(errorMessage)
                    else:
                        return (-1, errorMessage)

                if xrefObject.hasElement('/W'):
                    bytesPerFieldObject = xrefObject.getElementByName('/W')
                    if bytesPerFieldObject.getType() == 'array':
                        bytesPerField = bytesPerFieldObject.getElementRawValues()
                        if len(bytesPerField) != 3:
                            errorMessage = 'Bad content of /W element'
                            if isForceMode:
                                pdfCrossRefSection.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        else:
                            entrySize = 0
                            for num in bytesPerField:
                                entrySize += num
                    else:
                        errorMessage = 'Bad object type for /W element'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                else:
                    errorMessage = 'Element /W not found'
                    if isForceMode:
                        pdfCrossRefSection.addError(errorMessage)
                    else:
                        return (-1, errorMessage)

                if xrefObject.hasElement('/Index'):
                    subsectionIndexesObject = xrefObject.getElementByName('/Index')
                    if subsectionIndexesObject.getType() == 'array':
                        subsectionIndexes = subsectionIndexesObject.getElementRawValues()
                        if len(subsectionIndexes) % 2 != 0:
                            errorMessage = 'Bad content of /Index element'
                            if isForceMode:
                                pdfCrossRefSection.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        else:
                            numSubsections = len(subsectionIndexes) / 2
                    else:
                        errorMessage = 'Bad object type for /Index element'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)

                pdfCrossRefSection.setBytesPerField(bytesPerField)
                stream = xrefObject.getStream()
                for i in range(0, len(stream), entrySize):
                    entryBytes = stream[i:i+entrySize]
                    try:
                        if bytesPerField[0] == 0:
                            f1 = 1
                        else:
                            f1 = int(entryBytes[:bytesPerField[0]].encode('hex'), 16)
                        if bytesPerField[1] == 0:
                            f2 = 0
                        else:
                            f2 = int(entryBytes[bytesPerField[0]:bytesPerField[0]+bytesPerField[1]].encode('hex'), 16)
                        if bytesPerField[2] == 0:
                            f3 = 0
                        else:
                            f3 = int(entryBytes[bytesPerField[0]+bytesPerField[1]:].encode('hex'), 16)
                    except:
                        errorMessage = 'Error in hexadecimal conversion'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    try:
                        pdfCrossRefEntry = PDFCrossRefEntry(f2, f3, f1)
                    except:
                        errorMessage = 'Error creating PDFCrossRefEntry'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    entries.append(pdfCrossRefEntry)
                for i in range(numSubsections):
                    firstObject = subsectionIndexes[index]
                    numObjectsInSubsection = subsectionIndexes[index+1]
                    try:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(firstObject, numObjectsInSubsection)
                    except:
                        errorMessage = 'Error creating PDFCrossRefSubSection'
                        if isForceMode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    pdfCrossRefSubSection.setEntries(entries[firstEntry:firstEntry+numObjectsInSubsection])
                    pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
                    index += 2
                return (0, pdfCrossRefSection)
            else:
                return (-1, 'The object stream is None')
        else:
            return (-1, 'The indirect object stream is None')

    def createPDFTrailer(self, rawContent, offset, streamPresent=False):
        '''
            Create a PDFTrailer instance from the raw content of the PDF file
            @param rawContent String with the raw content of the PDF body (string)
            @param offset Offset of the trailer in the PDF file (int)
            @param streamPresent It specifies if an object stream exists in the PDF body
            @return A tuple (status,statusContent), where statusContent is the PDFTrailer in case status = 0 or an error in case status = -1
        '''
        global pdfFile, isForceMode
        trailer = None
        self.charCounter = 0
        if not isinstance(rawContent, str):
            return (-1, 'Empty trailer content')
        self.readSymbol(rawContent, 'trailer')
        ret = self.readObject(rawContent[self.charCounter:], 'dictionary')
        if ret[0] == -1:
            dict = PDFDictionary('')
            dict.addError('Error creating the trailer dictionary')
        else:
            dict = ret[1]
        ret = self.readSymbol(rawContent, 'startxref')
        if ret[0] == -1:
            try:
                trailer = PDFTrailer(dict, streamPresent=streamPresent)
            except Exception as e:
                errorMessage = 'Error creating PDFTrailer'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        else:
            ret = self.readUntilEndOfLine(rawContent)
            if ret[0] == -1:
                log.error("EOL not found while looking for the last cross reference section")
                if not isForceMode:
                    return (-1, 'EOL not found while looking for the last cross reference section')
                lastXrefSection = -1
            else:
                lastXrefSection = ret[1]
            try:
                trailer = PDFTrailer(dict, lastXrefSection, streamPresent=streamPresent)
            except Exception as e:
                errorMessage = 'Error creating PDFTrailer'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        trailer.setOffset(offset)
        eofOffset = rawContent.find('%%EOF')
        if eofOffset == -1:
            trailer.setEOFOffset(eofOffset)
            trailer.setSize(len(rawContent))
        else:
            trailer.setEOFOffset(offset+eofOffset)
            trailer.setSize(eofOffset)
        return (0, trailer)

    def createPDFTrailerFromStream(self, indirectObject, rawContent):
        '''
            Create a PDFTrailer instance from the raw content of the PDF file
            @param indirectObject Object stream object (PDFIndirectObject).
            @param rawContent String with the raw content of the PDF body (string)
            @return A tuple (status,statusContent), where statusContent is the PDFTrailer in case status = 0 or an error in case status = -1
        '''
        trailer = None
        self.charCounter = 0
        trailerElements = ['/Size', '/Prev', '/Root', '/Encrypt', '/Info', '/ID']
        dict = {}
        if indirectObject is not None:
            xrefStreamObject = indirectObject.getObject()
            if xrefStreamObject is not None:
                for element in trailerElements:
                    if xrefStreamObject.hasElement(element):
                        dict[element] = xrefStreamObject.getElementByName(element)
                try:
                    dict = PDFDictionary('', dict)
                except Exception as e:
                    if isForceMode:
                        dict = None
                    else:
                        errorMessage = 'Error creating PDFDictionary'
                        if e.message != '':
                            errorMessage += ': '+e.message
                        return (-1, errorMessage)
                if not isinstance(rawContent, str):
                    if isForceMode:
                        lastXrefSection = -1
                    else:
                        return (-1, 'Empty trailer content')
                else:
                    ret = self.readUntilSymbol(rawContent, 'startxref')
                    if ret[0] == -1 and not isForceMode:
                        return ret
                    ret = self.readSymbol(rawContent, 'startxref')
                    if ret[0] == -1 and not isForceMode:
                        return ret
                    ret = self.readUntilEndOfLine(rawContent)
                    if ret[0] == -1:
                        if not isForceMode:
                            return ret
                        lastXrefSection = -1
                    else:
                        lastXrefSection = ret[1]
                try:
                    trailer = PDFTrailer(dict, lastXrefSection)
                except Exception as e:
                    errorMessage = 'Error creating PDFTrailer'
                    if e.message != '':
                        errorMessage += ': '+e.message
                    return (-1, errorMessage)
                trailer.setXrefStreamObject(indirectObject.getId())
            else:
                return (-1, 'Object stream is None')
        else:
            return (-1, 'Indirect object stream is None')
        return (0, trailer)

    def getIndirectObjects(self, content, looseMode=False):
        '''
            This function returns an array of raw indirect objects of the PDF file given the raw body.
            @param content: string with the raw content of the PDF body.
            @param looseMode: boolean specifies if the parsing process should search for the endobj tag or not.
            @return matchingObjects: array of tuples (object_content,object_header).
        '''
        global pdfFile
        matchingObjects = []
        if not isinstance(content, str):
            return matchingObjects
        if not looseMode:
            regExp = re.compile('((\d{1,10}\s\d{1,10}\sobj).*?endobj)', re.DOTALL)
            matchingObjects = regExp.findall(content)
        else:
            regExp = re.compile('((\d{1,10}\s\d{1,10}\sobj).*?)\s\d{1,10}\s\d{1,10}\sobj', re.DOTALL)
            matchingObjectsAux = regExp.findall(content)
            while matchingObjectsAux != []:
                if matchingObjectsAux[0] != []:
                    objectBody = matchingObjectsAux[0][0]
                    matchingObjects.append(matchingObjectsAux[0])
                    content = content[content.find(objectBody)+len(objectBody):]
                    matchingObjectsAux = regExp.findall(content)
                else:
                    matchingObjectsAux = []
            lastObject = re.findall('(\d{1,5}\s\d{1,5}\sobj)', content, re.DOTALL)
            if lastObject != []:
                content = content[content.find(lastObject[0]):]
                matchingObjects.append((content, lastObject[0]))
        return matchingObjects

    def getLines(self, content):
        '''
            Simple function to return the lines separated by end of line characters
            @param content
            @return List with the lines, without end of line characters
        '''
        lines = []
        i = 0
        while i < len(content):
            if content[i] == '\r':
                lines.append(content[:i])
                if content[i+1] == '\n':
                    i += 1
                content = content[i+1:]
                i = 0
            elif content[i] == '\n':
                lines.append(content[:i])
                content = content[i+1:]
                i = 0
            i += 1
        if i > 0:
            lines.append(content)
        return lines

    def readObject(self, content, objectType=None, forceMode=False, looseMode=False):
        '''
            Method to parse the raw body of the PDF file and obtain PDFObject instances
            @param content
            @param objectType
            @param forceMode
            @param looseMode
            @return A tuple (status,statusContent), where statusContent is a PDFObject instance in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if len(content) == 0 or content[:6] == 'endobj':
            return (-1, 'Empty content reading object')
        pdfObject = None
        oldCounter = self.charCounter
        self.charCounter = 0
        if objectType is not None:
            objectsTypeArray = [self.delimiters[i][2] for i in range(len(self.delimiters))]
            index = objectsTypeArray.index(objectType)
            if index != -1:
                delimiters = [self.delimiters[index]]
            else:
                errMSg = "Unknown object type"
                if isForceMode:
                    log.error(errMsg)
                    return (-1, errMsg)
                else:
                    sys.exit()
        else:
            delimiters = self.delimiters
        for delim in delimiters:
            ret = self.readSymbol(content, delim[0], False if delim[0] == '(' else True)
            if ret[0] != -1:
                if delim[2] == 'dictionary':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] == -1:
                        dictContent = ''
                    else:
                        dictContent = ret[1]
                    nonDictContent = content[self.charCounter:]
                    streamFound = re.findall('[>\s]stream', nonDictContent)
                    if streamFound:
                        ret = self.readUntilSymbol(content, 'stream')
                        if ret[0] == -1:
                            return ret
                        self.readSymbol(content, 'stream', False)
                        self.readUntilEndOfLine(content)
                        self.readSymbol(content, '\r', False)
                        self.readSymbol(content, '\n', False)
                        ret = self.readUntilSymbol(content, 'endstream')
                        if ret[0] == -1:
                            stream = content[self.charCounter:]
                        else:
                            stream = ret[1]
                            self.readSymbol(content, 'endstream')
                        ret = self.createPDFStream(dictContent, stream)
                        if ret[0] == -1:
                            return ret
                        pdfObject = ret[1]
                        break
                    else:
                        if ret[0] != -1:
                            self.readSymbol(content, delim[1])
                            ret = self.createPDFDictionary(dictContent)
                            if ret[0] == -1:
                                return ret
                            pdfObject = ret[1]
                        else:
                            pdfObject = PDFDictionary(content)
                            pdfObject.addError('Closing delimiter not found in dictionary object')
                        break
                elif delim[2] == 'string':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        stringContent = ret[1]
                        self.readSymbol(content, delim[1])
                        pdfObject = PDFString(stringContent)
                    else:
                        pdfObject = PDFString(content)
                        pdfObject.addError('Closing delimiter not found in string object')
                    break
                elif delim[2] == 'hexadecimal':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        hexContent = ret[1]
                        self.readSymbol(content, delim[1])
                        pdfObject = PDFHexString(hexContent)
                    else:
                        pdfObject = PDFHexString(content)
                        pdfObject.addError('Closing delimiter not found in hexadecimal object')
                    break
                elif delim[2] == 'array':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        arrayContent = ret[1]
                        self.readSymbol(content, delim[1])
                        ret = self.createPDFArray(arrayContent)
                        if ret[0] == -1:
                            return ret
                        pdfObject = ret[1]
                    else:
                        pdfObject = PDFArray(content)
                        pdfObject.addError('Closing delimiter not found in array object')
                    break
                elif delim[2] == 'name':
                    ret, raw = self.readUntilNotRegularChar(content)
                    pdfObject = PDFName(raw)
                    break
                elif delim[2] == 'comment':
                    ret = self.readUntilEndOfLine(content)
                    if ret[0] == 0:
                        self.comments.append(ret[1])
                        self.readSpaces(content)
                        pdfObject = self.readObject(content[self.charCounter:], objectType)
                    else:
                        return ret
                    break
        else:
            if content[0] == 't' or content[0] == 'f':
                ret, raw = self.readUntilNotRegularChar(content)
                pdfObject = PDFBool(raw)
            elif content[0] == 'n':
                ret, raw = self.readUntilNotRegularChar(content)
                pdfObject = PDFNull(raw)
            elif re.findall('^(\d{1,10}\s{1,3}\d{1,10}\s{1,3}R)', content, re.DOTALL) != []:
                ret, id = self.readUntilNotRegularChar(content)
                ret, genNumber = self.readUntilNotRegularChar(content)
                ret = self.readSymbol(content, 'R')
                if ret[0] == -1:
                    return ret
                pdfObject = PDFReference(id, genNumber)
            elif re.findall('^([-+]?\.?\d{1,15}\.?\d{0,15})', content, re.DOTALL) != []:
                ret, num = self.readUntilNotRegularChar(content)
                pdfObject = PDFNum(num)
            else:
                self.charCounter += oldCounter
                return (-1, 'Object not found')
        self.charCounter += oldCounter
        return (0, pdfObject)

    def readSpaces(self, string):
        '''
            Reads characters until all spaces chars have been read
            @param string
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(string, str):
            return (-1, 'Bad string')
        spacesCounter = self.charCounter
        for i in range(self.charCounter, len(string)):
            if string[i] not in spacesChars:
                break
            self.charCounter += 1
        spacesCounter -= self.charCounter
        return (0, spacesCounter)

    def readSymbol(self, string, symbol, deleteSpaces=True):
        '''
            Reads a given symbol from the string, removing comments and spaces (if specified)
            @param string
            @param symbol
            @param deleteSpaces
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(string, str):
            return (-1, 'Bad string')
        oldCharCounter = self.charCounter
        if self.charCounter > len(string)-1:
            errorMessage = 'EOF while looking for symbol "'+symbol+'"'
            log.error(errorMessage)
            return (-1, errorMessage)
        while string[self.charCounter] == '%':
            ret = self.readUntilEndOfLine(string)
            if ret[0] == -1:
                return ret
            self.comments.append(ret[1])
            self.readSpaces(string)
        symbolToRead = string[self.charCounter:self.charCounter+len(symbol)]
        if symbolToRead != symbol:
            errorMessage = 'Symbol "'+symbol+'" not found while parsing'
            log.debug(errorMessage)
            return (-1, errorMessage)
        self.charCounter += len(symbol)
        if deleteSpaces:
            self.readSpaces(string)
        return (0, self.charCounter - oldCharCounter)

    def readUntilClosingDelim(self, content, delim):
        '''
            Method that reads characters until it finds the closing delimiter
            @param content
            @param delim
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        output = ''
        if not isinstance(content, str):
            return (-1, 'Bad string')
        newContent = content[self.charCounter:]
        numClosingDelims = newContent.count(delim[1])
        if numClosingDelims == 0:
            errorMessage = 'No closing delimiter found'
            log.error(errorMessage)
            return (-1, errorMessage)
        elif numClosingDelims == 1:
            index = newContent.rfind(delim[1])
            self.charCounter += index
            return (0, newContent[:index])
        else:
            indexChar = 0
            prevChar = ''
            while indexChar != len(newContent):
                char = newContent[indexChar]
                if indexChar == len(newContent) - 1:
                    nextChar = ''
                else:
                    nextChar = newContent[indexChar+1]
                if char == delim[1] or (char + nextChar) == delim[1]:
                    if char != ')' or indexChar == 0 or newContent[indexChar-1] != '\\':
                        return (0, output)
                    else:
                        output += char
                        indexChar += 1
                        self.charCounter += 1
                elif (char == '(' and prevChar != '\\') or (char in ['[', '<'] and delim[0] != '('):
                    if (char + nextChar) != '<<':
                        delimIndex = delimiterChars.index(char)
                        self.charCounter += 1
                        ret = self.readUntilClosingDelim(content, self.delimiters[delimIndex])
                        if ret[0] != -1:
                            tempObject = char + ret[1]
                        else:
                            return ret
                    else:
                        delimIndex = delimiterChars.index(char + nextChar)
                        self.charCounter += 2
                        ret = self.readUntilClosingDelim(content, self.delimiters[delimIndex])
                        if ret[0] != -1:
                            tempObject = char + nextChar + ret[1]
                        else:
                            return ret
                    ret = self.readSymbol(content, self.delimiters[delimIndex][1], False)
                    if ret[0] != -1:
                        tempObject += self.delimiters[delimIndex][1]
                    else:
                        return ret
                    indexChar += len(tempObject)
                    output += tempObject
                else:
                    indexChar += 1
                    self.charCounter += 1
                    output += char
                    prevChar = char
            else:
                errorMessage = 'No closing delimiter found'
                log.error(errorMessage)
                return (-1, errorMessage)

    def readUntilEndOfLine(self, content):
        '''
            This function reads characters until the end of line
            @param content
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(content, str):
            return (-1, 'Bad string')
        errorMessage = []
        oldCharCounter = self.charCounter
        tmpContent = content[self.charCounter:]
        for char in tmpContent:
            if char == '\r' or char == '\n':
                return (0, content[oldCharCounter:self.charCounter])
            self.charCounter += 1
        else:
            errorMessage = 'EOL not found'
            log.error(errorMessage)
            return (-1, errorMessage)

    def readUntilLastSymbol(self, string, symbol):
        '''
            Method that reads characters until it finds the last appearance of 'symbol'
            @param string
            @param symbol
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(string, str):
            return (-1, 'Bad string')
        newString = string[self.charCounter:]
        index = newString.rfind(symbol)
        if index == -1:
            errorMessage = 'Symbol "'+symbol+'" not found'
            log.error(errorMessage)
            return (-1, errorMessage)
        self.charCounter += index
        return (0, newString[:index])

    def readUntilNotRegularChar(self, string):
        '''
            Reads the regular chars of the string until it reachs a non-regular char. Then it removes spaces chars.
            @param string
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        readChars = ''
        if not isinstance(string, str):
            return (-1, 'Bad string')
        notRegChars = spacesChars + delimiterChars
        for i in range(self.charCounter, len(string)):
            if string[i] in notRegChars:
                self.readSpaces(string)
                break
            readChars += string[i]
            self.charCounter += 1
        return (0, readChars)

    def readUntilSymbol(self, string, symbol):
        '''
            Method that reads characters until it finds the first appearance of 'symbol'
            @param string
            @param symbol
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        global pdfFile
        if not isinstance(string, str):
            return (-1, 'Bad string')
        newString = string[self.charCounter:]
        index = newString.find(symbol)
        if index == -1:
            errorMessage = 'Symbol "'+symbol+'" not found'
            return (-1, errorMessage)
        self.charCounter += index
        return (0, newString[:index])
