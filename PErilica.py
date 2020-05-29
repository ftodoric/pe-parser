import os
import sys

#===============================================================================================
#PE Parser
#=========
#
#Program for parsing and viewing the internal binary structure of executable files in PE format.
#64bit applications not supported. Developed in Python 3.7.1.
#
#@date: 31 June 2019
#@version: Python 3.7.1
#@author: ftodoric
#===============================================================================================

DISPLAY_LAYOUT_WIDTH = 35

#PE FILE CONSTANTS (in bytes)
MZ_HEADER_SIZE = int("0x40", 16)
PE_HEADER_OFFSET_ADDR = int("0x3C", 16)
PE_HEADER_SIZE = int("0x14", 16)
SECTION_HEADER_SIZE = int("0x28", 16)
IMPORT_DIRECTORY_SIZE = int("0x14", 16)

def readBytes(file, numberOfBytes):
    hexString = ""
    for i in range(numberOfBytes):
        nextByte = format(ord(file.read(1)), 'x')
        if (len(nextByte) == 1):
            nextByte = '0' + nextByte
        hexString += nextByte
    return hexString

def reverseBytes(hexString):
    reversedBytes = ""
    for i in range(len(hexString)-1, -1, -2):
        if (i != 0):
            reversedBytes += (hexString[i-1] + hexString[i])
    return reversedBytes

def hexFormat(hexString): #for example: 0x0036, 0x000034fa, ...
    return '0x' + hexString

def layoutPrint(firstString, secondString): #for tabular display of data
    spaces = ""
    for i in range(DISPLAY_LAYOUT_WIDTH - len(firstString)):
        spaces += ' '
    print("    " + firstString + spaces + secondString, end = '')

def hexStringToASCII(hexString):
    asciiString = ""
    i = 0
    while (i != len(hexString)):
        hexPart = hexString[i] + hexString[i+1]
        if (hexPart != '00'):
            asciiString += chr(int(hexPart, 16))
        i += 2
    return asciiString


#Function "calcPhysOffset"  first searches for section in which rightful section RVA is found,
#then calculates offset address based on RVA, section RVA and Pointer to Raw Data.
#
#@param:
#   sections - map for sections' data in form of: {section name : [list of all essential data]}
#   RVA - relative virtual address to be calculated into physical offset
#
#@author: Physx
def calcPhysOffset(sections, RVA):
    for key in sections:
        virtualSize = sections[key][0]
        sectionRVA = sections[key][1]
        pointerToRawData = sections[key][3]
        if ((int(sectionRVA, 16) <= (int(RVA, 16))) and (int(sectionRVA, 16) + int(virtualSize, 16) - 1) >= (int(RVA, 16))):
            break
    
    RVA = int(RVA, 16)
    sectionRVA = int(sectionRVA, 16)
    pointerToRawData = int(pointerToRawData, 16)
    result = format(RVA - sectionRVA + pointerToRawData, 'x')
    if (len(result) < 8):
        for i in range(8 - len(result)):
            result = '0' + result
    return result

def fourDigitString(hexString):
    if (len(hexString) != 4):
        for i in range(4 - len(hexString)):
            hexString = '0' + hexString
    return hexString
    
def main():
    print("PErilica" + chr(0x2122) + "    by Physx")
    print()
    
    #PE file can be drag and dropped on this .py file (if not drag and dropped, must be input in console)
    try:
        filepath = sys.argv[1]
        pe_file = open(filepath, "br")
        directories = filepath.split("\\")
        print(directories[len(directories)-1].upper() + " " + "="*80)
        print()
    except:
        print("Input file path: ", end = '')
        filepath = input()
        try:
            pe_file = open(filepath, "br"); print()
            if ("/" in filepath):
                directories = filepath.split("/")
            else:
                directories = filepath.split("\\")
            print(directories[len(directories)-1].upper() + " " + "="*80)
            print()
        except:
            print("Error: This File Doesn't Exist!")
            return

    #CHECKING IF THE LOADED FILE IS IN PE FORMAT AND 32BIT APPLICATION==========
    mz = reverseBytes(readBytes(pe_file, 2))
    if not(mz == "5a4d" or mz == "5A4D"):
        print("Error: Not PE File Format! Program Terminated.")
        return
    pe_file.seek(PE_HEADER_OFFSET_ADDR)
    pe_header_offset = reverseBytes(readBytes(pe_file, 4))
    pe_file.seek(int(pe_header_offset, 16) + 4)
    machine = reverseBytes(readBytes(pe_file, 2))
    if not(machine == "014c" or machine == "014C"):
        print("Error: 64-bit Applications Not Supported! Program Terminated.")
        return
    #===========================================================================
    pe_file.seek(0)

    #MZ HEADER LOADING
    mz_header = {"Signature": "", "Bytes on Last Page of File": "", "Pages in File": "", "Relocations": "", "Size of Header in Paragraphs": "", "Minimum Extra Paragraphs": "", "Maximum Extra Paragraphs": "", "Initial (relative) SS": "", "Initial SP": "", "Checksum": "", "Initial IP": "", "Initial (relative) CS": "", "Offset to Relocation Table": "", "Overlay Number": ""}
    for i in range(0, MZ_HEADER_SIZE, 2):
        for key in mz_header:
            if (mz_header[key] == ""):
                mz_header[key] = reverseBytes(readBytes(pe_file, 2))
                break

    #PE HEADER LOADING
    pe_file.seek(int(pe_header_offset, 16))
    pe_header = {"Signature": "", "Machine": "", "Number of Sections": "", "Time Date Stamp": "", "Pointer to Symbol Table": "", "Number of Symbols": "", "Size of Optional Header": "", "Characteristics": ""}
    for i in range(8):
        for key in pe_header:
            if (pe_header[key] == ""):
                if (i == 0 or i == 3 or i == 4 or i == 5):
                    pe_header[key] = reverseBytes(readBytes(pe_file, 4))
                    i += 2
                    break
                else:
                    pe_header[key] = reverseBytes(readBytes(pe_file, 2))
                    break

    #OPTIONAL HEADER LOADING
    optionalHeaderSize = int(pe_header["Size of Optional Header"], 16)
    opt_header = {"Magic": "", "Major Linker Version": "", "Minor Linker Version": "", "Size of Code": "", "Size of Initialized Data": "", "Size of Unitialized Data": "", "Address of Entry Point": "", "Base of Code": "", "Base of Data": "", "Image Base": "", "Section Alignment": "", "File Alignment": "", "Major O/S Version": "", "Minor O/S Version": "", "Major Image Version": "", "Minor Image Version": "", "Major Subsystem Version": "", "Minor Subsystem Version": "", "Win32 Version Value": "", "Size of Image": "", "Size of Headers": "", "Checksum": "", "Subsystem": "", "DLL Characteristics": "", "Size of Stack Reserve": "", "Size of Stack Commit": "", "Size of Heap Reserve": "", "Size of Heap Commit": "", "Loader Flags": "", "Number of Data Directories": "", "RVA    EXPORT Table": "", "Size   EXPORT Table": "", "RVA    IMPORT Table": "", "Size   IMPORT Table": ""}
    for i in range(62):
        for key in opt_header:
            if (opt_header[key] == ""):
                if (i == 1 or i == 2):
                    opt_header[key] = reverseBytes(readBytes(pe_file, 1))
                    break
                elif (i == 0 or (i >= 12 and i <= 17) or i == 22 or i == 23):
                    opt_header[key] = reverseBytes(readBytes(pe_file, 2))
                    break
                else:
                    opt_header[key] = reverseBytes(readBytes(pe_file, 4))
                    break
        if (i >= 34):
            pe_file.seek(4, 1)

    #SECTION HEADERS LOADING
    sections = {} # structure --> { sectionName : [list of all data in this section] }
    numberOfSections = int(pe_header["Number of Sections"], 16)     
    for i in range(numberOfSections):
        sectionName = hexStringToASCII(readBytes(pe_file, 8))
        sections[sectionName] = ["" for j in range(9)]
        for j in range(9):
            if (j == 6 or j == 7):
                sections[sectionName][j] = reverseBytes(readBytes(pe_file, 2))
            else:
                sections[sectionName][j] = reverseBytes(readBytes(pe_file, 4))
        
    #PRINTING MZ HEADER
    print("MZ Header")
    print("=========")
    for key in mz_header:
        layoutPrint(key + ":", hexFormat(mz_header[key]))
        if (key == "Signature"):
            print(" --> \"MZ\"", end = '')
        print()
    print()
    
    #PRINTING PE HEADER
    print("PE Header")
    print("=========")
    for key in pe_header:
        layoutPrint(key + ":", hexFormat(pe_header[key]))
        if (key == "Signature"):
            print(" --> \"PE\"", end = '')
        print()
    print()

    #PRINTING OPTIONAL HEADER
    print("Optional Header")
    print("===============")
    for key in opt_header:
        layoutPrint(key + ":", hexFormat(opt_header[key]))
        if (key == "Address of Entry Point"):
            print(" (phys: " + hexFormat(calcPhysOffset(sections, opt_header["Address of Entry Point"])) + ")", end = '')
        print()
    print()

    #PRINTING SECTION HEADERS
    print("Section Headers")
    print("===============")
    for key in sections:
        layoutPrint("Name:", key); print()
        layoutPrint("Virtual Size:", hexFormat(sections[key][0])); print()
        layoutPrint("RVA:", hexFormat(sections[key][1])); print()
        layoutPrint("Size of Raw Data:", hexFormat(sections[key][2])); print()
        layoutPrint("Pointer to Raw Data:", hexFormat(sections[key][3])); print()
        layoutPrint("Pointer to Relocations:", hexFormat(sections[key][4])); print()
        layoutPrint("Pointer to Line Numbers:", hexFormat(sections[key][5])); print()
        layoutPrint("Number of Relocations:", hexFormat(sections[key][6])); print()
        layoutPrint("Number of Line Numbers:", hexFormat(sections[key][7])); print()
        layoutPrint("Characteristics:", hexFormat(sections[key][8])); print()
        print()

    #EXPORT TABLE DATA FOR ORDINALS
    exportTableRVA = opt_header["RVA    EXPORT Table"]
    if (exportTableRVA != '00'*4):
        pe_file.seek(int(calcPhysOffset(sections, exportTableRVA), 16) + 16)
        ordBase = reverseBytes(readBytes(pe_file, 4))
        pe_file.seek(16, 1)
        ordTableRVA = reverseBytes(readBytes(pe_file, 4))
        ordTableOffset = calcPhysOffset(sections, ordTableRVA)
        pe_file.seek(-8, 1)
        exportNamePointerTableRVA = reverseBytes(readBytes(pe_file, 4))
        exportNamePointerTableOffset = calcPhysOffset(sections, exportNamePointerTableRVA)

    #IMPORT TABLE
    importTableRVA = opt_header["RVA    IMPORT Table"]
    importTableOffset = int(calcPhysOffset(sections, importTableRVA), 16)
    pe_file.seek(importTableOffset)
    print("IMPORT Table")
    print("============")
    next20Bytes = readBytes(pe_file, 20)
    while (next20Bytes != '00'*20): #20 Bytes of Zeroes = End of Import Directory
        pe_file.seek(-20, 1)

        #PRINTING IMPORT DIRECTORY
        layoutPrint("Import Directory", ""); print()
        layoutPrint("================", ""); print()
        importNameTableRVA = reverseBytes(readBytes(pe_file, 4))
        layoutPrint("    Import Name Table RVA:", hexFormat(importNameTableRVA)); print()
        layoutPrint("    Time Date Stamp:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()
        layoutPrint("    Forwarder Chain:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()
        nameRVA = reverseBytes(readBytes(pe_file, 4))
        layoutPrint("    Name RVA:", hexFormat(nameRVA))
        dllNameOffset = calcPhysOffset(sections, nameRVA)
        print(" (phys: " + hexFormat(dllNameOffset) + ")", end = ' --> ')

        #PRINTING DLL NAME===============================
        rememberImportDirOffset = pe_file.tell()
        pe_file.seek(int(dllNameOffset, 16))
        nextByte = readBytes(pe_file, 1)
        dllName = ""
        while (nextByte != '00'):
            pe_file.seek(-1, 1)
            dllName += readBytes(pe_file, 1)
            nextByte = readBytes(pe_file, 1)
        print("\"" + hexStringToASCII(dllName) + "\"")
        pe_file.seek(rememberImportDirOffset)
        #================================================

        importAddressTableRVA = reverseBytes(readBytes(pe_file, 4))
        layoutPrint("    Import Address Table RVA:", hexFormat(importAddressTableRVA)); print()

        #PRINTING IMPORT THUNKS==========================
        print()
        layoutPrint("    Import Thunks", ""); print()
        layoutPrint("    =============", ""); print()
        rememberImportDirOffset = pe_file.tell()
        importNameTableOffset = calcPhysOffset(sections, importNameTableRVA)
        pe_file.seek(int(importNameTableOffset, 16))
        
        next4Bytes = readBytes(pe_file, 4)
        offset = 0
        while (next4Bytes != '00'*4):
            pe_file.seek(-4, 1)
            currentNameTableRVA = format(int(importNameTableRVA, 16) + offset, 'x')
            hintNameRVA = reverseBytes(readBytes(pe_file, 4))
            
            #ORDINAL HANDLING=============================================================
            if (hintNameRVA[0] == '8'):
                ordinal = hintNameRVA[4:]
                rememberOrdinal = pe_file.tell()
                
                pe_file.seek(int(ordTableOffset, 16))
                ordinalBytes = ""
                counter = 0
                while (True):
                    ordinalBytes = reverseBytes(readBytes(pe_file, 2))
                    counter += 1
                    if (int(ordinal, 16) == int(ordinalBytes, 16) + int(ordBase, 16)):
                        break

                pe_file.seek(int(exportNamePointerTableOffset, 16))
                for i in range(counter):
                    functionRVA = reverseBytes(readBytes(pe_file, 4))
                    
                pe_file.seek(int(calcPhysOffset(sections, functionRVA), 16))
                nextByteOrdinal = readBytes(pe_file, 1);
                apiName = ""
                while (nextByteOrdinal != '00'):
                    pe_file.seek(-1, 1)
                    apiName += readBytes(pe_file, 1)
                    nextByteOrdinal = readBytes(pe_file, 1)
                apiName = hexStringToASCII(apiName)
                print(" "*12 + "API: " + hexFormat(currentNameTableRVA) + " (phys: " + hexFormat(calcPhysOffset(sections, currentNameTableRVA)) + ") --> Ordinal: " + hexFormat(ordinal) + ", Name: \"" + apiName + "\"")
                
                pe_file.seek(rememberOrdinal)
            #=============================================================================
            else:
                hintNameOffset = calcPhysOffset(sections, hintNameRVA)
            
                rememberImportNameTableOffset = pe_file.tell()
                pe_file.seek(int(hintNameOffset, 16))
                hint = reverseBytes(readBytes(pe_file, 2))
                nextByte = readBytes(pe_file, 1);
                apiName = ""
                while (nextByte != '00'):
                    pe_file.seek(-1, 1)
                    apiName += readBytes(pe_file, 1)
                    nextByte = readBytes(pe_file, 1)
                apiName = hexStringToASCII(apiName)
                pe_file.seek(rememberImportNameTableOffset)
            
                print(" "*12 + "API: " + hexFormat(currentNameTableRVA) + " (phys: " + hexFormat(calcPhysOffset(sections, currentNameTableRVA)) + ") --> Hint: " + hexFormat(hint) + ", Name: \"" + apiName + "\"")

            offset += 4
            next4Bytes = readBytes(pe_file, 4)
            
        pe_file.seek(rememberImportDirOffset)
        #================================================

        print()
        next20Bytes = readBytes(pe_file, 20)  #reminder: next20Bytes - looks for 20 zeroes for the end of import directory table

    #EXPORT TABLE
    print("EXPORT Table")
    print("============")
    if (exportTableRVA == '00'*4):
        print("Doesn't exist!")
    else:
        pe_file.seek(int(calcPhysOffset(sections, exportTableRVA), 16))
        print("    Export Directory")
        print("    ================")
        layoutPrint("    Characteristics:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()
        layoutPrint("    Time Date Stamp:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()
        layoutPrint("    Major Version:", hexFormat(reverseBytes(readBytes(pe_file, 2)))); print()
        layoutPrint("    Minor Version:", hexFormat(reverseBytes(readBytes(pe_file, 2)))); print()
        nameRVA = reverseBytes(readBytes(pe_file, 4))
        nameOffset = calcPhysOffset(sections, nameRVA)
        rememberExportDirOffset = pe_file.tell()

        #DLL NAME===============================
        pe_file.seek(int(nameOffset, 16))
        nextByte = readBytes(pe_file, 1)
        dllName = ""
        while (nextByte != '00'):
            pe_file.seek(-1, 1)
            dllName += readBytes(pe_file, 1)
            nextByte = readBytes(pe_file, 1)
        pe_file.seek(rememberExportDirOffset)
        #=======================================
        
        layoutPrint("    Name RVA:", hexFormat(nameRVA) + " (phys: " + hexFormat(nameOffset) + ") --> \"" + hexStringToASCII(dllName) + "\""); print()
        layoutPrint("    Ordinal Base:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()
        numberOfFunctions = reverseBytes(readBytes(pe_file, 4))
        layoutPrint("    Number of Functions:", hexFormat(numberOfFunctions)); print()
        layoutPrint("    Number of Names:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()
        exportAddressTableRVA = reverseBytes(readBytes(pe_file, 4))
        layoutPrint("    Address Table RVA:", hexFormat(exportAddressTableRVA)); print()
        exportNamePointerTableRVA = reverseBytes(readBytes(pe_file, 4))
        layoutPrint("    Name Pointer Table RVA:", hexFormat(exportNamePointerTableRVA)); print()
        layoutPrint("    Ordinal Table RVA:", hexFormat(reverseBytes(readBytes(pe_file, 4)))); print()

        #EXPORT ORDINAL TABLE LIST
        pe_file.seek(int(ordTableOffset, 16))
        ord_table = [0 for i in range(int(numberOfFunctions, 16))]
        for i in range(int(numberOfFunctions, 16)):
            ord_table[i] = reverseBytes(readBytes(pe_file, 2))

        #EXPORT ADDRESS TABLE
        print()
        print("        Export Address Table")
        print("        ====================")
        exportAddressTableOffset = calcPhysOffset(sections, exportAddressTableRVA)
        pe_file.seek(int(exportAddressTableOffset, 16))
        offset = 0
        for i in range(int(numberOfFunctions, 16)):
            currentRVA = format(int(exportAddressTableRVA, 16) + offset, 'x')
            functionRVA = reverseBytes(readBytes(pe_file, 4))

            ordinal = format(offset//4, 'x')
            print("            API: " + hexFormat(currentRVA) + " (phys: " + hexFormat(calcPhysOffset(sections, currentRVA)) + ") --> Ordinal: " + hexFormat(fourDigitString(str(ordinal))) + ", Name: \"", end = '')
            
            functionNameOrd = ord_table.index(fourDigitString(str(ordinal)))
            rememberAddressTableOffset = pe_file.tell()

            #API NAME===============================================
            pe_file.seek(int(calcPhysOffset(sections, exportNamePointerTableRVA), 16))
            pe_file.seek(functionNameOrd*4, 1)
            functionNameRVA = reverseBytes(readBytes(pe_file, 4))
            pe_file.seek(int(calcPhysOffset(sections, functionNameRVA), 16))
            
            nextByte = readBytes(pe_file, 1);
            apiName = ""
            while (nextByte != '00'):
                pe_file.seek(-1, 1)
                apiName += readBytes(pe_file, 1)
                nextByte = readBytes(pe_file, 1)
            apiName = hexStringToASCII(apiName)
            
            print(apiName + "\"")
            #=======================================================
            pe_file.seek(rememberAddressTableOffset)
            offset += 4

        #EXPORT FUNCTION NAME TABLE
        print()
        print("        Export Function Name Table")
        print("        ==========================")
        exportNamePointerTableOffset = calcPhysOffset(sections, exportNamePointerTableRVA)
        pe_file.seek(int(exportNamePointerTableOffset, 16))
        offset = 0
        for i in range(int(numberOfFunctions, 16)):
            currentRVA = format(int(exportNamePointerTableRVA, 16) + offset, 'x')
            functionRVA = reverseBytes(readBytes(pe_file, 4))

            ordinal = format(offset//4, 'x')
            print("            API: " + hexFormat(currentRVA) + " (phys: " + hexFormat(calcPhysOffset(sections, currentRVA)) + ") --> Ordinal: " + hexFormat(fourDigitString(str(ordinal))) + ", Name: \"", end = '')
            
            functionNameOrd = ord_table.index(fourDigitString(str(ordinal)))
            rememberAddressTableOffset = pe_file.tell()

            #API NAME===============================================
            pe_file.seek(int(calcPhysOffset(sections, exportNamePointerTableRVA), 16))
            pe_file.seek(functionNameOrd*4, 1)
            functionNameRVA = reverseBytes(readBytes(pe_file, 4))
            pe_file.seek(int(calcPhysOffset(sections, functionNameRVA), 16))

            nextByte = readBytes(pe_file, 1);
            apiName = ""
            while (nextByte != '00'):
                pe_file.seek(-1, 1)
                apiName += readBytes(pe_file, 1)
                nextByte = readBytes(pe_file, 1)
            apiName = hexStringToASCII(apiName)
            
            print(apiName + "\"")
            #=======================================================
            pe_file.seek(rememberAddressTableOffset)
            offset += 4

        #EXPORT ORDINAL TABLE
        print()
        print("        Export Ordinal Table")
        print("        ====================")
        pe_file.seek(int(ordTableOffset, 16))
        #ordBase
        for i in ord_table:
            print("            Value: " + hexFormat(i) + " (Decoded Ordinal: " + hexFormat(fourDigitString(format(int(i, 16) + int(ordBase, 16), 'x'))) + "), Name: \"", end = '')

            rememberOrdTable = pe_file.tell()
            #API NAME===============================================
            pe_file.seek(int(calcPhysOffset(sections, exportNamePointerTableRVA), 16))
            pe_file.seek(ord_table.index(i)*4, 1)
            functionNameRVA = reverseBytes(readBytes(pe_file, 4))
            pe_file.seek(int(calcPhysOffset(sections, functionNameRVA), 16))

            nextByte = readBytes(pe_file, 1);
            apiName = ""
            while (nextByte != '00'):
                pe_file.seek(-1, 1)
                apiName += readBytes(pe_file, 1)
                nextByte = readBytes(pe_file, 1)
            apiName = hexStringToASCII(apiName)
            
            print(apiName + "\"")
            #=======================================================
            pe_file.seek(rememberOrdTable)

    pe_file.close()

main()
os.system("pause")
