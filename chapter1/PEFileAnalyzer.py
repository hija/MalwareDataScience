import pefile
import argparse
import sys
import traceback
import os


def analyze(filename, show_imports = True, show_exports = True, show_sections = True):
    print('::: PE-Analysis :::')
    print('File: ', os.path.basename(filename))
    print()

    try:
        pe = pefile.PE(filename)

        # First check if some checksums are right
        # i.e. compare http://win32assembly.programminghorizon.com/pe-tut2.html
        try:
            assert pe.DOS_HEADER.e_magic == 0x5A4D #MZ
            assert pe.NT_HEADERS.Signature == 0x4550 #PE
        except:
            print('The PE File seems to be invalid!', file=sys.stderr)
            return

        ### SECTIONS
        if show_sections:
            print('[*] Sections')
            for section in pe.sections:
                print(section.Name.decode('utf-8'))
                print('\tVirtual Address: {}'.format(hex(section.VirtualAddress)))
                print('\tVirtual Size: {}'.format(hex(section.Misc_VirtualSize)))
                print('\tRaw Size: {}'.format(hex(section.SizeOfRawData)))
            print()

        #### IMPORTS
        if show_imports:
            print('[*] Imports')
            if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                print('\t There are no imports for this PE-File')
            else:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    print('\t{}'.format(entry.dll.decode('utf-8')))
                    if entry.imports:
                        for function in entry.imports:
                            if function.name:
                                print('\t\t{}'.format(function.name.decode('utf-8')))
                            else:
                                print('\t\t Unknown functionname')
            print()

        ### EXPORTS
        if show_exports:
            print('[*] Exports')
            if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                print('\t There are no exports for this PE-File')
            else:
                for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    print('\t{}'.format(export.name.decode('utf-8')))

    except pefile.PEFormatError:
        print('The PE File seems to be invalid!', file=sys.stderr)
    except:
        traceback.print_exc(file=sys.stdout) # Just print out the error

parser = argparse.ArgumentParser(description='Anaylze a PEFile')
parser.add_argument('file', help='file to be analyzed')
parser.add_argument('--exports', action="store_true", help="show the exports")
parser.add_argument('--imports', action="store_true", help="show the imports")
parser.add_argument('--sections', action="store_true", help="show the exports")
args = parser.parse_args()
analyze(args.file, show_imports = args.imports, show_exports = args.exports, show_sections = args.sections)
