#!/usr/bin/python
from __future__ import print_function
import os
import sys
import time
import uuid
import hashlib
import requests
import logging
import argparse
import shlex
import subprocess
from enum import Enum
from Crypto import Random
from datetime import datetime


# Suppress urlib3 output as any warnings/errors should be caught by the script.
requests.packages.urllib3.disable_warnings()


"""
 CONSTANTS
"""
LOG_DIRECTORY = "/scripts/ms3_packager/logs/"
OUTPUT_PATH = "/scripts/ms3_packager/packaged/"
TS2Encrypt_Binary = "\"/scripts/ms3_packager/bin/Ts2Encrypt\""
MS3_INJECTOR_URL = "INTENTIONALLY EMPTY"
MAX_HTTP_RETRIES = 3
serviceID = ""
#added both the http and https url here to mitigate proxy tunnelling issues.
proxies = {'http' : 'http://IP:3128','https' : 'https://IP:3128'}


"""
 SETUP LOGGING.
"""
# Generate a UUID for the Job id reference.
job_ID = str(uuid.uuid1())

log_file_name = datetime.now().strftime('marlin_packager_%H_%M_%d_%m_%Y.log')

LOG_FILE = os.path.join(LOG_DIRECTORY, log_file_name)

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)-8s JOB: {0} - %(message)s".format(job_ID),
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename=LOG_FILE,
                    filemode='w')



"""
 Error codes taken from: http://www-dev.expressplay.com/sites/all/docs/sdk/embedded/Ts2Results_8h_source.html
 ALSO SEE: http://d31lwto7rjo21l.cloudfront.net/sdk-errors/ExpressPlay-SDK-Errors.txt
"""

class Tsencrypt_Error_Codes(Enum):
    TS2_ERROR_INVALID_SYNC_BYTE_INVALID_MEDIA_FOR_PACKAGING = 63
    TS2_ERROR_NEED_MORE_DATA_INVALID_MEDIA_FOR_PACKAGING = 62
    TS2_ERROR_INVALID_SECTION_HEADER_INVALID_MEDIA_FOR_PACKAGING = 61
    TS2_ERROR_INVALID_SIZE = 60
    TS2_ERROR_INVALID_TABLE_ID = 59
    TS2_ERROR_NO_PROGRAM_AVAILABLE = 58
    TS2_ERROR_PES_INCOMPLETE_PACKET = 57
    TS2_ERROR_PES_UNBOUNDED_COMPLETION = 56
    TS2_ERROR_INVALID_VERSION = 55
    TS2_ERROR_NOT_BBTS_PROTECTED_CHECK_PACKAGER_ARGS = 54
    TS2_ERROR_INVALID_DATA_INVALID_MEDIA_FOR_PACKAGING = 53
    TS2_ERROR_DECRYPTION_FAILED = 52
    TS2_ERROR_CRC_MISMATCH = 51
    TS2_ERROR_DECRYPTER_NOT_READY = 50
    TS2_ERROR_MAC_MISMATCH = 49
    TS2_ERROR_PRNG_FAILED = 48
    TS2_ERROR_INVALID_CONTENT_ID_CHECK_CONTENT_ID = 47


"""
 PROGRAM METHODS
"""

def generateKey():
    # return str(uuid.uuid1()).replace('-', '')
    # return a random 16 byte array.
    return Random.get_random_bytes(16)


def ConvertBytesToHex(byteStr):
    """
    Convert a byte string to it's hex string representation.
    """       
    return ''.join( [ "%02X" % ord(x) for x in byteStr ] ).strip().lower()


def invoke_Packager(ts2Encrypt_Params):
    #here due to CalledProcessError stating output is not a recognised attribute
    #although the docs state it is?!
    error_msg = ''
    try:
        # execute the ts2encrypt process
        process = subprocess.Popen(shlex.split(ts2Encrypt_Params), 
                                   shell=False, 
                                   stderr=subprocess.PIPE, 
                                   stdout=subprocess.PIPE)


        output, stderr = process.communicate()
        ret_code = process.wait()

        if ret_code == 0:
            logging.info("TS2Encrypt completed successfully")
            return 0
        else:
            error_msg = Tsencrypt_Error_Codes(ret_code).name
            raise subprocess.CalledProcessError(returncode=ret_code, 
                                                cmd=ts2Encrypt_Params)


    except subprocess.CalledProcessError as ex:
        #additional newlines are in place to make the error easier to read due to the long process arguments in the ex.cmd output
        logging.error("ERROR while Executing:\r\n\r\nCMD: {ex.cmd}.\r\n\r\nError condition: {ex.returncode}, {error_msg}\r\n\r\n".format(ex=ex, error_msg=error_msg))
        return 1


def keyInject(contentID, serviceID, encryptionKey):
    success = False

    for retry in range(MAX_HTTP_RETRIES):
        try:
            if retry > 0:
                time.sleep(10)

            # set the key injection parameters
            query_params = {"contentID": contentID, "contentProvider": serviceID, "assetKey": encryptionKey}

            logging.info("Invoking HTTP POST ( {0} of {1} attempts ) for URL {2}".format(str(retry + 1),
                                                                                         str(MAX_HTTP_RETRIES),
                                                                                         MS3_INJECTOR_URL))


            # using requests execute the key injection post method
            ki_request = requests.post(MS3_INJECTOR_URL, 
                                       params=query_params, 
                                       proxies=proxies, 
                                       timeout=10) 


            ki_request.raise_for_status()
            resp_code = ki_request.status_code
            logging.info("Request response Code: {0}".format( str(resp_code)))

            if resp_code == 200:
                logging.info("Key {0} Successfully injected".format(encryptionKey))
                success = True
                break
            if resp_code == 201:
                logging.info("Key {0} Successfully injected".format(encryptionKey))
                success = True
                break
            if resp_code == 409:
                logging.warning("Conflict - duplicate contentID in database is the likely cause")
                success = False
                break
            else:
                logging.error("Unknown error or un-trapped HTTP code - {0}".format(str(resp_code)))
                success = False
                break

        except Exception as ki_ex:
            print("KEY INJECTION FAILED: {0}".format(str(ki_ex)), file=sys.stderr)
            logging.error("KEY INJECTION FAILED: {0}".format(str(ki_ex)))
    return success



####################################################################
#  Main Program                                                    #
####################################################################


def main():
    try:
        parser = argparse.ArgumentParser(description="MARLIN Offline Packager Script.",
        epilog="USAGE:  marlin_packager.py  --contentID \"123456789\"" + \
        " --assetBasePath \"/path/to/input/file/directory/\"" + \
        " --assets \"asset1.mp4\" \"asset2.mp4\" \"asset3.mp4\" \"asset_n\" \"asset_n\"")

        requiredArgs = parser.add_argument_group('Required MARLIN Packager Arguments')
        requiredArgs.add_argument('--contentID', help="Transcode FrontEnd JobID", type=str, required=True)
        requiredArgs.add_argument('--assetBasePath', help="assetBasePath, path to input files directory", type=str, required=True)
        requiredArgs.add_argument('--assets', help="List of assets comma separated", nargs='+', type=str, required=True)
        args = parser.parse_args()

        # Start initial logging process and output args to log.
        logging.info(" *** NEW PACKAGING REQUEST ACCEPTED *** ")
        logging.info("Arguments passed to MarlinPackager.py: {0}, {1}, {2}".format(args.contentID,                
                                                                               args.assetBasePath,
                                                                               str(args.assets)))

        logging.info("Content ID is: {0}".format(args.contentID))
        logging.info("Asset base path is: {0}".format(args.assetBasePath))
        logging.info("{0} assets will be processed".format(str(len(args.assets))))
        logging.info("*** MS3_Process *** for contentID: {0} STARTING ***".format(args.contentID))

        # Create required encryption key data
        marlin_DRM_ID = "cid:marlin#S{0}-{1}@00000000".format(serviceID,
                                                              args.contentID)


        # generate random key in bytes(16)
        key_bytes = generateKey()
        # convert the bytes to a lower hex string.
        encryptionKey = ConvertBytesToHex(key_bytes)

        proc_err_flag = 0

        # write keydata to log for support
        logging.info("Marlin DRM ID is: {0}".format(marlin_DRM_ID))
        logging.info("Key is: {0}".format(str(encryptionKey)))

        for asset in args.assets:
            source_file = "".join(args.assetBasePath + asset)
            target_file = "".join(OUTPUT_PATH + asset)

            if os.path.isfile(source_file):
                logging.info("File: {0} exists".format(asset))
                logging.info("Encrypting Source: {0} to Target: {1}".format(source_file, 
                                                                            target_file))


                # set the ts2Encrypt arguments
                ts2Encrypt_Params = "{0} --key {1}::{2} --protection bbts-2.0 {3} {4}".format(TS2Encrypt_Binary, 
                                                                                              marlin_DRM_ID, 
                                                                                              encryptionKey, 
                                                                                              source_file, 
                                                                                              target_file)


                logging.info("TS2Encrypt exec: {0}".format(ts2Encrypt_Params))

                # invoke the ts2Encrypt packager and catch the return code 0 or 1 for success/error flag
                proc_err_flag = invoke_Packager(ts2Encrypt_Params)

            else:
                logging.error("FILE: {0} Not Found!".format(asset))
                proc_err_flag = 1

        # attempt key injection!
        if proc_err_flag == 0:
            logging.info("Asset Packaging Successful. Attempting License inject")
            # start the key injection process
            key_Injection_Status = keyInject(args.contentID, 
                                             serviceID, 
                                             encryptionKey)


            if key_Injection_Status == True:
                logging.info("DRM Content key delivered successfully.")
                logging.info("**** MS3 Process for ContentID: {0} COMPLETED SUCCESSFULLY! **** ".format(args.contentID))
                exit(0)
            else:
                logging.error("**** PROCESSING OF THE PACKAGE HAS BEEN ABORTED **** \r\n")
                exit(1)
        else:
            print("**** TS2ENCRYPT ENCOUNTERED AN ERROR. PROCESSING OF THE PACKAGE HAS BEEN ABORTED **** ", file=sys.stderr)
            logging.error("**** TS2ENCRYPT ENCOUNTERED AN ERROR. PROCESSING OF THE PACKAGE HAS BEEN ABORTED **** \r\n")
            exit(1)


    except Exception as jobEx:
        logging.error("**** Processing has encountered an error: DEBUG = {0} ****".format(str(jobEx)))
        exit(1)


if __name__ == '__main__':
    main()
    
