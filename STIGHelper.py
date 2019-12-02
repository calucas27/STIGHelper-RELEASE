#This tool was made as a final project for INFA713 - Managing Security Risks.
#Please feel free to replicate and/or add to this tool however you like.
#All of the operating systems, tools, and guides belong to their respective publishers.
#Special thanks to DISA (Defense Information Systems Agency) for making the STIGs open and available to the public!

import os
import time
import argparse
import sys
import subprocess

def checkPlatform():
    platform = os.name
    return platform

def scanFiles(platform):
    if platform == 'nt':
        scriptFiles = os.listdir('./windows')
    elif platform == 'posix':
        scriptFiles = os.listdir('linux/')
    print("[*] Successfully loaded " + str(len(scriptFiles)) + " script file(s)")
    print(" ")
    return scriptFiles

def executeScripts(scriptFiles, mode):
    for file in scriptFiles:
        if mode == "enforce":
            scriptArgs = " -enforce"
        elif mode == "audit":
            scriptArgs = " -audit"
        if checkPlatform() == 'nt':
            command = "powershell.exe " " -ExecutionPolicy unrestricted" + " ./windows/" + file + scriptArgs
            print(command)
            os.system(command)
        elif checkPlatform() == 'posix':
            command = "/bin/bash " + "linux/" + file + scriptArgs
            os.system(command)

def createScoreFile():
    if checkPlatform() == "nt":
        command = "powershell.exe " " -ExecutionPolicy unrestricted" + "echo ' ' > score.tmp"
        os.system(command)
    elif checkPlatform() == "posix":
        command = "/bin/bash " + "echo ' ' > score.tmp"
        os.system(command)

def printResults():
    file = open('score.tmp','r').read()
    passCount = file.count("Pass")
    failCount = file.count("Fail")
    totalCount = passCount + failCount
    print ("=====!!!!!==========!!!!!=====")
    print ("       Scoring Results       ")
    print ("       Passed Checks: " + str(passCount))
    print ("       Failed Checks: " + str(failCount))
    print ("       Total Checks:  " + str(totalCount))
    print ("=====!!!!!==========!!!!!=====")

    print ("")
    
    print("[*] Detailed List of Findings: ")
    print(file)
    print("More detailed information about each of these findings is available in its script file, as well as the Windows 10 STIG")
    print("You can also view this list by opening the score.tmp file in this directory.")

def main(args):
    if args.audit:
        print ("[*] Script running in Audit Mode")
        mode = "audit"
    if args.enforce:
        print("[*] Script running in Enforce Mode")
        mode = "enforce"
    return mode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Arguments to be passed to the underlying scripts.") 
    parser.add_argument('-a','--audit',action='store_true',help='Run the tool in Audit Mode, will scan but not make changes.')
    parser.add_argument('-e','--enforce',action='store_true',help='Run the tool in Enforce Mode, which will scan *and* make changes. NOT recommended for use on prod, use this for fresh installs. ')
    args = parser.parse_args()
    print ("=====!!!!!==========!!!!!=====")
    print ("          STIGHelper          ")
    print ("         Version 1.0          ")
    print ("    Created by @calucas27     ")
    print ("    Created for INFA 713      ")
    print ("=====!!!!!==========!!!!!=====")
    print (" ")
    mode = main(args)
    platform = checkPlatform()
    if platform == "nt":
        print("[*] Detected Windows Platform")
    elif platform == "posix":
        print("[*] Detected Linux Platform")
    files = scanFiles(platform)
    createScoreFile()
    executeScripts(files, mode)
    printResults()
