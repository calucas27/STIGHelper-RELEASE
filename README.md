# STIGHelper

## Overview

STIGHelper is a class project for INFA713 designed to automate the application of some of the DISA STIG controls to Windows 10 and (eventually) Linux systems!  Currently, there are 18 scripts implemented for use on Windows systems.  All scripts are built following the latest (at the time of this release) DISA STIG guidelines.

## Prerequisites
There's only a couple pre-requisites to make this tool work on your host system.

```
Python Version 3.6.8 or higher (I used version 3.8.0 for all testing.)
Python argparse module
Windows 10 or Linux host system of your choice.
```

## Installation


Install Python3, and ensure it's working on your system.  You can verify the version with.

```
python --version
```
```
(or python3 --version if you're on *nix)
```
Next, you'll need the argparse module, which can be installed through pip - Python's package manager.

```
pip install argparse
```
Clone this repository to a directory on your system.
```
git clone <this repo>
```

## Deployment
When running this tool, ensure you are running the main file `STIGHelper.py` as root on Linux, or with an admin PowerShell prompt on Windows.  Place the repo anywhere you'd like on the system - it doesn't particularly matter.

## Usage
The tool takes two main parameters that influence its operation. `-enforce`, and `-audit`.  

### Enforce Mode
Enforce mode actively makes changes on the system, and will overwrite existing settings.  Currently, this setting is not recommended for use on production systems - use this on fresh systems.

### Audit Mode
Audit mode only scans the system and compares existing values to known good values from the STIG.  Currently, this mode is recommmended as it makes no actual changes to the system, making it ideal to use on currently deployed systems.

## Authors

* **Chase Lucas** - *Primary Author* - [Dakota State University](https://dsucyber.com)

## Acknowledgments
* DISA for making the lists of Windows/Linux STIGs available to the public.
* NIST for creating the NIST SP 800-53 that inspires many of these controls.
* Dr. Kevin Streff, the professor of this course.