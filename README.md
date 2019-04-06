# BroadMulticast

Python script for analyzing traffic captured from an IoT environment. The tool also probes the network in order to discover new nodes. 

Notice that the package will run on python3 and does not support python2 


This package allows parsing from a capture file, using the dissectors provided by tshark.

This tool is a forked version of this github repository:

https://github.com/emaione2/BroadMulticast

## Required Packages

  -- Pyshark https://github.com/KimiNewt/pyshark
  -- netaddr https://github.com/drkjam/netaddr/
  -- nested_dict https://github.com/bunbun/nested-dict

## Usage

Simply run the following to run the script:
```bash
python3 run_test.py <Folder_path> <filename_1> <filename_2> ...
```
<Folder_path> is the path of the folder which contains the pacp files

<filename_x> is the name of the file that resided in <Folder_path> 

you may specify as many files as you wish. 



## License
This project is licensed under MIT. Contributions to this project are accepted under the same license. 

