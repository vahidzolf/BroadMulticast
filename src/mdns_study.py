from src.classFrames import *
import pyshark
cap=pyshark.FileCapture(
    input_file="/home/edoardo/MEGAsync/Tesi/test_canon.pcap",
    display_filter='mdns'
)
devices={}
