#!/bin/bash
input="macs"
while IFS= read -r var
do
  echo $var
#  echo $var | sed -e 's/[\r\n]//g' | xargs -i  grep {} -A 5 CS.output 
  echo $var | sed -e 's/[\r\n]//g' | xargs -i sed -n '/^\*\*\*\*\*\*/,/^\*\*\*\*\*\*/p'  CS.output 
  echo "******"
done < "$input"
