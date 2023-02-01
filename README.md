# P-Code interpreter

This repository contains the code for the high P-Code interpreter described in the paper "[A Formal Semantics for P-Code](https://link.springer.com/chapter/10.1007/978-3-031-25803-9_7)" by Naus, Verbeek and Ravindran.

The code in this repo is intended for use with our custom P-Code dumping script, which can be found here: https://github.com/niconaus/PCode-Dump

Make sure that the Ghidra option "Decompiler Parameter ID" is enabled, otherwise you might run into intra-procedural type issues.

## Usage

Load the PCode module in GHCI, or compile with GCH.
Enter the file name of the P-Code that you want to interpret.
Enter the function address as Integral number.
Enter the function arguments, using " " to separate them.

The return value of the called function will be printed as an integer value.

Example:

```
PCode> main
P-Code interpreter 
Please input P-Code file
p.txt
Enter function address
4294983536
Enter arguments
4 5
Return value of called function is:
9
```

#### Acknowledgements:

This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific) under contract N6600121C4028 and Agreement No. HR.00112090028, and the US Office of Naval Research (ONR) under grant N00014-17-1-2297.

Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of DARPA or NIWC Pacific, or ONR. 

Special thanks to [harrisonwl](https://github.com/harrisonwl "harrisonwl") for his feedback on this codebase
