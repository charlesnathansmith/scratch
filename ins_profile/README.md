Runs first 1000000000 instructions and collects statistics on the last 500000000 to attempt to identify where it's getting stuck

## Building
Copy ins_profile to pin/tools/source and build from VS project.
This was built with a slightly older version of pin and the project file probably needs updated for newer versions.
Should build with PIN 3.32 and earlier.  It can be updated for newer versions by making a copy of MyPinTool and just swapping out source file in the project.

## Running
```
C:\pin\pin.exe -t C:\pin\source\tools\ins_profile\Release\api_log.dll -o log.txt -- StingWin.exe
```

Results for StingWin.exe in log.txt
Copy instruction data into spreadsheet to sort by how many times each instruction gets executed and the last time it executed during analysis.
