# Wireshark PCAP/PCAPNG  Filter and Merger Tool
This is a Python GUI tool for merging filtered PCAP or PCAPNG files into a single output file. The tool uses Wireshark to apply the filter to the selected files.

### Prerequisites
- Wireshark must be installed in the default directory C:\Program Files (x86)\Wireshark or at a custom location which should be specified in the tool.
- Python 3.x should be installed on the system.
- The following Python standard libraries are required:
  - `time`
  - `os`
  - `glob`
  - `subprocess`
  - `shutil`
  - `zipfile`
  - `tkinter
  - `threading`
  
### How to Use
1. Clone the repository to your local system.
2. Install the required packages using pip.
3. Open the terminal and navigate to the repository directory.
4. Run the `WS_Filter_Merge.py` file using Python.
5. The GUI will open with the option to select either a zipped file or unzipped folder using the `...` button.
6. If the selected file is a zip file, the tool will extract it to a temporary folder and use the extracted folder for further processing. later after processing, folder will be removed.
7. Check the appropriate option in the GUI to indicate whether the selected file/folder is a PCAPNG or PCAP file.
8. Enter the filter criteria in the input field provided.
9. Click the `Submit` button to begin the filter and merging process.
10. The output file will be saved in the same directory where the program is executed with the name merged.pcapng.

### Contributions
Contributions to this repo are welcome. If you find a bug or have a suggestion for improvement, please open an issue on the repository. If you would like to make changes to the code, feel free to submit a pull request.

### Acknowledgments
This program was created as a part of a programming challenge. Special thanks to the challenge organizers for the inspiration.
