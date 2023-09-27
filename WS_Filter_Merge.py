from os import makedirs
from os.path import exists, join, dirname, basename, isdir, isfile, splitext
from glob import glob
from subprocess import Popen
from shutil import rmtree
from zipfile import ZipFile
from tkinter import Tk, filedialog, END, StringVar, Label, Radiobutton, Entry, Button, Toplevel, LabelFrame, Frame, \
    Scrollbar, Menu, messagebox
from tkinter.ttk import Progressbar, Style, Combobox, Notebook, Treeview
from threading import Thread
from datetime import datetime
from csv import reader
from time import time
from warnings import filterwarnings
from sqlite3 import connect
from sys import argv
from re import match
from asyncio import create_subprocess_exec, create_task, as_completed, run
from asyncio.subprocess import PIPE


class WSApp:
    if not exists('log'):
        makedirs('log')
    logFilCount = 1
    fileHandler = None
    maxLinesPerLogFile = 49999
    currentLineCountLog = 0
    dbFileName = 'conf/filters.db'
    dbTableName = 'filters'
    pathConf = 'conf/conf.csv'
    iconFile = join(dirname(__file__), 'wireshark.ico')
    inputFiles = ''
    outputFilePath = ''
    userEnteredPath = ''
    availableKeysToSelectList = []
    userSelectedFilterSyntax = ''
    preconfiguredFilterDict = {
        'Custom Filter': 'custom_filter', 'HTTP-Packets': 'http', 'SSL-TLS-Packets(Including-HTTPS)': 'tls',
        'SSL-TLS-Handshake-For-HTTPS': 'http.request.method == "CONNECT"', 'TCP-Packet': 'tcp', 'UDP-Packet': 'udp',
        'ICMP(Ping-Requests-And-Replies)': 'icmp', 'DNS-Packets': 'dns', 'FTP-Packets': 'ftp',
        'SMTP(Email-Transmission)': 'smtp', 'POP3(Email-From-Server)': 'pop3',
        'IMAP(Email-Retrieval-And-Management)': 'imap', 'SSH(Secure-Remote-Access)': 'ssh',
        'TELNET(unencrypted-remote-access)': 'telnet', 'ARP(IP-Addresses-MAC-Addresses)': 'arp',
        'DHCP(Automatic-IP-Assignment)': 'dhcp', 'SNMP(Network-Monitoring)': 'snmp', 'NTP(Time-Sync)': 'ntp',
        'SMB(Printer-Sharing)': 'smb'
    }

    def __init__(self):
        self.pathTshark = None
        self.pathMergeCap = None
        filterwarnings("ignore", category=UserWarning)
        self.window = Tk()
        self.window.config(bg='light grey')
        self.window.title('PacketPulse v1.3')
        self.window.geometry('520x420')
        self.window.iconbitmap(self.iconFile)
        self.window.resizable(False, False)
        self.radioVar = StringVar()
        self.radioVar.set(None)
        self.menuBar = Menu(self.window, cursor='hand2')
        self.toolMenu = Menu(self.menuBar, tearoff=0, cursor='hand2')
        self.toolMenu.add_command(label="Filters", command=self.launchFilterModWindow)
        self.extraMenu = Menu(self.menuBar, tearoff=0, cursor='hand2')
        self.extraMenu.add_command(label="Help", command=self.showShortcuts)
        self.extraMenu.add_separator()
        self.extraMenu.add_command(label="About", command=self.aboutWindow)
        self.aboutMessage = messagebox
        self.keysMessage = messagebox
        self.menuBar.add_cascade(label="Tools", menu=self.toolMenu)
        self.menuBar.add_cascade(label="?", menu=self.extraMenu)
        self.window.config(menu=self.menuBar)
        self.radioFolder = Radiobutton(self.window, text='Folder (files, zipped files)', font=('Arial', 11, 'bold'),
                                       bg='light grey', variable=self.radioVar, command=self.enableFileDialogBtn,
                                       value='folder', padx=10, pady=5, activebackground='light blue',
                                       activeforeground='black', state='disabled')
        self.radioFolder.place(x=145, y=10)
        self.radioZipped = Radiobutton(self.window, text='Zipped (files, zipped files)', font=('Arial', 11, 'bold'),
                                       bg='light grey', variable=self.radioVar,
                                       command=self.enableFileDialogBtn, value='zip', padx=10, pady=5,
                                       activebackground='light blue', activeforeground='black', state='disabled')
        self.radioZipped.place(x=145, y=40)
        self.pathLabel = Label(self.window, text='Folder/Zipped', font=('Arial', 10, 'bold italic'), bg='light grey')
        self.pathLabel.place(x=6, y=85)
        self.pathEntryFrame = Frame(self.window, borderwidth=2, relief="groove")
        self.pathEntryFrame.place(x=110, y=85)
        self.pathEntry = Entry(self.pathEntryFrame, bd=2, width=50, bg='white', state='readonly')
        self.pathEntry.pack(side="right", padx=5)
        self.pathEntryLabel = Label(self.pathEntryFrame)
        self.pathEntryLabel.pack(side="right", padx=(0, 5))
        self.fileDialogBtn = Button(self.window, text='Browse', command=self.fileDialogFunc, bg='light grey',
                                    state='disabled', cursor='arrow')
        self.fileDialogBtn.place(x=460, y=83)
        self.outputLabel = Label(self.window, text='Output File', font=('Arial', 10, 'bold italic'), bg='light grey')
        self.outputLabel.place(x=6, y=120)
        self.outputEntryFrame = Frame(self.window, borderwidth=2, relief="groove")
        self.outputEntryFrame.place(x=110, y=120)
        self.outputEntry = Entry(self.outputEntryFrame, bd=2, width=50, bg='white', state='readonly')
        self.outputEntry.pack(side="right", padx=5)
        self.outputEntryLabel = Label(self.outputEntryFrame)
        self.outputEntryLabel.pack(side="right", padx=(0, 5))
        self.saveDialogBtn = Button(self.window, text='Output', command=self.handleFileName, bg='light grey',
                                    state='disabled', cursor='arrow')
        self.saveDialogBtn.place(x=460, y=118)

        self.filterLabelFrame = LabelFrame(self.window, text="Filter", padx=10, pady=10,
                                           font=('Arial', 10, 'bold italic'), bg='light grey')
        self.filterLabelFrame.place(x=8, y=150)
        self.filterCombo = Combobox(self.filterLabelFrame, font=('Arial', 9), width=65, validate="key",
                                    state='disabled', cursor='hand2')
        self.filterCombo.grid(row=0, column=0, padx=5, pady=5)
        self.filterCombo.set("Select filter")
        self.customFilterEntryFrame = Frame(self.filterLabelFrame, borderwidth=2, relief="groove")
        self.customFilterEntryFrame.grid(row=1, column=0, padx=5, pady=5)
        self.customFilterEntry = Entry(self.customFilterEntryFrame, bd=2, width=73, bg='white', state='readonly')
        self.customFilterEntry.pack(side="right", padx=5)
        self.customFilterEntryLabel = Label(self.customFilterEntryFrame)
        self.customFilterEntryLabel.pack(side="right", padx=(0, 5))
        self.submitBtn = Button(self.window, text='Submit', command=self.filterMerge, bg='light grey', state='disabled')
        self.submitBtn.place(x=210, y=270)
        self.resetBtn = Button(self.window, text='Reset', command=self.resetBtnFunc, bg='light grey', state='disabled')
        self.resetBtn.place(x=270, y=270)
        self.progress = Progressbar(self.window, length=510, mode="determinate", style="Custom.Horizontal.TProgressbar")
        self.progress.place(x=6, y=315)
        self.progressStyle = Style()
        self.progressStyle.theme_use('clam')
        self.progressStyle.configure("Custom.Horizontal.TProgressbar", background="yellow", text='0 %')
        self.progressStyle.layout('Custom.Horizontal.TProgressbar', [('Horizontal.Progressbar.trough',
                                                                      {'children': [('Horizontal.Progressbar.pbar',
                                                                                     {'side': 'left', 'sticky': 'ns'})],
                                                                       'sticky': 'nswe'}),
                                                                     ('Horizontal.Progressbar.label', {'sticky': ''})])
        self.messageLabel = Label(self.window, wraplength='510', justify='left', font=('Arial', 8, 'bold'),
                                  bg='light grey')
        self.messageLabel.place(x=6, y=345)
        self.warnLabel = Label(self.window,
                               text='Note: Make sure Wireshark is installed and path configured in "conf/conf.csv"',
                               font=('Arial', 9, 'bold'), bg='light grey')
        self.warnLabel.place(x=6, y=380)

    def aboutWindow(self):
        message = 'Version 1.3 - Wireshark Filter and Merge\nDeveloped by Priyanshu\n\nFor any suggestions or ' \
                  'enhancements, please feel free to contact me through the following channels:\n\nEmail: chandel' \
                  'priyanshu8@outlook.com\nMobile: +91-XXXXXXXXXX\n\nYou can also reach me via my personal ' \
                  'website:\nhttps://priyanshuchandel.github.io/'
        self.aboutMessage.showinfo("About", message)

    def showShortcuts(self):
        message = "Filter Modification Key Shortcuts:\n"
        message += "    Ctrl + N: Add New Filter\n"
        message += "    Ctrl + S: Save New/Modification\n"
        message += "    Delete: Delete Selection\n\n\n"
        self.keysMessage.showinfo("Keyboard Shortcuts", message)

    def updateProgress(self, newVal, totalVal):
        resultVal = (newVal / totalVal) * 99
        self.progress['value'] = resultVal
        self.progressStyle.configure("Custom.Horizontal.TProgressbar", text='{:g} %'.format(resultVal))
        self.window.update()

    def enableFileDialogBtn(self):
        self.progress.config(value=0)
        self.pathEntry.config(state='normal')
        self.pathEntry.delete(0, 'end')
        self.customFilterEntry.config(state='normal')
        self.customFilterEntry.delete(0, 'end')
        self.submitBtn.config(state='disabled', bg='light grey', cursor='arrow')
        self.fileDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
        self.customFilterEntry.config(state='disabled')
        self.pathEntry.config(state='disabled')
        self.messageLabel.config(text='')

    def checkEntries(self, event):
        customFilterInput = self.customFilterEntry.get()
        if customFilterInput:
            self.userSelectedFilterSyntax = customFilterInput
            self.submitBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
            self.filterCombo.config(state='disabled')
            self.messageLabel.config(text='Click "Submit" to proceed')
        else:
            self.submitBtn.config(state='disabled', bg='light grey', cursor='arrow')
            self.filterCombo.config(state='normal')
        self.writeLog('info', f'User typed custom filter "{customFilterInput}"')
        self.writeLog('debug', f'UserSelectedFilter "{customFilterInput}"')

    def resetBtnFunc(self):
        self.radioVar.set(None)
        self.radioFolder.config(state='normal', cursor='hand2')
        self.radioZipped.config(state='normal', cursor='hand2')
        self.pathEntry.config(state='normal')
        self.pathEntry.delete(0, END)
        self.pathEntry.config(state='disabled')
        self.outputEntry.config(state='normal')
        self.outputEntry.delete(0, END)
        self.outputEntry.config(state='disabled')
        self.filterCombo.set("Select filter")
        self.filterCombo.config(state='disabled')
        self.customFilterEntry.config(state='normal')
        self.customFilterEntry.delete(0, END)
        self.customFilterEntry.config(state='disabled')
        self.fileDialogBtn.config(state='disabled', cursor='arrow')
        self.submitBtn.config(state='disabled', bg='light grey', cursor='arrow')
        self.resetBtn.config(state='disabled', bg='light grey', cursor='arrow')
        self.progress.config(value=0)
        self.progressStyle.configure("Custom.Horizontal.TProgressbar", text='0 %')
        self.messageLabel.config(text='')
        self.saveDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
        self.toolMenu.entryconfig("Filters", state="normal")
        try:
            rmtree('Filtered')
            rmtree('Extracted')
        except Exception as e:
            self.writeLog('error', 'Error while removing folders')
            self.writeLog('debug', f'[{e}]')
            pass

    def unZip(self, zippedPath):
        self.progressStyle.configure("Custom.Horizontal.TProgressbar", background="yellow")
        unZipSuccess = 0
        if isdir(zippedPath):
            try:
                filesZippedPcap = glob(zippedPath + '\\*.zip')
                totalZippedFiles = len(filesZippedPcap)
                for zipFile in filesZippedPcap:
                    multipleZip = ZipFile(zipFile)
                    multipleZip.extractall('Extracted')
                    unZipSuccess = unZipSuccess + 1
                    self.updateProgress(unZipSuccess, totalZippedFiles)
                self.progress.config(value=100)
                self.writeLog('info', f'UnZipping Success of multiple zipped files in a folder')
                self.progressStyle.configure("Custom.Horizontal.TProgressbar", background="green", text='100 %')
                return True
            except Exception as failed:
                self.writeLog('error', f'Error while unzipping multiple zipped files in a folder')
                self.writeLog('debug', f'[{failed}]')
                self.messageLabel.config(text='Error! check logs')
                return False
        elif isfile(zippedPath):
            try:
                with ZipFile(zippedPath, 'r') as singleZip:
                    singleZip.extractall('Extracted')
                    self.updateProgress(1, 1)
                    nestedZipFiles = [f for f in singleZip.namelist() if f.endswith('.zip')]
                    totalNestedZippedFiles = len(singleZip.namelist())
                    nestedSuccess = 0
                    for nestedZip in nestedZipFiles:
                        nestedZipPath = join('Extracted', nestedZip)
                        ZipFile(nestedZipPath).extractall('Extracted')
                        nestedSuccess = nestedSuccess + 1
                        self.updateProgress(nestedSuccess, totalNestedZippedFiles)
                    self.progress.config(value=100)
                    self.writeLog('info', f'UnZipping Success of single zipped file(nested/UnNested)')
                    self.progressStyle.configure("Custom.Horizontal.TProgressbar", background="green", text='100 %')
                return True
            except Exception as failed:
                self.writeLog('error', f'Error while unzipping of single zipped file(nested/UnNested)')
                self.writeLog('debug', f'[{failed}]')
                self.messageLabel.config(text='Error! check logs')
                return False
        else:
            self.writeLog('error', f'Invalid input [{zippedPath}]')
            self.messageLabel.config(text='Error! check logs')
            return False

    def fileDialogFunc(self):
        def fileDialogTread():
            self.toolMenu.entryconfig("Filters", state="disabled")
            self.messageLabel.config(text='')
            start = time()
            radioVar = self.radioVar.get()
            if radioVar == 'folder':
                self.writeLog('info', f'[Folder] radio button selected')
                folderSourcePath = filedialog.askdirectory()
                self.writeLog('info', f'[{folderSourcePath}] selected as source path')
                self.pathEntry.config(state='normal')
                self.pathEntry.insert(0, folderSourcePath)
                if len(self.pathEntry.get()) > 0:
                    self.radioFolder.config(state='disabled', cursor='arrow')
                    self.radioZipped.config(state='disabled', cursor='arrow')
                    filesPcap = glob(folderSourcePath + '\\*.pcap*')
                    filesZippedPcap = glob(folderSourcePath + '\\*.zip')
                    if filesPcap and not filesZippedPcap:
                        self.inputFiles = filesPcap
                        self.writeLog('info', 'Folder having pcap/pcapng files')
                        self.pathEntry.config(state='readonly')
                        self.fileDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
                        self.saveDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                    elif filesZippedPcap and not filesPcap:
                        self.writeLog('info', 'Folder having multiple zipped captures')
                        self.pathEntry.config(state='readonly')
                        self.fileDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
                        self.saveDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                        self.writeLog('info', 'Unpacking...')
                        self.messageLabel.config(text='Unpacking captures..')
                        unZipSuccess = self.unZip(folderSourcePath)
                        if unZipSuccess:
                            self.inputFiles = glob('Extracted\**\\*.pcap*', recursive=True)
                            self.writeLog('info', 'Unpacking done')
                            self.messageLabel.config(text='Unpacking done, select output filename')
                            self.saveDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                        if not unZipSuccess:
                            self.writeLog('error', 'Unzipping failed')
                            self.messageLabel.config(text='Error! check logs')
                    else:
                        self.writeLog('error', 'Unsupported files format or no ".pcap/.pcapng" found or no valid '
                                               '".zip" found or this folder is having mix of files')
                        self.messageLabel.config(text='Error! check logs')
                        self.fileDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
                        self.pathEntry.config(state='readonly')
                    self.resetBtn.config(state='normal', fg='white', bg='orange', cursor='hand2')
                else:
                    self.writeLog('warning', 'No folder source path selected')
                    self.messageLabel.config(text='Select source path')
                    self.fileDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                    self.pathEntry.config(state='readonly')

            elif radioVar == 'zip':
                self.writeLog('info', '[Zip] radio button selected')
                zippedSourcePath = filedialog.askopenfilename(filetypes=(("zip files", "*.zip"),))
                self.writeLog('info', f'[{zippedSourcePath}] selected as Zip folder source path')
                self.pathEntry.config(state='normal')
                self.pathEntry.insert(0, zippedSourcePath)
                if len(self.pathEntry.get()) > 0:
                    self.radioFolder.config(state='disabled', cursor='arrow')
                    self.radioZipped.config(state='disabled', cursor='arrow')
                    self.pathEntry.config(state='readonly')
                    self.fileDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
                    with ZipFile(zippedSourcePath, 'r') as zip_ref:
                        zipZipped = [file for file in zip_ref.namelist() if file.endswith('.zip')]
                        filesZipped = [file for file in zip_ref.namelist() if
                                       file.endswith('.pcap') or file.endswith('.pcapng')]

                    if filesZipped and not zipZipped:
                        self.writeLog('info', 'Selected zip folder contains no further zip file inside')
                        self.writeLog('info', 'Unpacking...')
                        self.messageLabel.config(text='Unpacking captures..')
                        unZipSuccess = self.unZip(zippedSourcePath)
                        if unZipSuccess:
                            self.inputFiles = glob('Extracted\**\\*.pcap*', recursive=True)
                            self.writeLog('info', 'Unpacking done...')
                            self.messageLabel.config(text='Unpacking done, select output filename')
                            self.saveDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                        if not unZipSuccess:
                            self.writeLog('error', 'Unzipping failed')
                            self.messageLabel.config(text='Error! check logs')

                    elif zipZipped and not filesZipped:
                        self.writeLog('info', 'Selected zip folder contains further zip inside')
                        self.writeLog('info', 'Unpacking...')
                        self.messageLabel.config(text='Unpacking captures..')
                        unZipSuccess = self.unZip(zippedSourcePath)
                        if unZipSuccess:
                            self.inputFiles = glob('Extracted\**\\*.pcap*', recursive=True)
                            self.writeLog('info', 'Unpacking done...')
                            self.messageLabel.config(text='Unpacking done, select output filename')
                            self.saveDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                        if not unZipSuccess:
                            self.writeLog('error', 'Unzipping failed')
                            self.messageLabel.config(text='Error! check logs')
                    else:
                        self.writeLog('info', 'Unsupported files format or no ".pcap/.pcapng" found or no valid '
                                              '".zip" found or this folder is having mix of files')
                        self.messageLabel.config(text='Error! check logs')
                        self.fileDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
                        self.pathEntry.config(state='disabled')
                    self.resetBtn.config(state='normal', fg='white', bg='orange', cursor='hand2')
                else:
                    self.writeLog('warning', 'No zip source path selected')
                    self.messageLabel.config(text='Please select source path')
                    self.fileDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                    self.pathEntry.config(state='disabled')
            end = time()
            elapsedTime = end - start
            hours, remainder = divmod(elapsedTime, 3600)
            minutes, remainder = divmod(remainder, 60)
            seconds, milliseconds = divmod(remainder, 1)
            self.writeLog('info', f'ELAPSED TIME TO READ FILES {int(hours)} hours {int(minutes)} minutes {int(seconds)}'
                                  f' seconds {int(milliseconds * 1000)} milliseconds')
            self.toolMenu.entryconfig("Filters", state="normal")

        threadFileDialog = Thread(target=fileDialogTread)
        threadFileDialog.start()

    def filterMerge(self):
        def filterMergeTread():
            self.toolMenu.entryconfig("Filters", state="disabled")
            self.progress.config(value=0)
            self.progressStyle.configure("Custom.Horizontal.TProgressbar", background="yellow", text='0 %')
            self.submitBtn.config(state='disabled', bg='light grey', cursor='arrow')
            self.resetBtn.config(state='disabled', bg='light grey', cursor='arrow')
            self.filterCombo.config(state='disabled')
            startFilter = time()
            self.customFilterEntry.config(state='readonly')

            if not exists('Filtered'):
                self.writeLog('info', '[Filtered] path does not exists, creating..')
                makedirs('Filtered')
                self.writeLog('info', '[Filtered] path created')
            self.messageLabel.config(text='Filtering..')
            self.writeLog('info', 'Filtering...')
            filterPass = 0
            filterFail = 0

            async def filterFile():
                nonlocal filterPass, filterFail

                async def innerFilterFile(f):
                    DETACHED_PROCESS = 0x00000008
                    filteredPath = 'Filtered/' + basename(f)
                    commandR = [self.pathTshark, '-r', f, '-w', filteredPath, '-2', '-R',
                                self.userSelectedFilterSyntax]
                    filterProcess = await create_subprocess_exec(*commandR, stdout=PIPE, stderr=PIPE,
                                                                 creationflags=DETACHED_PROCESS)
                    stdout, stderr = await filterProcess.communicate()
                    if filterProcess.returncode == 0:
                        return True, f
                    else:
                        return False, f, filterProcess.returncode, stderr, stdout

                totalFilesToFilter = len(self.inputFiles)
                tasks = []
                for file in self.inputFiles:
                    tasks.append(create_task(innerFilterFile(file)))
                for task in as_completed(tasks):
                    result = await task
                    if result[0]:
                        filterPass = filterPass + 1
                        self.updateProgress(filterPass, totalFilesToFilter)
                        self.writeLog('info', f'[{result[1]}] filtered')
                    if not result[0]:
                        self.writeLog('error', f'[{result[1]}] failed to filter')
                        self.writeLog('debug', f'FILTER PROCESS RETURN-CODE {result[2]}')
                        self.writeLog('debug', f'FILTER PROCESS ERROR {result[3]}')
                        self.writeLog('debug', f'FILTER PROCESS Output {result[4]}')
                        filterFail = filterFail + 1

            try:
                run(filterFile())
            except Exception as e:
                self.writeLog('error', 'Error while running multiprocessing filter')
                self.writeLog('debug', f'{e}')
                self.messageLabel.config(text='error, check logs!')
            self.writeLog('info', f'[{filterPass}] files filtered successfully')
            self.writeLog('info', f'[{filterFail}] files failed to filter')
            endFilter = time()
            elapsedTimeFilter = endFilter - startFilter
            hoursFilter, remainderFilter = divmod(elapsedTimeFilter, 3600)
            minutesFilter, remainderFilter = divmod(remainderFilter, 60)
            secondsFilter, millisecondsFilter = divmod(remainderFilter, 1)
            self.writeLog('info', f'ELAPSED TIME TO COMPLETE Filtering PROCESS IS {int(hoursFilter)} hours '
                                  f'{int(minutesFilter)} minutes {int(secondsFilter)} seconds '
                                  f'{int(millisecondsFilter * 1000)} milliseconds')
            startMerging = time()
            if filterPass > 0:
                self.writeLog('info', 'Done filtering, merging all the filtered files')
                self.messageLabel.config(text='Filter completed, Merging all the filtered Wireshark files')
                command = [self.pathMergeCap, '-w', self.outputFilePath, 'Filtered/*.pcap*']
                mergeProcess = Popen(command, shell=True)
                mergeProcess.wait()
                if mergeProcess.returncode == 0:
                    self.writeLog('info', 'Files merged successfully')
                    self.writeLog('info', f'{self.userEnteredPath} saved')
                    self.progress.config(value=100)
                    self.progressStyle.configure("Custom.Horizontal.TProgressbar", background="green",
                                                 text='100 %')

                    self.messageLabel.config(
                        text=f'{splitext(basename(self.userEnteredPath))[0][:3]}...pcapng created '
                             f'successfully')
                else:
                    self.writeLog('error', 'Failed to merge filtered files')
                    self.writeLog('debug', f'MERGE PROCESS RETURN-CODE{mergeProcess.returncode}')
                self.customFilterEntry.config(state='normal')
                self.customFilterEntry.delete(0, END)
                self.customFilterEntry.config(state='readonly')
                self.pathEntry.config(state='normal')
                self.pathEntry.delete(0, END)
                self.pathEntry.config(state='readonly')
                self.outputEntry.config(state='normal')
                self.outputEntry.delete(0, END)
                self.outputEntry.config(state='readonly')
                self.fileDialogBtn.config(state='disabled', bg='light grey', cursor='arrow')
                self.submitBtn.config(state='disabled', bg='light grey', cursor='arrow')
                self.filterCombo.set("Select filter")
                self.resetBtn.config(state='normal', fg='white', bg='orange', cursor='hand2')
            else:
                self.messageLabel.config(text='Error! Check logs')
                self.writeLog('error', 'No filtered files available to merge')
                self.resetBtn.config(state='normal', fg='white', bg='orange', cursor='hand2')
            try:
                rmtree('Filtered')
                rmtree('Extracted')
            except Exception as e:
                self.writeLog('error', 'Error while removing the files')
                self.writeLog('debug', f'{e}')
                pass
            endMerging = time()
            elapsedTimeMerge = endMerging - startMerging
            hoursMerge, remainderMerge = divmod(elapsedTimeMerge, 3600)
            minutesMerge, remainderMerge = divmod(remainderMerge, 60)
            secondsMerge, millisecondsMerge = divmod(remainderMerge, 1)
            self.writeLog('info', f'ELAPSED TIME TO COMPLETE Merging PROCESS IS {int(hoursMerge)} hours '
                                  f'{int(minutesMerge)} minutes {int(secondsMerge)} seconds '
                                  f'{int(millisecondsMerge * 1000)} milliseconds')
            elapsedTimeTotal = endMerging - startFilter
            hoursTotal, remainderTotal = divmod(elapsedTimeTotal, 3600)
            minutesTotal, remainderTotal = divmod(remainderTotal, 60)
            secondsTotal, millisecondsTotal = divmod(remainderTotal, 1)
            self.writeLog('info', f'ELAPSED TIME TO COMPLETE WHOLE PROCESS IS {int(hoursTotal)} hours '
                                  f'{int(minutesTotal)} minutes {int(secondsTotal)} seconds '
                                  f'{int(millisecondsTotal * 1000)} milliseconds')

            self.toolMenu.entryconfig("Filters", state="normal")

        thread_submitBtn = Thread(target=filterMergeTread)
        thread_submitBtn.start()

    def handleFileName(self):
        self.resetBtn.config(state='disabled', bg='light grey', cursor='arrow')
        self.messageLabel.config(text='')
        self.outputFilePath = "merged.pcapng"
        try:
            self.userEnteredPath = filedialog.asksaveasfilename(defaultextension=".pcapng",
                                                                filetypes=[("wireshark files", "*.pcapng")])
            if self.userEnteredPath:
                self.saveDialogBtn.config(state='disabled', fg='white', bg='light grey', cursor='arrow')
                self.outputFilePath = self.userEnteredPath
                self.outputEntry.config(state='normal')
                self.outputEntry.insert(0, self.outputFilePath)
                self.outputEntry.config(state='readonly')
                self.filterCombo.config(state='normal')
                self.writeLog('info', f'User entered {self.userEnteredPath} as output')
            else:
                self.saveDialogBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
                self.outputEntry.config(state='readonly')
                self.filterCombo.config(state='disabled')
                self.writeLog('warning', 'User entered no output filename')
                self.messageLabel.config(text='Select output filename')
        except Exception as e:
            self.writeLog('error', f'Error while applying user given file path and filename, saving merged data with '
                                   f'default name {self.outputFilePath} at current working directory')
            self.writeLog('debug', f'{e}')
        self.resetBtn.config(state='normal', fg='white', bg='orange', cursor='hand2')

    def filterComboSelection(self, event):
        userSelectedFilterName = self.filterCombo.get()
        self.outputFilePath = self.userEnteredPath
        if userSelectedFilterName == self.availableKeysToSelectList[0]:
            self.userSelectedFilterSyntax = self.customFilterEntry.get()
            self.outputFilePath = self.outputFilePath.replace('.pcapng', f"_custom.pcapng")
            self.customFilterEntry.config(state='normal')
            self.customFilterEntry.delete(0, 'end')
            self.submitBtn.config(state='disabled', bg='light grey', cursor='arrow')
            self.messageLabel.config(text='Type custom filter')
            self.writeLog('info', f'User selected custom filter in combo, type custom filter')
        if not userSelectedFilterName == self.availableKeysToSelectList[0]:
            dbConn = connect(self.dbFileName)
            dbCur = dbConn.cursor()
            dbCur.execute(f"SELECT filtersSyntax FROM {self.dbTableName} WHERE filtersName = ?",
                          (userSelectedFilterName,))
            self.userSelectedFilterSyntax = dbCur.fetchone()[0]
            self.outputFilePath = self.outputFilePath.replace('.pcapng', f"_{userSelectedFilterName}.pcapng")
            self.customFilterEntry.config(state='normal')
            self.customFilterEntry.delete(0, 'end')
            self.customFilterEntry.insert('end', self.userSelectedFilterSyntax)
            self.customFilterEntry.config(state='readonly')
            self.submitBtn.config(state='normal', fg='white', bg='green', cursor='hand2')
            self.messageLabel.config(text='Click "Submit" to proceed')
            dbConn.close()
        self.outputEntry.config(state='normal')
        self.outputEntry.delete(0, 'end')
        self.outputEntry.insert('end', self.outputFilePath)
        self.outputEntry.config(state='readonly')
        self.writeLog('info', f'User selected filter name "{userSelectedFilterName}"')
        self.writeLog('debug', f'User selected filter syntax "{self.userSelectedFilterSyntax}"')

    def checkConfTsharkMergeCap(self):
        try:
            csvReader = None
            with open(self.pathConf, 'r') as cFile:
                csvReader = list(reader(cFile))
        except Exception as e:
            self.writeLog('error', 'Error occurred while opening conf\conf.csv')
            self.writeLog('debug', f'[{e}]')
            self.messageLabel.config(text='Error, check logs!')
        if csvReader is not None:
            self.pathTshark = csvReader[0][1]
            self.pathMergeCap = csvReader[1][1]
        else:
            self.pathTshark = None
            self.pathMergeCap = None
        if self.pathTshark and self.pathMergeCap:
            if exists(self.pathTshark) and exists(self.pathMergeCap):
                self.writeLog('info', f'[tshark.exe] and [mergecap.exe] found at specified path in conf/conf.xml '
                                      f'[{self.pathMergeCap}] [{self.pathTshark}]')
                self.radioFolder.config(state='normal', cursor='hand2')
                self.radioZipped.config(state='normal', cursor='hand2')
            else:
                self.radioFolder.config(state='disabled', cursor='arrow')
                self.radioZipped.config(state='disabled', cursor='arrow')
                self.writeLog('error', f'[mergecap.exe] or [tshark.exe] not found at specified path in conf/conf.xml '
                                       f'[{self.pathMergeCap}] [{self.pathTshark}]')
                self.messageLabel.config(text='Error, check logs!')

    def createFilterDB(self):
        dbPath = join(dirname((argv[0])), self.dbFileName)
        self.writeLog('info', 'Connecting filter DB')
        try:
            if exists(dbPath):
                self.writeLog('info', f'[{self.dbFileName}] exists, connecting existing DB')
                dbConn = connect(self.dbFileName)
            else:
                self.writeLog('info', f'Filter DB is not available in conf, creating DB [{self.dbFileName}] with '
                                      f'default filters')
                dbConn = connect(self.dbFileName)
                newDbCur = dbConn.cursor()
                newDbCur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{self.dbTableName}'")
                existingTable = newDbCur.fetchone()
                if existingTable:
                    newDbCur.execute(f"DROP TABLE {self.dbTableName}")
                newDbCur.execute(
                    f"CREATE TABLE IF NOT EXISTS {self.dbTableName} (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    f"filtersName TEXT, filtersSyntax TEXT, filterType TEXT)")
                for wsFilter, filterSyntax in self.preconfiguredFilterDict.items():
                    newDbCur.execute(f"INSERT INTO {self.dbTableName} (filtersName, filtersSyntax, filterType) "
                                     f"VALUES (?, ?, ?)", (wsFilter, filterSyntax, 'default'))
                dbConn.commit()
                self.writeLog('info', f'Filter DB [{self.dbFileName}] with default filters created in conf')
            dbCur = dbConn.cursor()
            dbCur.execute(f"SELECT filtersName FROM {self.dbTableName}")
            self.availableKeysToSelectList = [row[0] for row in dbCur.fetchall()]
            dbConn.close()
        except Exception as e:
            self.writeLog('error', f'Error occurred while connecting/Creating {self.dbFileName}')
            self.writeLog('debug', f'[{e}]')
            self.messageLabel.config(text=f'Warning, issue with {self.dbFileName}!')

    def writeLog(self, messageType, message):
        timeStamp = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
        formattedFileCount = f"{self.logFilCount:05d}"
        newFileName = f'logs_{timeStamp}_({formattedFileCount}).txt'
        if self.fileHandler is None or self.currentLineCountLog >= self.maxLinesPerLogFile:
            if self.fileHandler is not None:
                self.fileHandler.write(f"End of file, Next file: {newFileName}")
                self.fileHandler.flush()
                self.fileHandler.close()
            self.fileHandler = open(f"log/{newFileName}", 'a')
            self.logFilCount += 1
            self.currentLineCountLog = 0
        self.fileHandler.write(f'{datetime.now().replace(microsecond=0)} [{messageType}] {message}\n')
        self.currentLineCountLog += 1
        self.fileHandler.flush()

    def launchFilterModWindow(self):
        filterMod(self.window, self.dbFileName, self.dbTableName, self.preconfiguredFilterDict, self.writeLog)

    def runGUI(self):

        def validateComboInput():
            return False

        comboTypeDisabledCommand = self.window.register(validateComboInput)
        self.customFilterEntry.bind('<KeyRelease>', self.checkEntries)
        self.filterCombo['validatecommand'] = comboTypeDisabledCommand
        self.filterCombo.bind("<<ComboboxSelected>>", self.filterComboSelection)
        self.checkConfTsharkMergeCap()
        self.createFilterDB()
        self.filterCombo.configure(values=self.availableKeysToSelectList)
        self.window.mainloop()


class filterMod:
    listColumnsHeading = ("Filter-Name", "Filter-Syntax")

    def __init__(self, mainWin, dbFile, dbTable, preDict, logWriter):
        filterwarnings("ignore", category=UserWarning)
        self.dbFileName = dbFile
        self.dbTableName = dbTable
        self.preconfiguredFilterDict = preDict
        self.writeLog = logWriter
        self.filterModWin = Toplevel(mainWin)
        self.writeLog('info', 'User opened modification window')
        self.filterModWinIcon = join(dirname(__file__), 'mod.ico')
        self.filterModWin.title('Filter Modification')
        self.filterModWin.iconbitmap(self.filterModWinIcon)
        self.filterModWin.resizable(False, False)
        self.filterModWin.grab_set()
        self.filterModWin.focus_set()
        self.filterModNotebook = Notebook(self.filterModWin, width=420, height=430)

        self.filterModTab1 = Frame(self.filterModNotebook, bg='light grey')
        self.filterModNotebook.add(self.filterModTab1, text="Modify Filter")
        self.filterModNotebook.pack()
        self.filterModTab1Frame = Frame(self.filterModTab1, borderwidth=2, relief="groove")
        self.filterModTab1Frame.place(x=5, y=7)
        self.filterModTab1FilterNameEntry = Entry(self.filterModTab1Frame, width=54, fg='grey', font=("Arial", 9))
        self.filterModTab1FilterNameEntry.pack(side="right", padx=5)
        self.filterModTab1FilterNameEntry.insert(0, "Search here")
        self.filterModTab1FilterNameEntryLabel = Label(self.filterModTab1Frame)
        self.filterModTab1FilterNameEntryLabel.pack(side="right", padx=(0, 5))
        self.filterModTab1MessageLabel = Label(self.filterModTab1, bg='light grey', font=("Helvetica", 10))
        self.filterModTab1MessageLabel.place(x=2, y=45)
        self.filterModTab1ListFrame = Frame(self.filterModTab1, height=8, width=10)
        self.filterModTab1ListFrame.place(x=0, y=95)
        self.filterModTab1ListScrollY = Scrollbar(self.filterModTab1ListFrame, orient='vertical')
        self.filterModTab1ListScrollY.grid(row=0, column=2, sticky="ns")
        self.filterModTab1ListScrollX = Scrollbar(self.filterModTab1ListFrame, orient='horizontal')
        self.filterModTab1ListScrollX.grid(row=1, column=0, sticky="ew", columnspan=3)
        self.filterModTab1List = Treeview(self.filterModTab1ListFrame, columns=self.listColumnsHeading, show="headings",
                                          yscrollcommand=self.filterModTab1ListScrollY.set,
                                          xscrollcommand=self.filterModTab1ListScrollX.set, cursor='hand2')
        self.filterModTab1ListScrollY.config(command=self.filterModTab1List.yview)
        self.filterModTab1ListScrollX.config(command=self.filterModTab1List.xview)
        self.filterModTab1List.grid(row=0, column=0, sticky="nsew")
        self.filterModTab1List.tag_configure('evenRowDefault', background='white')
        self.filterModTab1List.tag_configure('oddRowDefault', background='light blue')
        self.filterModTab1List.tag_configure('evenRowUserAdded', background='grey')
        self.filterModTab1List.tag_configure('oddRowUserAdded', background='light grey')
        self.style = Style()
        self.style.theme_use('default')
        self.style.configure("Treeview", foreground='black', background='white', rowheight=25, fieldbackground='white')
        self.style.configure("Treeview.Heading", font=("Helvetica", 10))
        self.style.map("Treeview", background=[('selected', 'brown')])
        for col in self.listColumnsHeading:
            self.filterModTab1List.heading(col, text=col)
        self.filterNameUserEntry = Entry(self.filterModTab1ListFrame, highlightthickness=2, highlightcolor="blue",
                                         state='disabled', validate="key",
                                         validatecommand=(self.filterModWin.register(self.validateUserInput), "%P"))
        self.filterNameUserEntry.grid(row=2, column=0, columnspan=3, sticky="ew")
        self.filterSyntaxUserEntry = Entry(self.filterModTab1ListFrame, highlightthickness=2, highlightcolor="blue",
                                           state='disabled')
        self.filterSyntaxUserEntry.grid(row=3, column=0, columnspan=3, sticky="ew")

        self.filterModTab1FilterNameEntry.bind('<KeyRelease>', lambda event: self.returnSearch())
        self.filterModTab1FilterNameEntry.bind("<FocusIn>",
                                               lambda event: (self.filterModTab1FilterNameEntry.delete(0, 'end'),
                                                              self.filterModTab1FilterNameEntry.config(fg='black'))
                                               if self.filterModTab1FilterNameEntry.get() == "Search here" else None)
        self.filterModTab1FilterNameEntry.bind("<FocusOut>",
                                               lambda event: self.filterModTab1FilterNameEntry.insert(0, "Search here")
                                               if not self.filterModTab1FilterNameEntry.get() else None)
        self.filterModTab1List.bind("<<TreeviewSelect>>", self.onListItemSelection)
        self.filterModWin.bind('<Key>', self.saveModifications)

        self.filterModWin.after(1, self.updateListboxFetchAll)

    def validateUserInput(self, P):
        pattern = r'^[a-zA-Z0-9_\-()]*$'
        if match(pattern, P) is not None:
            self.filterModTab1MessageLabel.config(text='')
            return True
        else:
            self.filterModTab1MessageLabel.config(text='No special characters except "-", "_" and "()"', fg='red')
            return False

    def returnSearch(self):
        self.filterModTab1MessageLabel.config(text='')
        filterName = self.filterModTab1FilterNameEntry.get()
        if len(filterName) > 0:
            count = 0
            self.writeLog('info', f'Searching DB for filterName [{filterName}] entered by user')
            self.writeLog('info', f'Connecting to DB {self.dbFileName}')
            dbConn = connect(self.dbFileName)
            dbCur = dbConn.cursor()
            dbCur.execute(f"SELECT * FROM {self.dbTableName} WHERE UPPER(FiltersName) LIKE UPPER(?)",
                          ('%' + filterName + '%',))
            matchesFilters = dbCur.fetchall()
            self.filterModTab1List.delete(*self.filterModTab1List.get_children())
            if len(matchesFilters) == 0:
                self.writeLog('info', f'No match found for [{filterName}]')
                self.filterModTab1MessageLabel.config(text=f'No filter exists with name {filterName}', fg='red')
            else:
                self.writeLog('info', f'Matches found, updating list')
                self.filterModTab1MessageLabel.config(text='')
                self.filterModTab1List.column("Filter-Name", width=270)
                self.filterModTab1List.column("Filter-Syntax", width=440)
                for findMatchedFilter in matchesFilters:
                    if findMatchedFilter[1].lower() != 'Custom Filter'.lower():
                        if findMatchedFilter[3] == 'default':
                            if count % 2 == 0:
                                self.filterModTab1List.insert(parent="", index="end", values=(findMatchedFilter[1],
                                                                                              findMatchedFilter[2]),
                                                              tags=('evenRowDefault',))
                            else:
                                self.filterModTab1List.insert(parent="", index="end", values=(findMatchedFilter[1],
                                                                                              findMatchedFilter[2]),
                                                              tags=('oddRowDefault',))
                        elif findMatchedFilter[3] == 'userAdded':
                            if count % 2 == 0:
                                self.filterModTab1List.insert(parent="", index="end", values=(findMatchedFilter[1],
                                                                                              findMatchedFilter[2]),
                                                              tags=('evenRowUserAdded',))
                            else:
                                self.filterModTab1List.insert(parent="", index="end", values=(findMatchedFilter[1],
                                                                                              findMatchedFilter[2]),
                                                              tags=('oddRowUserAdded',))
                        count = count + 1
            dbConn.close()
            self.writeLog('info', 'List updated, closing db connection')
        if len(filterName) == 0:
            self.updateListboxFetchAll()
        self.filterNameUserEntry.config(state='normal')
        self.filterNameUserEntry.delete(0, "end")
        self.filterNameUserEntry.config(state='disabled')
        self.filterSyntaxUserEntry.config(state='normal')
        self.filterSyntaxUserEntry.delete(0, "end")
        self.filterSyntaxUserEntry.config(state='disabled')

    def updateListboxFetchAll(self):
        self.filterModTab1List.focus_set()
        count = 0
        self.filterModTab1List.delete(*self.filterModTab1List.get_children())
        dbConn = connect(self.dbFileName)
        dbCur = dbConn.cursor()
        dbCur.execute(f"SELECT * FROM {self.dbTableName}")
        allAvailFilter = dbCur.fetchall()
        self.filterModTab1List.column("Filter-Name", width=270)
        self.filterModTab1List.column("Filter-Syntax", width=440)
        for oneFilter in allAvailFilter[1:]:
            if oneFilter[3] == 'default':
                if count % 2 == 0:
                    self.filterModTab1List.insert(parent="", index="end", values=(oneFilter[1], oneFilter[2]),
                                                  tags=('evenRowDefault',))
                else:
                    self.filterModTab1List.insert(parent="", index="end", values=(oneFilter[1], oneFilter[2]),
                                                  tags=('oddRowDefault',))
            elif oneFilter[3] == 'userAdded':
                if count % 2 == 0:
                    self.filterModTab1List.insert(parent="", index="end", values=(oneFilter[1], oneFilter[2]),
                                                  tags=('evenRowUserAdded',))
                else:
                    self.filterModTab1List.insert(parent="", index="end", values=(oneFilter[1], oneFilter[2]),
                                                  tags=('oddRowUserAdded',))
            count = count + 1
        dbCur.close()
        self.filterNameUserEntry.delete(0, "end")
        self.filterNameUserEntry.config(state='disabled')
        self.filterSyntaxUserEntry.delete(0, "end")
        self.filterSyntaxUserEntry.config(state='disabled')
        dbConn.close()

    def onListItemSelection(self, event):
        self.filterModTab1MessageLabel.config(text='')
        selectedItem = self.filterModTab1List.selection()
        if selectedItem:
            itemValues = self.filterModTab1List.item(selectedItem, "values")
            self.filterNameUserEntry.config(state='normal')
            self.filterNameUserEntry.delete(0, "end")
            self.filterNameUserEntry.insert(0, itemValues[0])
            self.filterSyntaxUserEntry.config(state='normal')
            self.filterSyntaxUserEntry.delete(0, "end")
            self.filterSyntaxUserEntry.insert(0, itemValues[1])
            self.writeLog('info', f'User selected filter [{itemValues}]')
            if itemValues[0] not in self.preconfiguredFilterDict.keys():
                self.writeLog('info', f'User selected [{itemValues}] is not default filter, can be modified')
            else:
                self.writeLog('info', f'[{itemValues}] is default filter and modification not allowed')
                self.filterNameUserEntry.config(state='readonly')
                self.filterSyntaxUserEntry.config(state='readonly')
        self.filterModWin.bind("<Delete>", self.deleteManualEntries)

    def saveModifications(self, event):
        dbConn = connect(self.dbFileName)
        dbCur = dbConn.cursor()
        if (event.keysym == 'n' or event.keysym == 'N') and event.state & 0x4:
            self.filterModTab1MessageLabel.config(text='Enter filterName and filter syntax to add', fg='green')
            self.writeLog('info', 'User proceed to add new filter')
            self.filterModTab1List.selection_remove(self.filterModTab1List.selection())
            self.filterNameUserEntry.config(state='normal')
            self.filterNameUserEntry.delete(0, "end")
            self.filterNameUserEntry.focus_set()
            self.filterSyntaxUserEntry.config(state='normal')
            self.filterSyntaxUserEntry.delete(0, "end")

        if (event.keysym == 's' or event.keysym == 'S') and event.state & 0x4:
            selectedItem = self.filterModTab1List.selection()
            userInputFilterNameState = self.filterNameUserEntry.cget("state")
            userInputSyntaxNameState = self.filterNameUserEntry.cget("state")
            if (userInputFilterNameState != 'disabled' and userInputFilterNameState != 'readonly') or \
                    (userInputSyntaxNameState != 'disabled' and userInputSyntaxNameState != 'readonly'):
                userInputFilterName = self.filterNameUserEntry.get()
                userInputSyntaxName = self.filterSyntaxUserEntry.get()
                if selectedItem:
                    itemValue = self.filterModTab1List.item(selectedItem, "values")[0]
                    dbCur.execute(f"SELECT id FROM {self.dbTableName} WHERE filtersName = ?", (itemValue,))
                    currentSelection = dbCur.fetchone()[0]
                    self.writeLog('info', f'Modifying attributes of [{itemValue}]')
                    try:
                        if len(userInputFilterName) > 0 and len(userInputSyntaxName) > 0:
                            dbCur.execute(f"SELECT COUNT(*) FROM {self.dbTableName} WHERE filtersName = ?",
                                          (userInputFilterName,))
                            existingResult = dbCur.fetchone()
                            if existingResult[0] == 0:
                                dbCur.execute(f"UPDATE {self.dbTableName} SET filtersName = ?, filtersSyntax = ? "
                                              f"WHERE id = ?",
                                              (userInputFilterName, userInputSyntaxName, currentSelection))
                                dbConn.commit()
                                self.writeLog('info', f'Attributes of [{itemValue}] modifies with '
                                                      f'[{userInputFilterName}] [{userInputSyntaxName}] '
                                                      f'successfully. Fetching updated list for user')
                                self.updateListboxFetchAll()
                                self.filterModTab1MessageLabel.config(text='Changes saved', fg='green')
                            else:
                                self.writeLog('warning', f'Modification of filter [{itemValue}] failed. Modified '
                                                         f'name [{userInputFilterName}] already exists, choose '
                                                         f'unique name')
                                self.filterModTab1MessageLabel.config(text='Filter name exists, choose unique name',
                                                                      fg='red')
                        else:
                            self.writeLog('warning', 'User trying to save with at least one empty entry')
                            self.filterModTab1MessageLabel.config(text='Both fields are mandatory', fg='red')
                    except Exception as e:
                        self.filterModTab1MessageLabel.config(text='modifications failed', fg='red')
                        self.writeLog('error', 'Error while saving the modifications')
                        self.writeLog('debug', f'{e}')
                if not selectedItem:
                    try:
                        if len(userInputFilterName) > 0 and len(userInputSyntaxName) > 0:
                            dbCur.execute(f"SELECT COUNT(*) FROM {self.dbTableName} WHERE filtersName = ?",
                                          (userInputFilterName,))
                            existingResult = dbCur.fetchone()
                            if existingResult[0] == 0:
                                dbCur.execute(f"INSERT INTO {self.dbTableName} (filtersName, filtersSyntax, "
                                              f"filterType) VALUES (?, ?, ?)", (userInputFilterName,
                                                                                userInputSyntaxName, 'userAdded'))
                                dbConn.commit()
                                self.writeLog('info', f'New filter having filter name [{userInputFilterName}] and '
                                                      f'filter syntax [{userInputSyntaxName}] added successfully. '
                                                      f'Fetching updated list for user')
                                self.updateListboxFetchAll()
                                self.filterModTab1List.yview_moveto(1.0)
                                self.filterModTab1MessageLabel.config(text='Filter added', fg='green')
                            else:
                                self.writeLog('warning', f'New filter having filter name [{userInputFilterName}] '
                                                         f'and filter syntax [{userInputSyntaxName}] failed to '
                                                         f'add. Same filter name already exists')
                                self.filterModTab1MessageLabel.config(text='Filter name exists, choose unique name',
                                                                      fg='red')
                        elif len(userInputFilterName) == 0 and len(userInputSyntaxName) == 0:
                            self.writeLog('warning', 'User trying to add new filter with at least one empty entry')
                            self.filterModTab1MessageLabel.config(text='Both fields are mandatory', fg='red')
                    except Exception as e:
                        self.filterModTab1MessageLabel.config(text='Failed to add new filter', fg='red')
                        self.writeLog('error', 'Error while saving new filter')
                        self.writeLog('debug', f'{e}')
            else:
                self.writeLog('warning', 'User trying to save unmodified entries (disabled/readonly entries)')
        dbConn.close()

    def deleteManualEntries(self, event):
        selectedItem = self.filterModTab1List.selection()
        dbConn = connect(self.dbFileName)
        dbCur = dbConn.cursor()
        if selectedItem:
            itemValue = self.filterModTab1List.item(selectedItem, "values")[0]
            if itemValue not in self.preconfiguredFilterDict.keys():
                dbCur.execute(f"SELECT id FROM {self.dbTableName} WHERE filtersName = ?", (itemValue,))
                currentSelection = dbCur.fetchone()[0]
                self.writeLog('warning', f'User trying to delete [{itemValue}] having id [{currentSelection}]')
                try:
                    dbCur.execute(f"DELETE FROM {self.dbTableName} WHERE id = ?", (currentSelection,))
                    dbConn.commit()
                    self.writeLog('info', f'Removed filter {itemValue} permanently')
                    self.updateListboxFetchAll()
                    self.filterModTab1MessageLabel.config(text='Removed successfully', fg='green')
                except Exception as e:
                    self.writeLog('error', f'Error while removing [{itemValue}] having id [{currentSelection}]')
                    self.writeLog('debug', f'{e}')
                    self.filterModTab1MessageLabel.config(text='Failed to remove', fg='red')
            else:
                self.writeLog('warning', f'User trying to delete default filter [{itemValue}]')
                self.filterModTab1MessageLabel.config(text='Default filters cannot remove', fg='red')
        dbConn.close()


if __name__ == '__main__':
    flc_app = WSApp()
    flc_app.runGUI()
