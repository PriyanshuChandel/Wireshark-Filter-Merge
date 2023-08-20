from os import devnull, path, makedirs
from os.path import exists, join, dirname
from glob import glob
from subprocess import Popen
from shutil import rmtree
from zipfile import ZipFile
from tkinter import Tk, filedialog, END, StringVar, Label, Radiobutton, Entry, Button, Toplevel
from tkinter.ttk import Progressbar, Style
from threading import Thread
from datetime import datetime
from csv import reader
from time import time

if not exists('log'):
    makedirs('log')
fileHandler = open(f"log/logs_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt", 'a')

userConf = 'conf/conf.csv'
iconFile = join(dirname(__file__), 'wireshark.ico')
aboutIcon = join(dirname(__file__), 'info.ico')


def unZip(zippedPath, progressBar, window, progressStyle, messageText):
    progressStyle.configure("Custom.Horizontal.TProgressbar", background="yellow")
    unZipSuccess = 0
    if path.isdir(zippedPath):
        try:
            filesZippedPcap = glob(zippedPath + '\\*.zip')
            totalZippedFiles = len(filesZippedPcap)
            for zipFile in filesZippedPcap:
                multipleZip = ZipFile(zipFile)
                multipleZip.extractall('Extracted')
                unZipSuccess = unZipSuccess + 1
                updateProgress(progressBar, unZipSuccess, totalZippedFiles, window, progressStyle)
            progressBar.config(value=100)
            fileHandler.write(f'{datetime.now().replace(microsecond=0)} [UnZipping Success]\n')
            progressStyle.configure("Custom.Horizontal.TProgressbar", background="green", text='100 %')
            return True
        except Exception as failed:
            fileHandler.write(f'{datetime.now().replace(microsecond=0)} [ERROR UnZipping1] {failed}\n')
            messageText.config(text='Error! check logs')
            return False
    elif path.isfile(zippedPath):
        try:
            with ZipFile(zippedPath, 'r') as singleZip:
                singleZip.extractall('Extracted')
                updateProgress(progressBar, 1, 1, window, progressStyle)
                nestedZipFiles = [f for f in singleZip.namelist() if f.endswith('.zip')]
                totalNestedZippedFiles = len(singleZip.namelist())
                nestedSuccess = 0
                for nestedZip in nestedZipFiles:
                    nestedZipPath = path.join('Extracted', nestedZip)
                    ZipFile(nestedZipPath).extractall('Extracted')
                    nestedSuccess = nestedSuccess + 1
                    updateProgress(progressBar, nestedSuccess, totalNestedZippedFiles, window, progressStyle)
                progressBar.config(value=100)
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} [UnZipping Success]\n')
                progressStyle.configure("Custom.Horizontal.TProgressbar", background="green", text='100 %')
            return True
        except Exception as failed:
            fileHandler.write(f'{datetime.now().replace(microsecond=0)} [ERROR UnZipping2] {failed}\n')
            messageText.config(text='Error! check logs')
            return False
    else:
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} invalid input [{zippedPath}]\n')
        messageText.config(text='Error! check logs')
        return False


def threadingFileDialog(radioVarValue, pathEntry, dialogBtn, filterEntry, messageText, progressBar, window,
                        progressStyle, radioFolder, radioZipped, resetBtn):
    thread_fileDialog = Thread(target=fileDialogFunc,
                               args=(radioVarValue, pathEntry, dialogBtn, filterEntry, messageText, progressBar,
                                     window, progressStyle, radioFolder, radioZipped, resetBtn))
    thread_fileDialog.start()


files = ''


def fileDialogFunc(radioVarValue, pathEntry, dialogBtn, filterEntry, messageText, progressBar, window, progressStyle,
                   radioFolder, radioZipped, resetBtn):
    global files
    start = time()
    if radioVarValue == 'folder':
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} [Folder] radio button selected.\n')
        folderSourcePath = filedialog.askdirectory()
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} [{folderSourcePath}] selected as source path\n')
        pathEntry.config(state='normal')
        pathEntry.insert(0, folderSourcePath)
        if len(pathEntry.get()) > 0:
            radioFolder.config(state='disabled')
            radioZipped.config(state='disabled')
            filesPcap = glob(folderSourcePath + '\\*.pcap*')
            filesZippedPcap = glob(folderSourcePath + '\\*.zip')
            if filesPcap and not filesZippedPcap:
                files = filesPcap
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Folder having pcap/pcapng files\n')
                pathEntry.config(state='readonly')
                dialogBtn.config(state='disabled', bg='light grey')
                filterEntry.config(state='normal')
                messageText.config(text='Enter the filter and click on submit')
            elif filesZippedPcap and not filesPcap:
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Folder having multiple zipped captures\n')
                pathEntry.config(state='readonly')
                dialogBtn.config(state='disabled', bg='light grey')
                messageText.config(text='Enter the filter and click on submit')
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unpacking...\n')
                messageText.config(text='Unpacking captures..')
                unZipSuccess = unZip(folderSourcePath, progressBar, window, progressStyle, messageText)
                if unZipSuccess:
                    files = glob('Extracted\**\\*.pcap*', recursive=True)
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unpacking done...\n')
                    messageText.config(text='Unpacking done, enter the filter and click on submit')
                    filterEntry.config(state='normal')
                if not unZipSuccess:
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unzipping failed\n')
                    messageText.config(text='Error! check logs')

            else:
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unsupported files format or no '
                                  f'".pcap/.pcapng" found or no valid ".zip" found or this folder is having mix of '
                                  f'files\n')
                messageText.config(text='Error! check logs')
                dialogBtn.config(state='disabled', bg='light grey')
                pathEntry.config(state='disabled')
        else:
            fileHandler.write(f'{datetime.now().replace(microsecond=0)} No folder source path selected\n')
            messageText.config(text='Please select source path')
            dialogBtn.config(state='disabled', bg='light grey')
            pathEntry.config(state='disabled')

    elif radioVarValue == 'zip':
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} [Zip] radio button selected.\n')
        zippedSourcePath = filedialog.askopenfilename(filetypes=(("zip files", "*.zip"), ("all files", "*.*")))
        fileHandler.write(
            f'{datetime.now().replace(microsecond=0)} [{zippedSourcePath}] selected as Zip folder source '
            f'path\n')
        pathEntry.config(state='normal')
        pathEntry.insert(0, zippedSourcePath)
        if len(pathEntry.get()) > 0:
            radioFolder.config(state='disabled')
            radioZipped.config(state='disabled')
            pathEntry.config(state='readonly')
            dialogBtn.config(state='disabled', bg='light grey')
            with ZipFile(zippedSourcePath, 'r') as zip_ref:
                zipZipped = [file for file in zip_ref.namelist() if file.endswith('.zip')]
                filesZipped = [file for file in zip_ref.namelist() if
                               file.endswith('.pcap') or file.endswith('.pcapng')]

            if filesZipped and not zipZipped:
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} selected zip folder contains no further '
                                  f'zip file inside\n')
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unpacking...\n')
                messageText.config(text='Unpacking captures..')

                unZipSuccess = unZip(zippedSourcePath, progressBar, window, progressStyle, messageText)
                if unZipSuccess:
                    files = glob('Extracted\**\\*.pcap*', recursive=True)
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unpacking done...\n')
                    messageText.config(text='Unpacking done, enter the filter and click on submit')
                    filterEntry.config(state='normal')

                if not unZipSuccess:
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unzipping failed\n')
                    messageText.config(text='Error! check logs')

            elif zipZipped and not filesZipped:
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} selected zip folder contains further zip '
                                  f'inside\n')
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unpacking...\n')
                messageText.config(text='Unpacking captures..')
                unZipSuccess = unZip(zippedSourcePath, progressBar, window, progressStyle, messageText)
                if unZipSuccess:
                    files = glob('Extracted\**\\*.pcap*', recursive=True)
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unpacking done...\n')
                    messageText.config(text='Unpacking done, enter the filter and click on submit')
                    filterEntry.config(state='normal')

                if not unZipSuccess:
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unzipping failed\n')
                    messageText.config(text='Error! check logs')

            else:
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} Unsupported files format or no '
                                  f'".pcap/.pcapng" found or no valid ".zip" found or this folder is having mix of '
                                  f'files\n')
                messageText.config(text='Error! check logs')
                dialogBtn.config(state='disabled', bg='light grey')
                pathEntry.config(state='disabled')

        else:
            fileHandler.write(f'{datetime.now().replace(microsecond=0)} No zip source path selected\n')
            messageText.config(text='Please select source path')
            dialogBtn.config(state='disabled', bg='light grey')
            pathEntry.config(state='disabled')
    resetBtn.config(state='normal', bg='orange')
    end = time()
    elapsedTime = end - start
    hours, remainder = divmod(elapsedTime, 3600)
    minutes, remainder = divmod(remainder, 60)
    seconds, milliseconds = divmod(remainder, 1)
    fileHandler.write(f'{datetime.now().replace(microsecond=0)} ELAPSED TIME TO COMPLETE {int(hours)} '
                      f'hours {int(minutes)} minutes {int(seconds)} seconds {int(milliseconds * 1000)} milliseconds')


def threadingSubmitBtn(selectedFiles, messageText, filterEntry, pathEntry, fileDialogBtn, submitBtn, progressBar,
                       window, progressStyle, resetBtn):
    thread_submitBtn = Thread(target=filterMerge, args=(selectedFiles, messageText, filterEntry, pathEntry,
                                                        fileDialogBtn, submitBtn, progressBar, window, progressStyle,
                                                        resetBtn))
    thread_submitBtn.start()


def filterMerge(selectedFiles, messageText, filterEntry, pathEntry, fileDialogBtn, submitBtn, progressBar, window,
                progressStyle, resetBtn):
    progressBar.config(value=0)
    progressStyle.configure("Custom.Horizontal.TProgressbar", background="yellow", text='0 %')
    submitBtn.config(state='disabled', bg='light grey')
    resetBtn.config(state='disabled', bg='light grey')
    startFilter = time()
    csvReader = list(reader(open(userConf, 'r')))
    pathTShark = csvReader[0][1]
    endMerging = None
    if not path.exists(pathTShark):
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} tshark.exe not found at specified path in '
                          f'conf/conf.xml [{pathTShark}]\n')
        messageText.config(text='Error, check logs!')
    else:
        userFilter = str(filterEntry.get())
        filterEntry.config(state='readonly')
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} USER FILTER INPUT [{userFilter}]\n')
        fNull = open(devnull, 'w')
        if not path.exists('Filtered'):
            fileHandler.write(
                f'{datetime.now().replace(microsecond=0)} [Filtered] path does not exists, creating.. \n')
            makedirs('Filtered')
            fileHandler.write(f'{datetime.now().replace(microsecond=0)} [Filtered] path created\n')
        messageText.config(text='Filtering..')
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} Filtering...\n')
        filterPass = 0
        filterFail = 0
        totalFilesToFilter = len(selectedFiles)
        for file in selectedFiles:
            path_out = 'Filtered/' + path.basename(file)
            command = [pathTShark, '-r', file, '-w', path_out, '-2', '-R', userFilter]
            filterProcess = Popen(command, stdout=fNull, stderr=fNull, shell=True)
            streamData = filterProcess.communicate()
            if filterProcess.returncode != 0:
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} [{file}] failed to filter\n')
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} [FILTER PROCESS RETURN '
                                  f'CODE {filterProcess.returncode}]\n')
                filterFail = filterFail + 1
            elif filterProcess.returncode == 0:
                filterPass = filterPass + 1
                updateProgress(progressBar, filterPass, totalFilesToFilter, window, progressStyle)
                fileHandler.write(f'{datetime.now().replace(microsecond=0)} [{file}] filtered\n')
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} [{filterPass}] files filtered\n')
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} [{filterFail}] files failed to filter\n')
        endFilter = time()
        elapsedTimeFilter = endFilter - startFilter
        hoursFilter, remainderFilter = divmod(elapsedTimeFilter, 3600)
        minutesFilter, remainderFilter = divmod(remainderFilter, 60)
        secondsFilter, millisecondsFilter = divmod(remainderFilter, 1)
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} ELAPSED TIME TO COMPLETE Filtering PROCESS IS '
                          f'{int(hoursFilter)} hours {int(minutesFilter)} minutes {int(secondsFilter)} seconds '
                          f'{int(millisecondsFilter * 1000)} milliseconds')
        startMerging = time()
        if filterPass > 0:
            messageText.config(text='Filter completed, Merging all the filtered Wireshark files')
            pathMergeCAP = csvReader[1][1]
            if not path.exists(pathMergeCAP):
                fileHandler.write(
                    f'{datetime.now().replace(microsecond=0)} mergecap.exe not found at specified path in '
                    f'conf/conf.xml [{pathMergeCAP}]\n')
                messageText.config(text='Error, check logs!')
            else:
                pathOut = 'Merged.pcapng'
                command = [pathMergeCAP, '-w', pathOut, 'Filtered/*.pcap*']
                mergeProcess = Popen(command, shell=True)
                mergeProcess.wait()
                if mergeProcess.returncode != 0:
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} failed to merge filtered files\n')
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} [MERGE PROCESS RETURN '
                                      f'CODE{mergeProcess.returncode}]\n')
                else:
                    fileHandler.write(f'{datetime.now().replace(microsecond=0)} files merged successfully.\n')
                    progressBar.config(value=100)
                    progressStyle.configure("Custom.Horizontal.TProgressbar", background="green", text='100 %')
                    messageText.config(text='Merged.pcapng created at current working directory')
                filterEntry.config(state='normal')
                filterEntry.delete(0, END)
                filterEntry.config(state='disabled')
                pathEntry.config(state='normal')
                pathEntry.delete(0, END)
                pathEntry.config(state='disabled')
                fileDialogBtn.config(state='disabled')
                submitBtn.config(state='disabled', bg='light grey')
                resetBtn.config(state='normal', bg='orange')
        else:
            messageText.config(text='Error! Check logs')
            resetBtn.config(state='normal', bg='orange')
        try:
            rmtree('Filtered')
            rmtree('Extracted')
        except:
            pass
        endMerging = time()
        elapsedTimeMerge = endMerging - startMerging
        hoursMerge, remainderMerge = divmod(elapsedTimeMerge, 3600)
        minutesMerge, remainderMerge = divmod(remainderMerge, 60)
        secondsMerge, millisecondsMerge = divmod(remainderMerge, 1)
        fileHandler.write(f'{datetime.now().replace(microsecond=0)} ELAPSED TIME TO COMPLETE Merging PROCESS IS '
                          f'{int(hoursMerge)} hours {int(minutesMerge)} minutes {int(secondsMerge)} seconds '
                          f'{int(millisecondsMerge * 1000)} milliseconds')

    elapsedTimeTotal = endMerging - startFilter
    hoursTotal, remainderTotal = divmod(elapsedTimeTotal, 3600)
    minutesTotal, remainderTotal = divmod(remainderTotal, 60)
    secondsTotal, millisecondsTotal = divmod(remainderTotal, 1)
    fileHandler.write(f'{datetime.now().replace(microsecond=0)} ELAPSED TIME TO COMPLETE WHOLE PROCESS IS '
                      f'{int(hoursTotal)} hours {int(minutesTotal)} minutes {int(secondsTotal)} seconds '
                      f'{int(millisecondsTotal * 1000)} milliseconds')


def mainGUI():
    window = Tk()
    window.config(bg='light grey')
    window.title('Filter & Merge v1.1')
    window.geometry('520x300')
    window.resizable(False, False)
    window.iconbitmap(iconFile)
    radio_var = StringVar()
    radio_var.set(None)

    mainLabel = Label(window, text='Wireshark Filter and Merge', font=('Arial', 16, 'bold'), fg='blue', bg='light grey')
    mainLabel.place(x=250, y=20, anchor='center')

    radioFolder = Radiobutton(window, text='Folder (files, zipped files)', font=('Arial', 11, 'bold'), bg='light grey',
                              variable=radio_var,
                              command=lambda: enableFileDialogBtn(progress, pathEntry, filterEntry, submitBtn,
                                                                  fileDialogBtn,
                                                                  messageLabel), value='folder', padx=10, pady=5)
    radioFolder.place(x=145, y=40)

    radioZipped = Radiobutton(window, text='Zipped (files, zipped files)', font=('Arial', 11, 'bold'), bg='light grey',
                              variable=radio_var,
                              command=lambda: enableFileDialogBtn(progress, pathEntry, filterEntry, submitBtn,
                                                                  fileDialogBtn,
                                                                  messageLabel), value='zip', padx=10, pady=5)
    radioZipped.place(x=145, y=70)

    pathLabel = Label(window, text='Folder/Zipped', font=('Arial', 10, 'bold italic'), bg='light grey')
    pathLabel.place(x=6, y=110)
    pathEntry = Entry(window, bd=4, width=55, bg='white', state='disabled')
    pathEntry.place(x=110, y=110)
    pathEntry.bind('<KeyRelease>', lambda event: checkEntries(pathEntry, filterEntry, submitBtn))
    fileDialogBtn = Button(window, text='Browse', command=lambda: threadingFileDialog(radio_var.get(), pathEntry,
                                                                                      fileDialogBtn, filterEntry,
                                                                                      messageLabel, progress, window,
                                                                                      progressStyle, radioFolder,
                                                                                      radioZipped, resetBtn),
                           bg='light grey', state='disabled')
    fileDialogBtn.place(x=460, y=108)

    filterLabel = Label(window, text='Type filter', font=('Arial', 10, 'bold italic'), bg='light grey')
    filterLabel.place(x=6, y=150)
    filterEntry = Entry(window, bd=4, width=55, bg='white', state='disabled')
    filterEntry.place(x=110, y=150)
    filterEntry.bind('<KeyRelease>', lambda event: checkEntries(pathEntry, filterEntry, submitBtn))
    submitBtn = Button(window, text='Submit', command=lambda: threadingSubmitBtn(files, messageLabel,
                                                                                 filterEntry, pathEntry, fileDialogBtn,
                                                                                 submitBtn, progress, window,
                                                                                 progressStyle, resetBtn),
                       bg='light grey', state='disabled')
    submitBtn.place(x=230, y=185)
    resetBtn = Button(window, text='Reset',
                      command=lambda: resetBtnFunc(radioFolder, radioZipped, pathEntry, filterEntry,
                                                   fileDialogBtn, submitBtn, resetBtn, progress, messageLabel,
                                                   progressStyle),
                      bg='light grey', state='disabled')
    resetBtn.place(x=290, y=185)
    progress = Progressbar(window, length=510, mode="determinate", style="Custom.Horizontal.TProgressbar")
    progress.place(x=6, y=223)
    progressStyle = Style()
    progressStyle.theme_use('clam')
    progressStyle.configure("Custom.Horizontal.TProgressbar", background="yellow", text='0 %')
    progressStyle.layout('Custom.Horizontal.TProgressbar', [('Horizontal.Progressbar.trough',
                                                             {'children': [('Horizontal.Progressbar.pbar',
                                                                            {'side': 'left', 'sticky': 'ns'})],
                                                              'sticky': 'nswe'}),
                                                            ('Horizontal.Progressbar.label', {'sticky': ''})])
    messageLabel = Label(window, font=('Arial', 9, 'bold'), bg='light grey')
    messageLabel.place(x=6, y=250)
    warnLabel = Label(window, text='Note: Make sure Wireshark is installed and path configured in "conf/conf.csv"',
                      font=('Arial', 9, 'bold'), bg='light grey')
    warnLabel.place(x=6, y=280)
    aboutBtn = Button(window, text='About', bg='brown', command=lambda: aboutWindow(window))
    aboutBtn.place(x=470, y=270)
    window.mainloop()


def aboutWindow(mainWin):
    aboutWin = Toplevel(mainWin)
    aboutWin.grab_set()
    aboutWin.geometry('285x90')
    aboutWin.resizable(False, False)
    aboutWin.title('About')
    aboutWin.iconbitmap(aboutIcon)
    aboutWinLabel = Label(aboutWin, text=f'Version - 1.1\nDeveloped by Priyanshu\nFor any improvement please reach on '
                                         f'below email\nEmail : chandelpriyanshu8@outlook.com\nMobile : '
                                         f'+91-8285775109 '
                                         f'', font=('Helvetica', 9)).place(x=1, y=6)


def updateProgress(progressBar, newVal, totalVal, window, progressStyle):
    resultVal = (newVal / totalVal) * 99
    progressBar['value'] = resultVal
    progressStyle.configure("Custom.Horizontal.TProgressbar", text='{:g} %'.format(resultVal))
    window.update()


def enableFileDialogBtn(progressBar, pathEntry, filterEntry, submitBtn, fileDialogBtn, messageText):
    progressBar.config(value=0)
    pathEntry.config(state='normal')
    pathEntry.delete(0, 'end')
    filterEntry.config(state='normal')
    filterEntry.delete(0, 'end')
    submitBtn.config(state='disabled', bg='light grey')
    fileDialogBtn.config(state='normal', bg='green')
    filterEntry.config(state='disabled')
    pathEntry.config(state='disabled')
    messageText.config(text='')


def checkEntries(pathEntry, filterEntry, submitBtn):
    if pathEntry.get() and filterEntry.get():
        submitBtn.config(state='normal', bg='green')
    else:
        submitBtn.config(state='disabled', bg='light grey')


def resetBtnFunc(radioFolder, radioZipped, pathEntry, filterEntry, dialogBtn, submitBtn, resetBtn, progressBar,
                 messageText, progressStyle):
    radioFolder.config(state='normal')
    radioZipped.config(state='normal')
    pathEntry.config(state='normal')
    pathEntry.delete(0, END)
    pathEntry.config(state='disabled')
    filterEntry.config(state='normal')
    filterEntry.delete(0, END)
    filterEntry.config(state='disabled')
    dialogBtn.config(state='disabled')
    submitBtn.config(state='disabled', bg='light grey')
    resetBtn.config(state='disabled', bg='light grey')
    progressBar.config(value=0)
    progressStyle.configure("Custom.Horizontal.TProgressbar", text='0 %')
    messageText.config(text='')
    try:
        rmtree('Filtered')
        rmtree('Extracted')
    except:
        pass


mainGUI()
