from time import sleep
from os import devnull, path, makedirs
from os.path import join, dirname 
from glob import glob
from subprocess import Popen
from shutil import rmtree
from zipfile import ZipFile
from tkinter import Tk, filedialog, END, StringVar, Label, Radiobutton, Entry, Button
from threading import Thread


icon_file = join(dirname(__file__), 'wireshark.ico')
window = Tk()
window.config(bg='grey')
window.title('Filter&Merge v1.0 - Developed by Priyanshu')
window.minsize(width=500, height=265)
window.maxsize(width=500, height=265)
window.iconbitmap(icon_file)

def threading_btn2():
    thread_btn2 = Thread(target=btn2_func)
    thread_btn2.start()


def btn2_func():
    global files
    if radio_var.get() == 'unzip':
        path_selected = filedialog.askdirectory()
        files = glob(path_selected + '\\*.pcap*')
        ent2.insert(0, path_selected)
    elif radio_var.get() == 'zip':
        path_selected = filedialog.askopenfilename(filetypes=(("zip files", "*.zip"), ("all files", "*.*")))
        ent2.insert(0, path_selected)
        labl6.config(text='Unpacking captures, meanwhile enter the filter and click submit')
        sleep(3)
        zipfiles = glob(path_selected)
        for file in zipfiles:
            z = ZipFile(file)
            z.extractall('Extracted')
            files = glob('Extracted\**\\*.pcap*', recursive=True)
        sleep(2)
        labl6.config(text='Unpacking done')


def threading_btn3():
    thread_btn3 = Thread(target=filter_merge)
    thread_btn3.start()


def filter_merge():
    PATH_TSHARK = r"C:\Program Files (x86)\Wireshark\tshark.exe"
    FILTER = str(ent3.get())
    FNULL = open(devnull, 'w')
    if not path.exists('Filtered'):
        makedirs('Filtered')
    labl6.config(text='Started filtering..')
    for _f in files:
        path_out = 'Filtered/' + path.basename(_f)
        command = []
        command.append(PATH_TSHARK)
        command.append('-r')
        command.append(_f)
        command.append('-w')
        command.append(path_out)
        command.append('-2')
        command.append('-R')
        command.append(FILTER)
        sp = Popen(command, stdout=FNULL, stderr=FNULL, shell=True)
        streamdata = sp.communicate()
        if sp.returncode != 0:
            labl6.config(text=f"Return code is {sp.returncode}")
            break
    labl6.config(text='Filter completed, Merging all the filtered Wireshark files')
    PATH_MERGECAP = r"C:\Program Files (x86)\Wireshark\mergecap.exe"
    path_out = 'Wireshark_Merged.pcapng'
    command = []
    command.append(PATH_MERGECAP)
    command.append('-w')
    command.append(path_out)
    command.append('Filtered/*.pcap*')
    sp = Popen(command, shell=True)
    sp.wait()
    labl6.config(text='Merged.pcapng created at current working directory')
    try:
        rmtree('Filtered')
        rmtree('Extracted')
    except:
        pass
    ent2.delete(0, END)
    ent3.delete(0, END)


radio_var = StringVar()
radio_var.set(None)

labl1 = Label(window, text='Welcome to Wireshark filter and merge tool', font=(None, 12, 'bold'), bg='grey').place(x=90,
                                                                                                                   y=1)

radiobtn1 = Radiobutton(window, text='Select here if it is unzipped folder', font=(None, 9, 'bold'), bg='grey',
                        variable=radio_var, value='unzip')
radiobtn1.place(x=150, y=30)
radiobtn2 = Radiobutton(window, text='Select here if it is zipped folder', font=(None, 9, 'bold'), bg='grey',
                        variable=radio_var, value='zip')
radiobtn2.place(x=150, y=60)

labl2 = Label(window, text='Select zip/unzip folder', font=(None, 9, 'bold'), bg='grey').place(x=6, y=90)
ent2 = Entry(window, bd=4, width=47, bg='lavender')
ent2.place(x=150, y=90)
btn2 = Button(window, text='...', command=threading_btn2, bg='green')
btn2.place(x=460, y=90)

labl3 = Label(window, text='Type filter', font=(None, 9, 'bold'), bg='grey').place(x=6, y=120)
ent3 = Entry(window, bd=4, width=47, bg='lavender')
ent3.place(x=150, y=120)
btn3 = Button(window, text='Submit', command=threading_btn3, bg='green')
btn3.place(x=250, y=160)

labl4 = Label(window, text='Note : Please make sure wireshark is installed in ..\Program Files (x86)\ ',
              font=(None, 9, 'bold'), bg='grey')
labl4.place(x=6, y=200)
labl5 = Label(window, text='After submission wait for success message', font=(None, 9, 'bold'), bg='grey')
labl5.place(x=6, y=220)
labl6 = Label(window, font=(None, 9, 'bold'), bg='grey')
labl6.place(x=6, y=240)

window.mainloop()
