import sqlite3, hashlib

from tkinter import *
from tkinter import simpledialog  # for pop ups
from functools import partial
from tkinter import ttk

from generator import passGenerator


# initiate and connect  with database
with sqlite3.connect("locker.db") as db:
    cursor = db.cursor()

# create database table
cursor.execute("""
CREATE TABLE IF NOT EXISTS credentials(
id INTEGER PRIMARY KEY,
username TEXT NOT NULL,
password TEXT NOT NULL
);

""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS locker(
id INTEGER PRIMARY KEY,
app TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL
);

""")

# crete pop ups
def popUps(text):
    answer = simpledialog.askstring("input string", text)

    return answer

window = Tk()

"""
creating a window through tinker 

window = Tk()
as a GUI

"""

window.title("Password Locker")


# hash password
def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash


# the sign up screen
def signUp():
    window.geometry("500x200")
    # username
    lb = Label(window, text="Username")
    lb.config(anchor=CENTER)
    lb.pack()

    # text input
    txt = Entry(window, width=15)
    txt.pack()

    # password
    lbp = Label(window, text="Password")
    lbp.config(anchor=CENTER)
    lbp.pack()

    # text input
    txt1 = Entry(window, width=15, show="*")
    txt1.pack()

    # re write password
    lbp1 = Label(window, text="Rewrite password")
    lbp1.config(anchor=CENTER)
    lbp1.pack()

    # text input
    txt2 = Entry(window, width=15, show="*")
    txt2.pack()

    error = Label(window)
    error.pack(pady=5)

    def saveCredentials():

        if txt.get() != "" and txt1.get() == txt2.get():
            username = txt.get()
            password = hashPassword(txt1.get().encode('utf-8'))

            insert_credentials = """INSERT INTO credentials(username , password)
            VALUES(?,?)"""
            cursor.execute(insert_credentials, [(username), (password)])
            db.commit()

            passwordLocker()

        else:
            txt.delete(0, 'end')
            txt1.delete(0, 'end')
            txt2.delete(0, 'end')

            error.config(text="wrong credentials")

    btn = Button(window, text="save", command=saveCredentials)
    btn.pack(pady=10)


# creating a user login page
def userloginscreen():
    window.geometry("500x175")

    # Title
    username = Label(window, text="Username")
    username.config(anchor=CENTER)
    username.pack()

    # text input
    txt = Entry(window, width=15)
    txt.pack()

    # password
    password = Label(window, text="Password")
    password.config(anchor=CENTER)
    password.pack()

    txt1 = Entry(window, width=15, show="*")
    txt1.pack()
    txt1.focus()

    error = Label(window)
    error.pack(pady=5)

    def getCredentials():
        username = txt.get()
        password = hashPassword(txt1.get().encode('utf-8'))
        cursor.execute("SELECT * FROM credentials WHERE id = 1 AND username =? AND password =? ", [username, password])
        return cursor.fetchall()

    # method for initializing login btn from command
    def checkCredentials():

        match = getCredentials()

        print(match)

        if match:
            passwordLocker()

        else:
            txt.delete(0, 'end')
            txt1.delete(0, 'end')
            error.config(text="wrong credentials")

    # make it be last after text input
    btn = Button(window, text="Login", command=checkCredentials)
    btn.pack(pady=10)


# when login directed to the Password locker
def passwordLocker():
    # prevent text from stacking up on each other
    for widget in window.winfo_children():
        widget.destroy()

        #ading credentials to database
        def addEntry():
            text = "app"
            text1 = "username"
            text2= "password"

            # create pop ups
            app= popUps(text)
            username= popUps(text1)
            password = popUps(text2)

            # insert the fields
            insert_fields = """INSERT INTO locker(app,username,password)
            VALUES(?,?,?) 
            """

            cursor.execute(insert_fields, (app, username, password))
            db.commit()

            passwordLocker()

        # deleting credential from database
        def removeEntry(input):
            cursor.execute("DELETE FROM locker WHERE id = ?",(input,))
            db.commit()

            passwordLocker()

        # copy account details

        #copy password
        def copyPass(input):
            window.clipboard_clear()
            window.clipboard_append(input)



    # creating the pass word locker
    window.geometry("700x400")




    vault = Label(window, text="Password Locker")
    vault.grid(column=1)

    btn = Button(window, text="+", command=addEntry)
    btn.grid( column=1,pady=10)

    btn2 = Button(window, text="Generate Password", command=passGenerator)
    btn2.grid(column=5, pady=10)



    # create entries
    lbl = Label(window, text="app")
    lbl.grid(row=2, column=0, padx=100)

    lbl = Label(window, text="username")
    lbl.grid(row=2, column=1, padx=100)

    lbl = Label(window, text="password")
    lbl.grid(row=2, column=2, padx=100)

    cursor.execute("SELECT * FROM locker")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM locker ")
            array = cursor.fetchall()



            lbl1 = Label(window, text=(array[i][1]), font=('Helvetica', 14))
            lbl1.grid(column=0, row=i+3)

            lbl2 = Label(window, text=(array[i][2]), font=('Helvetica', 14))
            lbl2.grid(column=1, row=i + 3)

            lbl3 = Label(window, text=(array[i][3]), font=('Helvetica', 14))
            lbl3.grid(column=2, row=i + 3)

            btn3 = Button(window, text="Copy Pass", command=partial(copyPass, array[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)

            btn = Button(window, text="Delete", command= partial(removeEntry, array[i][0]))
            btn.grid(column=5, row=i+3, pady=10)

            i=i+1

            cursor.execute("SELECT * FROM locker")
            if(len(cursor.fetchall()) <= i):
                break

# call method
cursor.execute("SELECT * FROM credentials")

if cursor.fetchall():
    userloginscreen()
else:
    signUp()
window.mainloop()
