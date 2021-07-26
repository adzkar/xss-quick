import PySimpleGUI as sg

sg.theme('DarkAmber')

layout = [  [sg.Text("XSS Quick")], 
            [sg.Text('Enter URL Target')],
            [sg.InputText()],
            [sg.Text('Enter Cookies')],
            [sg.InputText()],
            [sg.Text('Upload Payload')],
            [sg.InputText(), sg.FileBrowse()],
            [sg.Button("Scan")]
        ]

# Create the window
window = sg.Window("XSS Quick", layout)

# Create an event loop
while True:
    event, values = window.read()
    # End program if user closes window or
    # presses the OK button
    print(event, ' event')
    print(values, ' values')
    sg.Popup(event, values[0])
    if event == "OK" or event == sg.WIN_CLOSED:
        break

window.close()