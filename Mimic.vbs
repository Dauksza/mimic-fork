Option Explicit

Dim shell, fso, root, pythonw, scriptPath, message
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

root = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = fso.BuildPath(root, ".venv\Scripts\pythonw.exe")
scriptPath = fso.BuildPath(root, "Mimic.pyw")

If Not fso.FileExists(pythonw) Then
    message = "Mimic has not been installed in this folder yet." & vbCrLf & vbCrLf & _
              "Double-click Install-Mimic.bat, let setup finish, then launch Mimic.vbs again."
    MsgBox message, vbExclamation, "Mimic setup required"
    WScript.Quit 1
End If

If Not fso.FileExists(scriptPath) Then
    MsgBox "Mimic.pyw was not found in:" & vbCrLf & root, vbCritical, "Mimic launcher error"
    WScript.Quit 1
End If

shell.CurrentDirectory = root

' Install or refresh a convenient desktop shortcut for subsequent launches.
On Error Resume Next
Dim shortcutPath, shortcut
shortcutPath = fso.BuildPath(shell.SpecialFolders("Desktop"), "Mimic.lnk")
Set shortcut = shell.CreateShortcut(shortcutPath)
shortcut.TargetPath = WScript.ScriptFullName
shortcut.WorkingDirectory = root
shortcut.Description = "Mimic - Local App Analysis and Reconstruction"
shortcut.Save
On Error GoTo 0

shell.Run """" & pythonw & """ """ & scriptPath & """", 0, False
