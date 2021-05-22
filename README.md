# PortScan_Asychro-multithreading-GUI
异步多线程端口扫描器  带有GUI  文件保存功能  邮件通知   asycho multithreading port scan SYN sending, with GUI , file saving and mail sending function.


# Usage

1. pip install the needing package
2. change the mail account and password setting
3. change the ip and ip interface.   with ```ipconfig \all``` in cmd console to check your ip and interface.
4. to run it, use ```python portgui1.py```

# function explanation

support ip range and port range. The threading number is the sending threading number. 

Mail function will not work if the sending threading number is over 5.

You can stop the scanning with stop button, but please wait for several seconds to truely let it stop down. And then you can use the save buttton to save the unfinished task.
Also if you already had saved some task file before, you can use the load button to load that file and resume the scan task.

When task finshed, the result will be saved to a file in the directory, and aslo will automaticly send a file to your mailbox.

