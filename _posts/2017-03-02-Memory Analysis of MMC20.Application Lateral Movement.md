---
layout: post
title: "Memory Analysis of DCOM Lateral Movement Using MMC20.Application"       # Title of the post
description: Memory Analyzing MMC20.Application Lateral Movement         # Description of the post, used for Facebook Opengraph & Twitter
headline: Memory Analysis of MMC20.Application Lateral Movement     # Will appear in bold letters on top of the post
category: [incident response]
tags: [incident response, lateral movement]
image:
imagefeature: infinity003.jpg
comments: true
mathjax:
---

Continuing my analysis of lateral movement using MMC20.Application (see my [previous post](http://thenegative.zone/incident%20response/2017/02/04/MMC20.Application-Lateral-Movement-Analysis.html 'Analyzing MMC20.Application Lateral Movement')), the next logical course was to look in memory and see what I can find.  This post will cover my memory findings.  I will note that I performed this MMC20.Application abuse and then waited a little while before actually capturing memory.

Process Listing Reviews
----------------------------------------
Like most people one of the first things you likely gravitate to looking at first is the process listings, so I run through the battery of process listings.
<br><br>
First being pslist (I've snipped most of the listing, honing in only on the ones that stood out to me). <br><br>
PSList
```shell
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa8032f54600 svchost.exe             584    464      9      359      0      0 2017-02-22 17:48:24 UTC+0000
0xfffffa80332b0350 WmiPrvSE.exe           1984    584      0 --------      0      0 2017-02-22 17:48:27 UTC+0000   2017-02-22 18:05:00 UTC+0000
0xfffffa80332ae060 WmiPrvSE.exe           1480    584     10      202      0      0 2017-02-22 17:48:28 UTC+0000
0xfffffa80331d5280 dllhost.exe            3648    584      0 --------      1      0 2017-02-22 17:57:18 UTC+0000   2017-02-22 19:39:35 UTC+0000
0xfffffa8033a20800 mmc.exe                3216    584      0 --------      0      0 2017-02-22 19:12:27 UTC+0000   2017-02-22 19:31:51 UTC+0000
0xfffffa80334fd060 calc.exe               2040   3216      3       70      0      0 2017-02-22 19:13:10 UTC+0000
```
PSTree
```shell
.. 0xfffffa8032f54600:svchost.exe                     584    464      9    359 2017-02-22 17:48:24 UTC+0000
... 0xfffffa80332b0350:WmiPrvSE.exe                  1984    584      0 ------ 2017-02-22 17:48:27 UTC+0000
... 0xfffffa80332ae060:WmiPrvSE.exe                  1480    584     10    202 2017-02-22 17:48:28 UTC+0000
... 0xfffffa80331d5280:dllhost.exe                   3648    584      0 ------ 2017-02-22 17:57:18 UTC+0000
... 0xfffffa8033a20800:mmc.exe                       3216    584      0 ------ 2017-02-22 19:12:27 UTC+0000
.... 0xfffffa80334fd060:calc.exe                     2040   3216      3     70 2017-02-22 19:13:10 UTC+0000
```
PSScan
```shell
Offset(P)          Name                PID   PPID PDB                Time created                   Time exited
------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
0x00000000fd19e880 mmc.exe            3216    584 0x000000000db96000 2017-02-22 19:12:27 UTC+0000   2017-02-22 19:31:51 UTC+0000
0x00000000fd87b0e0 calc.exe           2040   3216 0x00000000274a7000 2017-02-22 19:13:10 UTC+0000
0x00000000fda2c0e0 WmiPrvSE.exe       1480    584 0x0000000085b3f000 2017-02-22 17:48:28 UTC+0000
0x00000000fda2e3d0 WmiPrvSE.exe       1984    584 0x000000008e7a7000 2017-02-22 17:48:27 UTC+0000   2017-02-22 18:05:00 UTC+0000
0x00000000fdd53300 dllhost.exe        3648    584 0x00000000b5b54000 2017-02-22 17:57:18 UTC+0000   2017-02-22 19:39:35 UTC+0000
0x00000000fded2680 svchost.exe         584    464 0x0000000099da2000 2017-02-22 17:48:24 UTC+0000
0x00000000ff59aa50 WmiPrvSE.exe       1800    584 0x00000001262f4000 2017-02-22 19:25:39 UTC+0000   2017-02-22 19:31:52 UTC+0000
```
PSXView
```shell
Offset(P)          Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
------------------ -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x00000000fded2680 svchost.exe             584 True   True   True     True   True  True    False
0x00000000fda2c0e0 WmiPrvSE.exe           1480 True   True   True     True   True  True    False
0x00000000fd87b0e0 calc.exe               2040 True   True   True     True   True  True    True
0x00000000fda2e3d0 WmiPrvSE.exe           1984 True   True   False    True   False True    False    2017-02-22 18:05:00 UTC+0000
0x00000000fdd53300 dllhost.exe            3648 True   True   False    True   False True    False    2017-02-22 19:39:35 UTC+0000
0x00000000fd19e880 mmc.exe                3216 True   True   False    True   False True    False    2017-02-22 19:31:51 UTC+0000
0x00000000ff59aa50 WmiPrvSE.exe           1800 False  True   False    False  False False   False    2017-02-22 19:31:52 UTC+0000
```
One of the first things I noticed was all the processes with svchost as their ParentProcess.  You might also notice that psscan's pool tag scanner it shows process 1800 where pslist does not.<br>

You'll likely also notice that mmc has a process running under it.  This too seems odd to me, combined with the fact that svchost has a handful on non-service like processes running under it (excluding the WmiPrvSE and dllhost which are inherent to this type of activity).<br>

The next logical step might be to look at the command-line arguments used.  For this we turn to cmdline, which shows us that svchost service launched a DCOM response to an object activation request.
```shell
************************************************************************
svchost.exe pid:    584
Command line : C:\Windows\system32\svchost.exe -k DcomLaunch
************************************************************************
WmiPrvSE.exe pid:   1480
Command line : C:\Windows\system32\wbem\wmiprvse.exe
************************************************************************
WmiPrvSE.exe pid:   1984
************************************************************************
dllhost.exe pid:   3648
************************************************************************
mmc.exe pid:   3216
************************************************************************
calc.exe pid:   2040
Command line : "C:\Windows\System32\calc.exe"
************************************************************************
```

The next step might be to look at the loaded dlls but from the processes above but in this case we know it is loading legitimate processes and for the sake of brevity I will skip some steps like looking for injection, dll, drivers, registry reviews and so forth.

SID Reviews
----------------------------------------
From this point I am still trying to gather more information on the processes I am potentially concerned with, so I ran GetSIDs.  You'll likely also notice that a few processes appear to belong to the user 'administrator'.  You'll also notice that many of these processes aren't running interactively or via physical console but via NTLM Authentication.  This gives us more of an understanding who and how these suspicious processes were launched.
```shell
svchost.exe (584): S-1-5-18 (Local System)
svchost.exe (584): S-1-16-16384 (System Mandatory Level)
svchost.exe (584): S-1-1-0 (Everyone)
svchost.exe (584): S-1-5-32-545 (Users)
svchost.exe (584): S-1-5-6 (Service)
svchost.exe (584): S-1-5-11 (Authenticated Users)
svchost.exe (584): S-1-5-15 (This Organization)
svchost.exe (584): S-1-5-80-1601830629-990752416-3372939810-977361409-3075122917 (DcomLaunch)
svchost.exe (584): S-1-5-80-1981970923-922788642-3535304421-2999920573-318732269 (PlugPlay)
svchost.exe (584): S-1-5-80-2343416411-2961288913-598565901-392633850-2111459193 (Power)
svchost.exe (584): S-1-5-5-0-51301 (Logon Session)
svchost.exe (584): S-1-2-0 (Local (Users with the ability to log in locally))
svchost.exe (584): S-1-5-32-544 (Administrators)
WmiPrvSE.exe (1480): S-1-5-20 (NT Authority)
WmiPrvSE.exe (1480): S-1-16-16384 (System Mandatory Level)
WmiPrvSE.exe (1480): S-1-1-0 (Everyone)
WmiPrvSE.exe (1480): S-1-5-32-545 (Users)
WmiPrvSE.exe (1480): S-1-5-6 (Service)
WmiPrvSE.exe (1480): S-1-2-1 (Console Logon (Users who are logged onto the physical console))
WmiPrvSE.exe (1480): S-1-5-11 (Authenticated Users)
WmiPrvSE.exe (1480): S-1-5-15 (This Organization)
WmiPrvSE.exe (1480): S-1-5-86-615999462-62705297-2911207457-59056572-3668589837 (WMI (Network Service))
WmiPrvSE.exe (1480): S-1-5-5-0-137850 (Logon Session)
WmiPrvSE.exe (1984): S-1-5-18 (Local System)
WmiPrvSE.exe (1984): S-1-16-16384 (System Mandatory Level)
WmiPrvSE.exe (1984): S-1-1-0 (Everyone)
WmiPrvSE.exe (1984): S-1-5-32-545 (Users)
WmiPrvSE.exe (1984): S-1-5-6 (Service)
WmiPrvSE.exe (1984): S-1-2-1 (Console Logon (Users who are logged onto the physical console))
WmiPrvSE.exe (1984): S-1-5-11 (Authenticated Users)
WmiPrvSE.exe (1984): S-1-5-15 (This Organization)
WmiPrvSE.exe (1984): S-1-5-80-2962817144-200689703-2266453665-3849882635-1986547430 (BDESVC)
WmiPrvSE.exe (1984): S-1-5-80-864916184-135290571-3087830041-1716922880-4237303741 (BITS)
WmiPrvSE.exe (1984): S-1-5-80-3256172449-2363790065-3617575471-4144056108-756904704 (CertPropSvc)
WmiPrvSE.exe (1984): S-1-5-80-3578261754-285310837-913589462-2834155770-667502746 (EapHost)
WmiPrvSE.exe (1984): S-1-5-80-1373701630-3910968185-3388013410-2492353-937432973 (hkmsvc)
WmiPrvSE.exe (1984): S-1-5-80-698886940-375981264-2691324669-2937073286-3841916615 (IKEEXT)
WmiPrvSE.exe (1984): S-1-5-80-62724632-2456781206-3863850748-1496050881-1042387526 (iphlpsvc)
WmiPrvSE.exe (1984): S-1-5-80-879696042-2351668846-370232824-2524288904-4023536711 (LanmanServer)
WmiPrvSE.exe (1984): S-1-5-80-2799810402-4136494038-1094338311-2889966999-3154753985 (MMCSS)
WmiPrvSE.exe (1984): S-1-5-80-917953661-2020045820-2727011118-2260243830-4032185929 (MSiSCSI)
WmiPrvSE.exe (1984): S-1-5-80-1802467488-1541022566-2033325545-854566965-652742428 (RasAuto)
WmiPrvSE.exe (1984): S-1-5-80-4176366874-305252471-2256717057-2714189771-3552532790 (RasMan)
WmiPrvSE.exe (1984): S-1-5-80-1954729425-4294152082-187165618-318331177-3831297489 (RemoteAccess)
WmiPrvSE.exe (1984): S-1-5-80-4125092361-1567024937-842823819-2091237918-836075745 (Schedule)
WmiPrvSE.exe (1984): S-1-5-80-1691538513-4084330536-1620899472-1113280783-3554754292 (SCPolicySvc)
WmiPrvSE.exe (1984): S-1-5-80-4259241309-1822918763-1176128033-1339750638-3428293995 (SENS)
WmiPrvSE.exe (1984): S-1-5-80-4022436659-1090538466-1613889075-870485073-3428993833 (SessionEnv)
WmiPrvSE.exe (1984): S-1-5-80-2009329905-444645132-2728249442-922493431-93864177 (SharedAccess)
WmiPrvSE.exe (1984): S-1-5-80-1690854464-3758363787-3981977099-3843555589-1401248062 (ShellHWDetection)
WmiPrvSE.exe (1984): S-1-5-80-3594706986-2537596223-181334840-1741483385-1351671666 (wercplsupport)
WmiPrvSE.exe (1984): S-1-5-80-3750560858-172214265-3889451188-1914796615-4100997547 (Winmgmt)
WmiPrvSE.exe (1984): S-1-5-80-1014140700-3308905587-3330345912-272242898-93311788 (wuauserv)
WmiPrvSE.exe (1984): S-1-5-5-0-77489 (Logon Session)
WmiPrvSE.exe (1984): S-1-2-0 (Local (Users with the ability to log in locally))
WmiPrvSE.exe (1984): S-1-5-32-544 (Administrators)
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-500 (administrator)
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-513 (Domain Users)
dllhost.exe (3648): S-1-1-0 (Everyone)
dllhost.exe (3648): S-1-5-32-545 (Users)
dllhost.exe (3648): S-1-5-32-544 (Administrators)
dllhost.exe (3648): S-1-5-4 (Interactive)
dllhost.exe (3648): S-1-2-1 (Console Logon (Users who are logged onto the physical console))
dllhost.exe (3648): S-1-5-11 (Authenticated Users)
dllhost.exe (3648): S-1-5-15 (This Organization)
dllhost.exe (3648): S-1-5-5-0-758235 (Logon Session)
dllhost.exe (3648): S-1-2-0 (Local (Users with the ability to log in locally))
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-520 (Group Policy Creator Owners)
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-512 (Domain Admins)
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-518 (Schema Admins)
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-519 (Enterprise Admins)
dllhost.exe (3648): S-1-18-1 (Authentication Authority Asserted Identity)
dllhost.exe (3648): S-1-5-21-1923566281-4131265335-1104240599-572
dllhost.exe (3648): S-1-16-12288 (High Mandatory Level)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-500 (administrator)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-513 (Domain Users)
mmc.exe (3216): S-1-1-0 (Everyone)
mmc.exe (3216): S-1-5-32-545 (Users)
mmc.exe (3216): S-1-5-32-544 (Administrators)
mmc.exe (3216): S-1-5-2 (Network)
mmc.exe (3216): S-1-5-11 (Authenticated Users)
mmc.exe (3216): S-1-5-15 (This Organization)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-520 (Group Policy Creator Owners)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-512 (Domain Admins)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-518 (Schema Admins)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-519 (Enterprise Admins)
mmc.exe (3216): S-1-18-1 (Authentication Authority Asserted Identity)
mmc.exe (3216): S-1-5-21-1923566281-4131265335-1104240599-572
mmc.exe (3216): S-1-5-64-10 (NTLM Authentication)
mmc.exe (3216): S-1-16-12288 (High Mandatory Level)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-500 (administrator)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-513 (Domain Users)
calc.exe (2040): S-1-1-0 (Everyone)
calc.exe (2040): S-1-5-32-545 (Users)
calc.exe (2040): S-1-5-32-544 (Administrators)
calc.exe (2040): S-1-5-2 (Network)
calc.exe (2040): S-1-5-11 (Authenticated Users)
calc.exe (2040): S-1-5-15 (This Organization)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-520 (Group Policy Creator Owners)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-512 (Domain Admins)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-518 (Schema Admins)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-519 (Enterprise Admins)
calc.exe (2040): S-1-18-1 (Authentication Authority Asserted Identity)
calc.exe (2040): S-1-5-21-1923566281-4131265335-1104240599-572
calc.exe (2040): S-1-5-64-10 (NTLM Authentication)
calc.exe (2040): S-1-16-12288 (High Mandatory Level)
```

Network Review
----------------------------------------
As mentioned above, I waited a little while (40 odd minutes) before capturing memory since most situations don't automatically have evil executed and then automatically have memory acquired.<br>
Next I looked at the network connections and listening processes still resident in memory.  Running netscan we see the following:
```shell
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x13d760a20        TCPv4    0.0.0.0:49230                  0.0.0.0:0            LISTENING        3216     mmc.exe
0x13d760a20        TCPv6    :::49230                       :::0                 LISTENING        3216     mmc.exe
```

Services Review
----------------------------------------
In this case, I don't have a great need to look at the services but regardless SvcScan shows the following regarding svcscan's DcomLaunch:
```shell
Shows svcscan with dcom started
Offset: 0x98f220
Order: 234
Start: SERVICE_AUTO_START
Process ID: 584
Service Name: Power
Display Name: Power
Service Type: SERVICE_WIN32_SHARE_PROCESS
Service State: SERVICE_RUNNING
Binary Path: C:\Windows\system32\svchost.exe -k DcomLaunch
```

Sessions Review
----------------------------------------
Now that we know a little more about the processes (who and how) we can dig a little deeper to help solidify our findings.  Looking at the logon session space is a great place to understand a little more about what you are dealing with.  The session information of note is listed below but one thing that stands out to me is our processes of interest are all running under Session ID 0 (understandable in this case) and the kernel driver loaded is TSDDD.dll, not cdd.dll, rdpdd.dll or something similar.  [TSDDD.dll](https://msdn.microsoft.com/en-us/library/aa940056(v=winembedded.5).aspx 'MSDN - TSDDD.dll info') is the terminal services VGA display driver and unlike the Canonical Display Driver (cdd.dll) it is meant for headless rendering.  It is also used when the video driver is undetermined for console disconnects and reconnects, so we can infer that mmc and calc was definitely launched/leveraged in some non-GUI manner.
```shell
**************************************************
Session(V): fffff88004686000 ID: 0 Processes: 51
PagedPoolStart: fffff900c0000000 PagedPoolEnd fffff920bfffffff
[snip]
 Process: 584 svchost.exe 2017-02-22 17:48:24 UTC+0000
 Process: 1984 WmiPrvSE.exe 2017-02-22 17:48:27 UTC+0000
 Process: 2004 TPAutoConnSvc. 2017-02-22 17:48:27 UTC+0000
 Process: 1480 WmiPrvSE.exe 2017-02-22 17:48:28 UTC+0000
 Process: 2656 WmiApSrv.exe 2017-02-22 17:50:51 UTC+0000
 Process: 3216 mmc.exe 2017-02-22 19:12:27 UTC+0000
 Process: 2040 calc.exe 2017-02-22 19:13:10 UTC+0000
 Image: 0xfffffa80320427c0, Address fffff96000050000, Name: win32k.sys
 Image: 0xfffffa8030f51d00, Address fffff96000450000, Name: TSDDD.dll
 ```

Atom Table Review
----------------------------------------
So now we know a decent bit about this pure evil activity of calc.exe but we still don't know explicitly how this execution happened.  There are a handful of ways you might be able to pull more on that thread, such as reviewing the strings of the processes noted or in free memory or perhaps in the pagefile but sometimes you can get some quick wins by reviewing the atom table, which usually contain some juicy strings being used by functions and they usually remain resident in the table even after whatever API function pushed them onto the table.  In this case I noted the following atoms:
 *The cmds atomscan and atoms different parsing techniques gave me the same finding in respect to strings shown below, so I won't bother to show both outputs.*
 ```shell
 Offset(V)  Session     WindowStation                  Atom  RefCount    HIndex     Pinned   Name
------------------ ---------- ------------------ ------------------ ---------- ---------- ---------- ----
[snip]
0x97729470 ---------- ------------------    0xc09d     3         157         0      CCF_DISPLAY_NAME
0x97729470 ---------- ------------------    0xc0fc     1         252       0      CCF_MMC_DYNAMIC_EXTENSIONS
0x1334ce4f0 ---------- ------------------    0xc09b     4         155         0      CCF_NODETYPE
0x1334ce4f0 ---------- ------------------    0xc0fd     1         253         0      CCF_COLUMN_SET_ID
0x97729470 ---------- ------------------    0xc09e     3         158         0      CCF_SNAPIN_CLASSID
0x97729470 ---------- ------------------    0xc09c     3         156         0      CCF_SZNODETYPE
0x1334ce4f0 ---------- ------------------    0xc0a2     2         162         0      CCF_DTC_RESOURCE
0x1334ce4f0 ---------- ------------------    0xc0a1     2         161         0      CCF_DTC_HOSTNAME
0x1334ce4f0 ---------- ------------------    0xc0fb     1         251         0      CCF_SNAPIN_PRELOADS
0x1334ce4f0 ---------- ------------------    0xc09f     2         159         0      CCF_COM_WORKSTATION
[snip]
```
So why do I highlight those?  Because DCOM objects use the [IDataObject Interface](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688421(v=vs.85).aspx 'Windows Dev Center - IDataObject') and the consumers of the data being piped via a DCOM object calls the [GetDataHere](https://msdn.microsoft.com/en-us/library/windows/desktop/ms687266(v=vs.85).aspx 'Windows Dev Center - GetDataHere') method and low and behold the GetDataHere method requires the object to support the following clipboard formats (see the following [Dev Center reference](https://msdn.microsoft.com/en-us/library/aa815059(v=vs.85).aspx 'MMC20 Clipboard Formats')) which are pushed onto the Atom Table:
* CCF_DISPLAY_NAME
* CCF_NODETYPE
* CCF_SNAPIN_CLASSID
* CCF_SZNODETYPE

Strings Review
----------------------------------------
Okay, so now we know a little more regarding the DCOM use but we haven't nailed down exactly how it was processed.  A review of strings may help here.  Reviewing the strings output (skipping a ton of the other process strings and free memory strings), we note the following references that clearly tell the tale a little more (note the MMC20.Application specifically).
```shell
[snip]
421901668 [FREE MEMORY:-1] [01;31MMCCtrl class
421902036 [FREE MEMORY:-1] @%SystemRoot%\system32\[01;31mmcbase.dll,-130
421902508 [FREE MEMORY:-1] @%SystemRoot%\system32\[01;31mmcbase.dll,-13351
421902788 [FREE MEMORY:-1] %SystemRoot%\system32\[01;31mmc.exe /a "%1" %*
421903100 [FREE MEMORY:-1] %SystemRoot%\system32\[01;31mmc.exe "%1" %*
421903468 [FREE MEMORY:-1] %SystemRoot%\system32\[01;31mmc.exe "%1" %*
421904036 [FREE MEMORY:-1] [01;31MMC Application Class
421904236 [FREE MEMORY:-1] [01;31MMC Application Class
1852759296 [FREE MEMORY:-1] [01;31MMC20.Application
1908179520 [kernel:f980367a0240] C:\Windows\system32\[01;31mmc.exe
1908180560 [kernel:f980367a0650] C:\Windows\system32\[01;31mmc.exe
1910865034 [896:8ad71c8a] [01;31MMCFxCommon
1910865138 [896:8ad71cf2] [01;31MMCFXC~1
1912979676 [388:006c30dc] %SystemRoot%\system32\[01;31mmc.exe
1912979780 [388:006c3144] %SystemRoot%\system32\[01;31mmc.exe
1912979972 [388:006c3204] [01;31MMC20.Application.1
1912980164 [388:006c32c4] [01;31MMC20.Application
1912980288 [388:006c3340] [01;31MMC20.Application.1
1912980340 [388:006c3374] [01;31MMC Application Class
1912980696 [388:006c34d8] [01;31MMC20.Application
1912980748 [388:006c350c] [01;31MMC Application Class
1912981164 [388:006c36ac] [01;31MMC20.Application.1
1912981556 [388:006c3834] %SystemRoot%\system32\[01;31mmcshext.dll
1912982044 [388:006c3a1c] %SystemRoot%\system32\[01;31mmcshext.dll
1912982348 [388:006c3b4c] [01;31Mmcshext.ExtractIcon.1
1912982548 [388:006c3c14] [01;31Mmcshext.ExtractIcon
1912982672 [388:006c3c90] [01;31Mmcshext.ExtractIcon.1
1912983064 [388:006c3e18] [01;31Mmcshext.ExtractIcon
1912983524 [388:006c3fe4] [01;31Mmcshext.ExtractIcon.1
1915928306 [FREE MEMORY:-1] \windows\system32\[01;31mmc.exe
1915928546 [FREE MEMORY:-1] \windows\system32\[01;31mmc.exe
[snip]
```
<br>
I will mention that poking around using Yarascan and volshell poking revealed some IP indicators but they didn't necessarily allow me to tie back to the activity noted (mmc.exe and calc), so I opted to leave them out. <br>

So hammering through some of the still resident artifacts present in memory still provided us enough clues as to what likely transpired but it definitely didn't stick out as a sore thumb.  Searching for activity in a manner like this was somewhat similar tactically to malware analysis but definitely veered course from my normal reviews.  Nonetheless, it was a fun and worthwhile endeavor.
