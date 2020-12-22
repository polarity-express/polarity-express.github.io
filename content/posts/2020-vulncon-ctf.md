+++
title = "2020 Vulncon CTF Write Up"
date = "2020-12-21T01:48:58-05:00"
author = "polarity_express"
authorTwitter = "" #do not include @
cover = ""
tags = ["writeup"]
keywords = ["", ""]
description = "Write Up For the 2020 Vulncon CTF"
showFullContent = false
+++

# Challenge Categories
* [Forensic Challenges](/posts/2020-vulncon-ctf/#forensic-challenges)

    * [Punishment](/posts/2020-vulncon-ctf/#challenge-punishment)
    * [Analysis](/posts/2020-vulncon-ctf/#challenge-analysis)
    * [Attack](/posts/2020-vulncon-ctf/#challenge-attack)
    * [Compromise](/posts/2020-vulncon-ctf/#challenge-compromise)

* [Memory Forensic Challenges](/posts/2020-vulncon-ctf/#memory-forensic-challenges)

    * [Game Over](/posts/2020-vulncon-ctf/#challenge-game-over)
    * [Phishy Email](/posts/2020-vulncon-ctf/#challenge-phishy-email)

* [OSINT Challenges](/posts/2020-vulncon-ctf/#osint-challenges)
    * [Find The Coin](/posts/2020-vulncon-ctf/#challenge-find-the-coin)
    * [trouver](/posts/2020-vulncon-ctf/#challenge-trouver)
    * [Flying Bear](/posts/2020-vulncon-ctf/#challenge-flying-bear)
    * [The Watcher](/posts/2020-vulncon-ctf/#challenge-the-watcher)



## Forensic Challenges
* [Punishment](/posts/2020-vulncon-ctf/#challenge-punishment)
* [Analysis](/posts/2020-vulncon-ctf/#challenge-analysis)
* [Attack](/posts/2020-vulncon-ctf/#challenge-attack)
* [Compromise](/posts/2020-vulncon-ctf/#challenge-compromise)

### Challenge: Punishment

Mr.BEAN was working on his school assignment, But unfortunately, his Lil Sister deleted that assignment file. As Mr.BEAN failed to submit the assignment on time, He will be punished heavily. Anyway, He has an exclusive excuse, but he needs to prove his innocence anyhow! Can you extract the date/time his assignment was deleted?

#### Steps to Solve

For this challenge I was given a file called **$I4A67FE.docx**. This is a special file name that implies it is most likely from a [Windows Recycling Bin](https://www.blackbagtech.com/blog/examining-the-windows-10-recycle-bin/). Since this file starts with an *$I* it will contain meta data about the deleted file. I ran xxd on the file to see the hex representation of the data in the file.

![](/imgs/2020_vulncon_ctf/punishment1.png)

The first 8 bytes are the header, since this file starts with **0x02** it was deleted from a system running Windows 10. The next eight bytes are the file size in bytes stored in little endian. The next 8 bytes are used to store the date and time the file was deleted in little endian. The time stamp is recorded as the number of 100 nano second intervals since Jan 1, 1601 UTC. Python can be used to convert this time stamp into a human readable format.

![](/imgs/2020_vulncon_ctf/punishment2.png)

This shows that the file was deleted on November 4, 2020 at 20:46:55 UTC.

### Challenge: Analysis

We have suspected Mr.Wolf in illegal dealings and for investigation we have grabbed browser files from his system investigate further and find the information.

#### Steps to Solve

For this challenge I was given the contents of Mr.Wolf's [**Mozilla**](https://www.foxtonforensics.com/browser-history-examiner/firefox-history-location) folder where FireFox stores it's data.

![](/imgs/2020_vulncon_ctf/analysis1.png)

The first place I checked was a file called **places.sqlite**, this is a sqlite database that is used by FireFox to store browser history. I used [SQLite Database Browser](https://sqlitebrowser.org/) to view the database. The **moz_places** table contains all of the URLs visited by the browser. I saw a link to the MEGA file hosting service so I searched the table for other URLs on that site.

![](/imgs/2020_vulncon_ctf/analysis2.png)

I then navigated to each of them until I got to this file on MEGA.

![](/imgs/2020_vulncon_ctf/analysis3.png)

After this, I noticed that Mr.Wolf most likely downloaded VeraCrypt.

![](/imgs/2020_vulncon_ctf/analysis4.png)

This lead me to believe that the **important_data.file** file was an encrypted VeraCrypt volume, and I would need to keep searching for a password. One URL had the page title "i don't use pastebin for my secrets - ed6efdcc" , I then visited the link and the password for the VeraCrypt was there.

![](/imgs/2020_vulncon_ctf/analysis5.png)

This allowed me to mount the VeraCrypt volume and get the flag.

![](/imgs/2020_vulncon_ctf/analysis6.png)


### Challenge: Attack

There's an attack that happened on one of our client Mr. Innocent Karma and his system has been compromised. We have provided the file, analyze it, and provide answers to our questions for further investigation. What was the IP of the attacker and what attack happened on that machine?

#### Steps to Solve

For this challenge I was given an OVA of Mr. Innocent Karma's system. To analyze the system, I imported the OVA into virtual box and then attached the VM's virtual drives to the VM I was using for this CTF. The first file I checked for suspicious activity was the **/var/log/auth.log** file. This file records authentication events in the system. This file could contain evidence of someone possibly brute forcing SSH or logging into the system from a strange IP address. I took a quick look through the file using **less**, and sure enough there were loads of failed login events.

![](/imgs/2020_vulncon_ctf/attack1.png)

This means that someone from the IP **192.168.1.30** was brute forcing the password for the **karma** user over SSH.


### Challenge: Compromise

What account was the username and password of the compromised user?

#### Steps to Solve

After solving the last challenge, I saw that **192.168.1.30** was able to eventually successfully authenticate using the **karma** user's credentials so for this challenge I just needed to find the Karma user's password. Passwords in most Linux systems are hashed and stored the **/etc/shadow** file.  


![](/imgs/2020_vulncon_ctf/compromise1.png)

After I had gotten the hash, I just needed to crack it to solve the challenge. For for this I just used **john** and the **rockyou.txt** wordlist.

![](/imgs/2020_vulncon_ctf/compromise2.png)

This showed that the **karma** user's password is **godisgood**.


## Memory Forensic Challenges

* [Game Over](/posts/2020-vulncon-ctf/#challenge-game-over)
* [Phishy Email](/posts/2020-vulncon-ctf/#challenge-phishy-email)


### Challenge: Game Over

My friend D E V I N E R was searching for shortcut to earn money. He visited some online sites for that and registered there with his email, but unfortunately he infected his PC with some malware. He gave me the memory dump of his PC and want me to find out the installed malware and remove it. Can you find out when and which website he visited to earn money?

#### Steps to Solve

For the memory forensics challenges I used [**Volatility**](https://www.volatilityfoundation.org/) to analyze the memory dump. The first step when using volatility, without knowledge of what OS the system was running when the memory dump was taken is to run the **imageinfo** plugin. This will display what profile to use when analyzing the memory dump.

![](/imgs/2020_vulncon_ctf/gameover1.png)

After finding what profile to use, I then ran the **pstree** plugin to see the running processes on the system. This will allow me to see what browser D E V I N E R was using so I can then extract the proper files from memory to see view his search history.

![](/imgs/2020_vulncon_ctf/gameover2.png)

Since it appears D E V I N E R was using Chrome I need to see if the [**History**](https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location) file is loaded in memory so that I can extract it. I can do this with the **filescan** plugin.

![](/imgs/2020_vulncon_ctf/gameover3.png)

Sure enough Chrome's **History** file was loaded into memory and I was able to then extract it with the **dumpfiles** plugin. 

![](/imgs/2020_vulncon_ctf/gameover4.png)

Chrome's **History** file is a sqlite database, so I used [SQLite Database Browser](https://sqlitebrowser.org/) to view the database. The **urls** table contains the URLs visited by the browser.

![](/imgs/2020_vulncon_ctf/gameover5.png)

This shows that D E V I N E R last visited **https\:\/\/www.gamblingsites.org** on 12/12/2020. The time is record in the database as the number of microseconds since January, 1601.


### Challenge: Phishy Email

To make things easy for me, D E V I N E R told me that he got an email and he believes that the backdoor is installed from that email. Now it's your job to find out from where that email was sent. He is using desktop application for email.

Note: He only remembers that there was smiley sign i.e. ":)" in the email.

#### Steps to Solve

Using the same **pstree** plugin from the last challenge I saw that the desktop mail client **Mail Spring** was being used on the system.

![](/imgs/2020_vulncon_ctf/phishyemail1.png)

Next I used the file scan plugin again and saw that there was a file called **edgehill.db** in memory and it was stored under a folder called **Mailspring**. I figured this could be a db where Mail Spring stores emails locally.

![](/imgs/2020_vulncon_ctf/phishyemail2.png)

I then extracted this file using the **dumpfiles** plugin.

![](/imgs/2020_vulncon_ctf/phishyemail3.png)

Although, when I opened this file in [SQLite Database Browser](https://sqlitebrowser.org/) there appeared to be nothing in the database. Out of desperation I decided to open the file in notepad and search for the string ":)" in the file. This lead to me to discover what looked like an email with a ":)" in it.

![](/imgs/2020_vulncon_ctf/phishyemail4.png)

This shows that the email with a ":)" in it looks like it was sent from **sarojchaudhary581\@gmail\.com**.


## OSINT Challenges

* [Find The Coin](/posts/2020-vulncon-ctf/#challenge-find-the-coin)
* [trouver](/posts/2020-vulncon-ctf/#challenge-trouver)
* [Flying Bear](/posts/2020-vulncon-ctf/#challenge-flying-bear)
* [The Watcher](/posts/2020-vulncon-ctf/#challenge-the-watcher)


### Challenge: Find The Coin 

Hackers stole lot of money from Kucoin(Popular exchanger), we found a recent transaction of the value 100,000,000 DX at 26 Nov 2020 happened from the hacker's wallet can you find the tx id for me?

#### Steps to Solve

The site [Etherscan](https://etherscan.io/token/0x973e52691176d36453868D9d86572788d27041A9) allows users to browse transactions for DxChain Tokens as well as many other types of crypto currencies. I then exported the transactions that occured on November 26th 2020 to a csv file.

![](/imgs/2020_vulncon_ctf/findthecoin1.png)

Then I just needed to filter by the 100,000,000 quantity and was able to find the tx id.

![](/imgs/2020_vulncon_ctf/findthecoin2.png)


### Challenge: trouver

My friend created a forum named photobay on online. can you find that for me, so i could post the pictures i like.

#### Steps to Solve

For this one I used the dork **intitle:photobay** with GoDuckGo and found a sub reddit called photobay.

![](/imgs/2020_vulncon_ctf/trouver1.png)

I then clicked on one of the latest posts on the sub reddit and found the flag.

![](/imgs/2020_vulncon_ctf/trouver2.png)


### Challenge: Flying Bear 

maniac has given me this number A25BF4, and asked me to find the related address. I think one of his challenges has an answer to what this number could be!

#### Steps to Solve

I searched for **"A25BF4"** with Google and found a page on **https\:\/\/flightaware.com**.

![](/imgs/2020_vulncon_ctf/flyingbear1.png)

This page shows that **A25BF4** is a transponder identification number for the aircraft with the N number **N251HR**.

![](/imgs/2020_vulncon_ctf/flyingbear2.png)

This page also shows the past owners of this aircraft registered with the FAA. I started with the address of the current owner although for this challenge the address of the first owner was needed.

![](/imgs/2020_vulncon_ctf/flyingbear3.png)

The address of registered owners of an aircraft can be found on **https\:\/\/registry.faa.gov**. 


### Challenge: The Watcher 

It was a cold winter night tim3zapper got a sudden message from his boss. tim3zapper has been asked to get the mail id of a famous photographer who will be invited for the airline event oraganized by example.com. Can you help tim3zapper with that?

#### Steps to Solve

I started by using Google to search **tim3zapper** and found a twitter profile.

![](/imgs/2020_vulncon_ctf/thewatcher1.png)


This looks like the right profile as the person claims to work at **example\.com**

![](/imgs/2020_vulncon_ctf/thewatcher2.png)


Although this profile looks like it has some deleted tweets.

![](/imgs/2020_vulncon_ctf/thewatcher3.png)


To view the deleted tweets, I viewed the profile on **https\:\/\/archive\.org**.

![](/imgs/2020_vulncon_ctf/thewatcher4.png)

This gave me another username **sullyth3h4x0r**, which I then searched for with Google.

![](/imgs/2020_vulncon_ctf/thewatcher5.png)

From the search I determined that someone with that username had a profile on **https\:\/\/ello\.co**

![](/imgs/2020_vulncon_ctf/thewatcher6.png)

On that person's profile, I found a post that told me to find the owner of the photograph to get the photographer's email.

![](/imgs/2020_vulncon_ctf/thewatcher7.png)

Bing's reverse image search, showed that that photo was on a page on **https\:\/\/www\.jetphotos\.com**

![](/imgs/2020_vulncon_ctf/thewatcher8.png)

This page got me the name of the photographer but I still needed an email. I then searched for Google again to try and find a page with the photographer's email.

![](/imgs/2020_vulncon_ctf/thewatcher9.png)

This led me to a page on **https\:\/\/www\.dutchops\.com**

![](/imgs/2020_vulncon_ctf/thewatcher10.png)

On that page I found a **mailto:** link with the photographer's email and was able to use it to complete the challenge.
