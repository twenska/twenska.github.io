---
title: "Book review: Practical Malware Analysis"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse Engineering
  - Practical Malware Analysis
  - Books
  - Review
---
# TL;DR
The book [Practical Malware Analysis](https://nostarch.com/malware) by Michael Sikorski and Andrew Honig teaches the basics of reverse engineering with a special focus on malicious software. It is a very goodtraining ressource and provides labs for each capter, that can be used to practice the theories explained in the book. The book gets a beginner started in the field of reverse engineering.

# Structure of the book
The book is structured in five main parts:

### Basic Analysis

The first part is about the basic steps to take when analysing a binary file. It shows the structure of PE files (the book focuses on Windows) and what artifacts and metadata can be relevant to analysis. It also helps setting up your lab environment, but I would recommend to use the [flare-vm](https://github.com/fireeye/flare-vm). It includes most tools used in this book and even the labs themselve! Next to the basic static analysis of PE files, this part also handles basic dynamic analysis. It shows tools that monitor the behaviour of the malware when executing it. This includes the tools from Sysinternals, Wireshark and FakeNet-NG.

### Advanced Static Analysis

In the beginning of this book part, there is a crash course in x86 assembly. It is quite useful, but somebody who never saw assembly before should maybe look for a more in depth ressource. If a person is very fluent in assembly, this introduction won't provide him with any new knowledge either. However, it will do as a refresher for people with basic assembly knowledge!

Next up, the popular disassembler IDA Pro is introduced with some of its feature set.

After getting the basics in Assembly and Disassembly right, two chapters take a first dive into reverse engineering binary code. The first one shows how common C code structures look like in assembly, while the other gives an overview of how Windows programs work (API, Registry, Networking).

### Advanced Dynamic Analysis

The dynamic analysis part is all about debugging (user and kernel-mode). It is a good introduction to debugging for reverse engineering purposes, mainly using OllyDbg and WinDbg. In a more recent version of such a book I would like to read about more dynamic techniques, like Hooking and Instrumentation.

### Malware Functionality

In this book part the authors focus on malware specific behaviour; especially how to recognize and reverse engineer it. Next to expected malware behaviour (e.g. extracting data or establishing C2 channels), various evasion and hiding techniques are elaborated. The book part ends with an introduction to writing network signatures to detect malware (which is often the target of reverse engineering it in the first place). Most of the techniques described are still relevant today (hi ProcessInjection), but some of them won't be common anymore. It still holds value to learn about all these techniques, because general malware patterns stay the same and attackers are often going back to *dated* techniques.

 In a newer book version I would like a dedicated chapter with focus on using reverse engineering for detection purposes (e.g. writing file signatures with Yara or how malware behaviour can be noticed in Event Logs).

### Anti-Reverse-Engineering

In this book part the reader is introduced to some common techniques employed by creators of software (malicious and not) that try to hinder reverse engineering efforts. This includes Anti-Disassembly, Anti-Debugging, Anti-VM and packing techniques. The different techniques are described and you tricks to circumvent the employed techniques are shown, so one can go on with reverese engineering code.

# Conclusion
In the first three and in the fifth part of the book you get the general basic knwoledge needed to reverse engineer software (not just malware). This knowledge is applicable not only in security, but in any IT job. I often feel, that by looking at the inner workings of software, one can understand a lot about how computers work and what challenges/problems can arise. 

The fourth part could be skipped if a reade doesn't have any interest in malware, but I can highly recommend it. It was the most interesting and fun part to me! Learning about the inner workings of malicious code will change the way you look at attacks and especially how to defend against them. Therefore, a basic knowledge of reverse engineering can be useful for both - Blue and Read Teamers.

If you are just getting started in Reverse Engineering and want to have a very good guide by your side, this book is definetely the right one for you. The age of the book isn't a problem, as the contents are still useful and up to date. **What makes this book stand out from other ressources is the well done combination of theory and practice, achieved by providing a lot of high quality labs.** There are over 50 of these in this book! All help you understand the theories from the relevant chapter, give you hands-on epxerience on doing reverse engineering and come with a detailed write-up. In my opinion this is the way to go if you want to learn reverse engineering!

If you are interested in seeing a sample lab from this book or just want a first look how reverse engineering malware can look like, you should take a look at [my walkthrough of one of the more advanced labs from the book](https://blog.twenska.de/blog/pma_book_walkthrough/).
